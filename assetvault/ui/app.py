"""AssetVault dashboard server (stdlib only). Decrypted data lives only in process memory."""
import os, sys, json, hmac, re, secrets, signal, threading, time, base64, datetime, sqlite3
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "bin"))
import avcore as av, avlogic as lg
import ops
from connectors.base import ConnectorError
from errors import MergeError, OpsError

IDLE_SECONDS = int(os.environ.get("ASSETVAULT_IDLE_SECONDS", "1800"))
MAX_BODY = 25 * 1024 * 1024
URL_FILE = os.path.join(av.ROOT, ".dashboard_url")
PID_FILE = os.path.join(av.ROOT, ".dashboard.pid")
EDITABLE = {"name": "text", "category": "cat", "room": "room", "brand": "text", "model": "text", "serial": "text",
            "owner": "text", "mac": "text", "os": "text", "asset_tag": "text", "os_version": "text", "managed_by": "text",
            "purchase_date": "date", "purchase_price": "num", "current_value": "num", "replacement_value": "num",
            "condition": "text", "warranty_expiry": "date", "warranty_provider": "text", "backup_method": "text",
            "rpo_target_hours": "int", "rpo_notes": "text", "encryption_status": "text", "last_checkin": "date", "notes": "text"}

class Bad(Exception): pass

STATE = {"key": None, "token": None, "last": time.time(), "stopped": False}
WLOCK = threading.Lock()

def now(): return datetime.datetime.now(av.TZ)
def db(): return av.open_db(STATE["key"])
def cfg(con):
    return {r["k"]: json.loads(r["v"]) for r in con.execute("SELECT k,v FROM config")}

def mask(s):
    return lg.mask_serial(s)

def history_map(con):
    m = {}
    for r in con.execute("SELECT * FROM backup_history ORDER BY date"):
        m.setdefault(r["item_id"], []).append(dict(r))
    return m

def item_view(r, hist, threshold, srcnames, badges, t):
    d = dict(r)
    ls, la = lg.last_success(hist), lg.last_attempt(hist)
    marks = badges.get(d["id"], [])
    out = {k: d.get(k) for k in ("id", "name", "room", "category", "owner", "source", "backup_method", "replacement_value",
                                 "warranty_expiry", "last_checkin", "encryption_status", "rpo_target_hours", "verified", "paused")}
    out.update(serial_masked=mask(d.get("serial")), has_serial=bool((d.get("serial") or "").strip()),
               rpo=lg.rpo_state(d, hist, t), strip=lg.day_strip(hist, 30, t, d),
               last_success=ls.isoformat() if ls else None, last_attempt=la.isoformat() if la else None,
               warranty=lg.warranty_status(d, t), flags=lg.completeness(d, threshold),
               unencrypted=lg.is_unencrypted(d), sources=srcnames.get(d["id"], []), badges=marks)
    return out

def state_payload():
    con = db(); t = now(); c = cfg(con); hm = history_map(con)
    srcn, badges = {}, {}
    for r in con.execute("SELECT i.item_id, s.name, s.kind, i.not_seen_at FROM item_sources i JOIN sources s ON s.id=i.source_id ORDER BY s.name"):
        srcn.setdefault(r["item_id"], []).append(r["name"])
        badges.setdefault(r["item_id"], []).append({"name": r["name"], "kind": r["kind"], "not_seen_at": r["not_seen_at"]})
    items = [item_view(r, hm.get(r["id"], []), c.get("receipt_photo_threshold"), srcn, badges, t)
             for r in con.execute("SELECT * FROM items ORDER BY name COLLATE NOCASE")]
    sources = [dict(r) for r in con.execute(
        "SELECT id, name, kind, connector, last_sync, added, updated, skipped, not_seen, health, detail FROM sources ORDER BY name")]
    reviews = [merge_view(con, r) for r in con.execute("SELECT * FROM reviews WHERE status='staged' ORDER BY id")]
    con.close()
    return {"now": t.isoformat(timespec="seconds"), "config": {k: c.get(k) for k in ("rooms", "categories", "receipt_photo_threshold", "schema_version")},
            "source_kinds": list(av.SOURCES_ENUM), "items": items, "sources": sources, "reviews": reviews}

def merge_view(con, row):
    import merge
    return merge.review_view(con, row)

def item_detail(iid, reveal=False):
    con = db(); r = con.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
    if not r: con.close(); raise Bad("no such item")
    d = dict(r); t = now(); c = cfg(con)
    hist = [dict(h) for h in con.execute("SELECT * FROM backup_history WHERE item_id=? ORDER BY date DESC, id DESC", (iid,))]
    srcs = [dict(s) for s in con.execute(
        """SELECT s.id, s.name, s.kind, s.health, s.last_sync, s.detail, i.seen_at, i.external_id, i.not_seen_at
           FROM item_sources i JOIN sources s ON s.id=i.source_id WHERE i.item_id=?""", (iid,))]
    con.close()
    ls, la = lg.last_success(hist), lg.last_attempt(hist)
    tgt = lg.rpo_target_hours(d)
    actual = round((t - ls).total_seconds() / 3600, 1) if ls else None
    flags = lg.completeness(d, c.get("receipt_photo_threshold"))
    d["serial_masked"] = mask(d.get("serial"))
    if not reveal: d["serial"] = None
    d["photo_refs"] = lg.refs(d.get("photo_refs")); d["receipt_refs"] = lg.refs(d.get("receipt_refs"))
    try: d["external_ids"] = json.loads(d.get("external_ids") or "{}")
    except ValueError: pass
    trail = [a for a in av.read_audit(STATE["key"]) if a.get("item_id") == iid]
    return {"item": d, "history": hist[:200], "sources": srcs, "audit": trail[-200:][::-1],
            "rpo": {"state": lg.rpo_state(d, hist, t), "target_hours": tgt, "actual_hours": actual,
                    "variance_hours": round(actual - tgt, 1) if (actual is not None and tgt) else None,
                    "last_success": ls.isoformat() if ls else None, "last_attempt": la.isoformat() if la else None},
            "warranty": lg.warranty_status(d, t), "flags": flags}

def clean(field, val, c):
    kind = EDITABLE[field]
    if val is None or (isinstance(val, str) and val.strip() == ""): return None
    if kind in ("text",): return str(val).strip()[:2000]
    if kind == "cat":
        if val not in (c.get("categories") or []): raise Bad("unknown category")
        return val
    if kind == "room":
        if val not in (c.get("rooms") or []): raise Bad("unknown room")
        return val
    if kind == "date":
        if not lg.parse_dt(val): raise Bad(f"{field}: invalid date")
        return str(val).strip()
    try:
        if kind == "num":
            v = float(val)
            if v < 0: raise ValueError
            return v
        if kind == "int":
            v = int(val)
            if v <= 0: raise ValueError
            return v
    except (TypeError, ValueError): raise Bad(f"{field}: invalid number")

def write(fn):
    """open fresh copy -> mutate -> save_db -> audit. Serialized by WLOCK and the vault file lock."""
    with WLOCK:
        with av.vault_lock():
            con = db()
            try:
                res, action, iid, detail = fn(con)
                av.save_db(STATE["key"], con)
            finally: con.close()
        av.audit(STATE["key"], action, iid, detail)
        return res

def get_item(con, iid):
    r = con.execute("SELECT * FROM items WHERE id=?", (iid,)).fetchone()
    if not r: raise Bad("no such item")
    return r

def act_add(body):
    def fn(con):
        c = cfg(con); vals = {}
        for f in EDITABLE:
            if f in body: vals[f] = clean(f, body[f], c)
        if not vals.get("name"): raise Bad("name required")
        ts = av.now(); vals.update(source="Manual", created_at=ts, updated_at=ts)
        cur = con.execute(f"INSERT INTO items({','.join(vals)}) VALUES({','.join('?' * len(vals))})", list(vals.values()))
        return {"id": cur.lastrowid}, "item_add", cur.lastrowid, {"fields": sorted(k for k, v in vals.items() if v is not None)}
    return write(fn)

def act_edit(iid, body):
    def fn(con):
        get_item(con, iid); c = cfg(con); vals = {}
        for f in EDITABLE:
            if f not in body: continue
            if f == "serial" and (body[f] or "") == "": continue      # blank serial = unchanged (it is masked in the UI)
            vals[f] = clean(f, body[f], c)
        if "name" in vals and not vals["name"]: raise Bad("name required")
        if not vals: raise Bad("nothing to change")
        vals["updated_at"] = av.now()
        con.execute(f"UPDATE items SET {','.join(k + '=?' for k in vals)} WHERE id=?", [*vals.values(), iid])
        return {"ok": True}, "item_edit", iid, {"fields": sorted(k for k in vals if k != "updated_at")}
    return write(fn)

def act_log(iid, body):
    res = body.get("result")
    if res not in ("success", "partial", "failed", "manual"): raise Bad("invalid result")
    # Store one canonical vault-TZ instant. Naive values are vault-local; offsets are converted.
    parsed = lg.parse_dt(body.get("date") or now().isoformat(timespec="seconds"))
    if not parsed: raise Bad("invalid date")
    date = parsed.isoformat(timespec="seconds")
    def fn(con):
        get_item(con, iid)
        con.execute("INSERT INTO backup_history(item_id,date,result,note,created_at) VALUES(?,?,?,?,?)",
                    (iid, date, res, (body.get("note") or "")[:2000] or None, av.now()))
        con.execute("UPDATE items SET updated_at=? WHERE id=?", (av.now(), iid))
        return {"ok": True}, "backup_logged", iid, {"result": res}
    return write(fn)

def act_flag(iid, col, action):
    def fn(con):
        r = get_item(con, iid); v = 0 if r[col] else 1
        con.execute(f"UPDATE items SET {col}=?, updated_at=? WHERE id=?", (v, av.now(), iid))
        return {col: v}, action + ("" if v else "_undo"), iid, {col: v}
    return write(fn)

def act_attach(iid, body):
    kind = body.get("kind")
    if kind not in ("photo", "receipt"): raise Bad("kind must be photo or receipt")
    try: data = base64.b64decode(body.get("data") or "", validate=True)
    except Exception: raise Bad("bad file data")
    if not data: raise Bad("empty file")
    mime = str(body.get("mime") or "application/octet-stream")[:100]
    name = str(body.get("name") or "")[:200]
    with WLOCK:
        with av.vault_lock():
            con = db()
            try:
                get_item(con, iid)
                bid = av.put_blob(STATE["key"], data); del data
                col = kind + "_refs"
                refs = lg.refs(con.execute(f"SELECT {col} FROM items WHERE id=?", (iid,)).fetchone()[0])
                refs.append({"id": bid, "name": name, "mime": mime, "added": av.now()})
                con.execute(f"UPDATE items SET {col}=?, updated_at=? WHERE id=?", (json.dumps(refs), av.now(), iid))
                av.save_db(STATE["key"], con)
            finally: con.close()
        av.audit(STATE["key"], "attach_" + kind, iid, {"blob": bid})
    return {"id": bid}

def _unlink_blob(bid):
    """Remove one encrypted blob file. Ids are server-generated 32-hex; ignore anything else."""
    if not isinstance(bid, str) or not re.fullmatch(r"[0-9a-f]{32}", bid): return
    path = os.path.join(av.BLOBS, bid + ".enc")
    if os.path.dirname(os.path.abspath(path)) != os.path.abspath(av.BLOBS): return
    try: os.remove(path)
    except OSError: pass

def _locked(fn):
    with WLOCK:
        return fn()

def act_sync(sid):
    return _locked(lambda: ops.sync_source(sid, key=STATE["key"]))

def act_verify(rid, body):
    try: index = int(body.get("index"))
    except (TypeError, ValueError): raise Bad("index required")
    verified = body.get("verified") if "verified" in body else None
    return _locked(lambda: ops.verify_soft(rid, index, verified, key=STATE["key"]))

def act_commit(rid):
    return _locked(lambda: ops.commit_staged(rid, key=STATE["key"]))

def act_discard(rid):
    return _locked(lambda: ops.discard_staged(rid, key=STATE["key"]))

def act_export(body):
    return _locked(lambda: ops.export_inventory((body or {}).get("kind"), key=STATE["key"]))

def act_delete(iid, body):
    blob_ids = []
    def fn(con):
        r = get_item(con, iid)
        if (body.get("confirm_name") or "") != r["name"]: raise Bad("confirmation does not match item name")
        for ref in lg.refs(r["photo_refs"]) + lg.refs(r["receipt_refs"]):
            blob_ids.append(ref.get("id") if isinstance(ref, dict) else None)
        con.execute("DELETE FROM backup_history WHERE item_id=?", (iid,))
        con.execute("DELETE FROM item_sources WHERE item_id=?", (iid,))
        con.execute("DELETE FROM items WHERE id=?", (iid,))
        return {"ok": True}, "item_delete", iid, None
    res = write(fn)   # db reference is gone before the files are; a crash can only orphan, not dangle
    for bid in blob_ids: _unlink_blob(bid)
    return res

def blob_allowed(bid):
    if not re.fullmatch(r"[0-9a-f]{32}", bid): return None
    con = db()
    try:
        for r in con.execute("SELECT photo_refs, receipt_refs FROM items"):
            for ref in lg.refs(r[0]) + lg.refs(r[1]):
                if ref["id"] == bid: return ref
    finally: con.close()
    return None

def sniff(b, fallback):
    if b[:3] == b"\xff\xd8\xff": return "image/jpeg"
    if b[:8] == b"\x89PNG\r\n\x1a\n": return "image/png"
    if b[:4] == b"GIF8": return "image/gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP": return "image/webp"
    if b[:5] == b"%PDF-": return "application/pdf"
    return "application/octet-stream"   # never echo client mime (no stored XSS via text/html)

INDEX = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
SEC_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
               "X-Frame-Options": "DENY",
               "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; form-action 'none'; base-uri 'none'"}

class H(BaseHTTPRequestHandler):
    server_version = "AssetVault"; sys_version = ""
    def log_message(self, *a): pass   # never log request paths (they carry the token)

    def send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)): body = json.dumps(body).encode()
        elif isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        for k, v in {**SEC_HEADERS, **(extra or {})}.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def auth(self):
        """Returns sub-path after the token, or None (403 already sent)."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if host not in ("127.0.0.1", "localhost"):
            self.send(403, {"error": "forbidden"}); return None
        u = urlsplit(self.path); tok = STATE["token"]; sub = None
        parts = u.path.split("/", 2)
        if len(parts) >= 2 and hmac.compare_digest(parts[1].encode(), tok.encode()):
            sub = "/" + (parts[2] if len(parts) > 2 else "")
        else:
            q = parse_qs(u.query).get("token", [""])[0]
            if q and hmac.compare_digest(q.encode(), tok.encode()):
                sub = u.path
        if sub is None:
            self.send(403, {"error": "forbidden"}); return None
        if self.command == "POST":
            origin = self.headers.get("Origin")
            if origin and urlsplit(origin).hostname not in ("127.0.0.1", "localhost"):
                self.send(403, {"error": "bad origin"}); return None
        if not self.headers.get("X-AV-Poll"): STATE["last"] = time.time()   # background polling doesn't count as activity
        return sub

    def do_GET(self):
        sub = self.auth()
        if sub is None: return
        try:
            if sub in ("/", ""):
                return self.send(200, INDEX.replace("__BASE__", "/" + STATE["token"] + "/"), "text/html; charset=utf-8")
            if sub == "/api/state": return self.send(200, state_payload())
            if sub == "/api/health": return self.send(200, {"ok": True})
            m = re.fullmatch(r"/api/item/(\d+)", sub)
            if m: return self.send(200, item_detail(int(m.group(1))))
            m = re.fullmatch(r"/api/item/(\d+)/serial", sub)
            if m:
                d = item_detail(int(m.group(1)), reveal=True)
                av.audit(STATE["key"], "serial_reveal", int(m.group(1)), None)
                return self.send(200, {"serial": d["item"]["serial"]})
            m = re.fullmatch(r"/api/blob/([0-9a-f]{32})", sub)
            if m:
                ref = blob_allowed(m.group(1))
                if not ref: return self.send(404, {"error": "not found"})
                data = av.get_blob(STATE["key"], m.group(1))
                return self.send(200, data, sniff(data, ref.get("mime")), {"Content-Disposition": "inline"})
            self.send(404, {"error": "not found"})
        except Bad as e: self.send(400, {"error": str(e)})
        except Exception as e: self.send(500, {"error": type(e).__name__})

    def do_POST(self):
        sub = self.auth()
        if sub is None: return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY: return self.send(413, {"error": "too large"})
            if "application/json" not in (self.headers.get("Content-Type") or ""): return self.send(415, {"error": "json only"})
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict): raise Bad("bad body")
            if sub == "/api/item": return self.send(200, act_add(body))
            if sub == "/api/export": return self.send(200, act_export(body))
            m = re.fullmatch(r"/api/source/(\d+)/sync", sub)
            if m:
                res = act_sync(int(m.group(1)))
                return self.send(200 if res.get("ok") else 400, res)
            m = re.fullmatch(r"/api/review/(\d+)/verify", sub)
            if m: return self.send(200, act_verify(int(m.group(1)), body))
            m = re.fullmatch(r"/api/review/(\d+)/commit", sub)
            if m: return self.send(200, act_commit(int(m.group(1))))
            m = re.fullmatch(r"/api/review/(\d+)/discard", sub)
            if m: return self.send(200, act_discard(int(m.group(1))))
            m = re.fullmatch(r"/api/item/(\d+)/(edit|log_backup|verify|pause|attach|delete)", sub)
            if not m: return self.send(404, {"error": "not found"})
            iid, a = int(m.group(1)), m.group(2)
            r = {"edit": lambda: act_edit(iid, body), "log_backup": lambda: act_log(iid, body),
                 "verify": lambda: act_flag(iid, "verified", "mark_verified"), "pause": lambda: act_flag(iid, "paused", "pause"),
                 "attach": lambda: act_attach(iid, body), "delete": lambda: act_delete(iid, body)}[a]()
            self.send(200, r)
        except (Bad, OpsError, MergeError, ConnectorError) as e: self.send(400, {"error": av.scrub(str(e))})
        except (ValueError, sqlite3.IntegrityError): self.send(400, {"error": "invalid input"})
        except Exception as e: self.send(500, {"error": type(e).__name__})

def _wfile(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f: f.write(text)
    os.chmod(path, 0o600)

def stop(server, reason):
    if STATE["stopped"]: return
    STATE["stopped"] = True
    try: av.audit(STATE["key"], "dashboard_stop", None, {"reason": reason})
    except Exception: pass
    for p in (URL_FILE, PID_FILE):
        try:
            if p == PID_FILE and open(p).read().strip() != str(os.getpid()): continue
            os.remove(p)
        except OSError: pass
    threading.Thread(target=server.shutdown, daemon=True).start()

def main():
    if os.path.exists(PID_FILE):
        try:
            pid = int(open(PID_FILE).read().strip()); os.kill(pid, 0)
            if "dashboard" in open(f"/proc/{pid}/cmdline").read():
                print(f"dashboard already running (pid {pid}); run bin/lock.sh first", file=sys.stderr); sys.exit(3)
        except (OSError, ValueError): pass
    try: key = av.unlock()
    except av.UnlockError as e:
        print(f"unlock failed: {e}", file=sys.stderr); sys.exit(2)
    STATE["key"] = key
    con = av.open_db(key); ver = av.schema_version(con); con.close()
    if ver < av.SCHEMA_VERSION: av.migrate(key)
    STATE["token"] = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("ASSETVAULT_PORT", "0"))), H)
    server.daemon_threads = True
    port = server.server_address[1]
    _wfile(URL_FILE, f"http://127.0.0.1:{port}/{STATE['token']}/\n")
    _wfile(PID_FILE, f"{os.getpid()}\n")
    av.audit(key, "dashboard_start", None, {"port": port})
    signal.signal(signal.SIGTERM, lambda *a: stop(server, "signal"))
    signal.signal(signal.SIGINT, lambda *a: stop(server, "signal"))
    def idle():
        while not STATE["stopped"]:
            time.sleep(min(30, max(1, IDLE_SECONDS / 4)))
            if time.time() - STATE["last"] > IDLE_SECONDS: stop(server, "idle"); return
    threading.Thread(target=idle, daemon=True).start()
    print(f"AssetVault dashboard listening on 127.0.0.1:{port} (url in {URL_FILE})", flush=True)
    server.serve_forever()
    server.server_close()

if __name__ == "__main__": main()
