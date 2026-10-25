"""End-to-end test against a THROWAWAY temp vault with clearly fake data. Never touches the real vault."""
import os, sys, json, secrets, tempfile, shutil, subprocess, time, base64, datetime, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
_BIN = os.path.dirname(os.path.abspath(__file__))
_INSTALL = os.path.dirname(_BIN)
REAL = os.environ.get("ASSETVAULT_ROOT", _INSTALL)   # install root whose bin/ and .venv/ are tested
TMP = tempfile.mkdtemp(prefix="avtest-"); os.chmod(TMP, 0o700)
os.environ["ASSETVAULT_ROOT"] = TMP
os.environ["ASSETVAULT_PASSPHRASE"] = "throwaway-" + secrets.token_hex(16)   # overrides only inside this process
for _secret_name in ("ASSETVAULT_GRAPH_SECRET", "ASSETVAULT_AD_PASSWORD", "ASSETVAULT_JAMF_SECRET", "ASSETVAULT_REST_TOKEN", "ASSETVAULT_REST_PASSWORD"):
    os.environ.pop(_secret_name, None)
BIN = os.path.join(REAL, "bin"); sys.path.insert(0, BIN)
import avcore as av, avlogic as lg
import merge, ops
assert av.ROOT == TMP and av.ROOT != REAL
PY = os.path.join(REAL, ".venv/bin/python")
R = {}; fails = []
def check(name, cond):
    R[name] = bool(cond)
    if not cond: fails.append(name)

try:
    # ---------- logic unit tests
    TZ = av.TZ; now = datetime.datetime(2026, 10, 24, 12, 0, tzinfo=TZ)
    it = {"rpo_target_hours": 24, "paused": 0}
    h = lambda hrs, r="success": {"date": (now - datetime.timedelta(hours=hrs)).isoformat(), "result": r}
    check("rpo_met", lg.rpo_state(it, [h(5)], now) == "Met")
    check("rpo_at_risk", lg.rpo_state(it, [h(13)], now) == "At risk")
    check("rpo_breached", lg.rpo_state(it, [h(30)], now) == "Breached")
    check("rpo_breached_only_failures", lg.rpo_state(it, [h(2, "failed")], now) == "Breached")
    check("rpo_no_data", lg.rpo_state(it, [], now) == "No data")
    check("rpo_paused_not_scheduled", lg.rpo_state({"rpo_target_hours": 24, "paused": 1}, [h(1)], now) == "Not scheduled")
    check("rpo_no_target_not_scheduled", lg.rpo_state({"rpo_target_hours": None}, [], now) == "Not scheduled")
    check("rpo_manual_counts", lg.rpo_state(it, [h(2, "manual")], now) == "Met")
    s = lg.day_strip([h(0), h(24, "partial"), h(24, "failed"), h(48, "failed")], 30, now, it)
    check("strip_len_30", len(s) == 30)
    check("strip_states", [x["state"] for x in s[-3:]] == ["failed", "partial", "success"] and s[0]["state"] == "no_result")
    check("strip_not_scheduled", all(x["state"] == "not_scheduled" for x in lg.day_strip([], 30, now, {"paused": 1, "rpo_target_hours": 24})))
    f = lg.completeness({"category": "Computers", "serial": "", "replacement_value": 900, "photo_refs": "[]", "receipt_refs": "[]", "room": None}, 500)
    check("completeness_flags", set(f) == {"missing serial", "missing receipt", "missing photo", "missing room"})
    check("completeness_missing_value", "missing value" in lg.completeness({"category": "Furniture", "room": "Office"}, 500))
    check("completeness_ok", lg.completeness({"category": "Furniture", "room": "Office", "replacement_value": 100}, 500) == [])
    check("warranty", [lg.warranty_status({"warranty_expiry": d}, now) for d in ("2026-01-01", "2026-12-01", "2027-12-01", None)] == ["expired", "expiring", "ok", "unknown"])
    # A +09:00 instant must be converted to vault TZ. The same wall time without an offset is
    # read as New York and lands on the next calendar day, so it falls off today's strip.
    foreign = datetime.datetime(2026, 10, 25, 10, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=9)))
    now_ny = foreign.astimezone(TZ)
    aware = foreign.isoformat(); naive = "2026-10-25T10:00"
    check("tz_aware_met", lg.rpo_state(it, [{"date": aware, "result": "success"}], now_ny) == "Met")
    check("tz_aware_on_strip", lg.day_strip([{"date": aware, "result": "success"}], 30, now_ny, it)[-1]["state"] == "success")
    check("tz_naive_dropped", lg.day_strip([{"date": naive, "result": "success"}], 30, now_ny, it)[-1]["state"] == "no_result")

    # ---------- vault init + migration idempotency
    av.init(["Office", "Garage"], ["Computers", "Networking", "Furniture"], 500)
    k = av.unlock()
    c1 = av.migrate(k); c2 = av.migrate(k)
    check("migrate_first_changes", len(c1) >= 13); check("migrate_rerun_noop", c2 == [])
    con = av.open_db(k)
    cols = {r[1] for r in con.execute("PRAGMA table_info(items)")}
    check("migrate_columns", {"owner", "mac", "os", "source", "external_ids", "last_checkin", "encryption_status", "rpo_target_hours", "verified", "paused", "backup_status", "rpo_target_days", "asset_tag", "os_version", "managed_by"} <= cols)
    check("migrate_tables", {"backup_history", "sources", "item_sources", "reviews"} <= {r[0] for r in con.execute("select name from sqlite_master")})
    check("schema_version", av.schema_version(con) == 3); con.close()
    check("migrate_audited_once", sum(a["action"] == "migrate" for a in av.read_audit(k)) == 1)

    # ---------- wrong passphrase fails cleanly
    env_bad = dict(os.environ, ASSETVAULT_PASSPHRASE="wrong-" + secrets.token_hex(8))
    p = subprocess.run([PY, os.path.join(BIN, "dashboard.py")], env=env_bad, capture_output=True, text=True, timeout=60)
    check("wrong_pass_exit2", p.returncode == 2 and "unlock failed" in p.stderr and not os.path.exists(os.path.join(TMP, ".dashboard_url")))
    try: os.remove(os.path.join(TMP, "audit.failed_unlocks"))
    except OSError: pass

    # ---------- start server
    env = dict(os.environ, ASSETVAULT_IDLE_SECONDS="1800")
    for _secret_name in ("ASSETVAULT_GRAPH_SECRET", "ASSETVAULT_AD_PASSWORD", "ASSETVAULT_JAMF_SECRET", "ASSETVAULT_REST_TOKEN", "ASSETVAULT_REST_PASSWORD"):
        env.pop(_secret_name, None)
    srv = subprocess.Popen([PY, os.path.join(BIN, "dashboard.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    uf = os.path.join(TMP, ".dashboard_url")
    for _ in range(100):
        if os.path.exists(uf) and os.path.exists(os.path.join(TMP, ".dashboard.pid")): break
        time.sleep(0.1)
    url = open(uf).read().strip()
    check("url_file_0600", oct(os.stat(uf).st_mode & 0o777) == "0o600")
    check("pid_file", open(os.path.join(TMP, ".dashboard.pid")).read().strip() == str(srv.pid))
    base = url.rstrip("/"); root = base.rsplit("/", 1)[0]; tok = base.rsplit("/", 1)[1]
    def req(path, body=None, full=None, headers=None):
        u = full or (base + path)
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(u, data=data, headers={"Content-Type": "application/json", **(headers or {})} if data is not None else (headers or {}))
        try:
            with urllib.request.urlopen(r, timeout=20) as resp: return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e: return e.code, e.read(), e.headers
    # auth
    check("403_no_token_root", req(None, full=root + "/")[0] == 403)
    check("403_no_token_api", req(None, full=root + "/api/state")[0] == 403)
    check("403_bad_token", req(None, full=root + "/" + "x" * len(tok) + "/api/state")[0] == 403)
    check("403_post_no_token", req(None, body={"name": "x"}, full=root + "/api/item")[0] == 403)
    check("403_bad_host", req("/api/state", headers={"Host": "evil.example:1"})[0] == 403)
    check("403_bad_origin", req("/api/item", body={"name": "FAKE"}, headers={"Origin": "http://evil.example"})[0] == 403)
    check("query_token_ok", req(None, full=root + "/api/health?token=" + tok)[0] == 200)
    st, body, hd = req("/")
    check("index_200", st == 200 and b"ASSET" in body and b"__BASE__" not in body and b"http://" not in body.replace(b"http://\"", b""))
    check("log_form_sends_offset", b"getTimezoneOffset" in body and b"isoOffset" in body)
    check("no_external_refs", b"https://" not in body and b"cdn" not in body.lower() and b"googleapis" not in body)
    check("csp_header", "default-src 'none'" in hd.get("Content-Security-Policy", ""))
    st, body, _ = req("/api/state"); S = json.loads(body)
    check("empty_state", st == 200 and S["items"] == [] and S["sources"] == [] and S.get("reviews") == [])
    # write path
    st, b, _ = req("/api/item", {"name": "FAKE-TEST Laptop Alpha", "category": "Computers", "room": "Office", "serial": "FAKESERIAL1234", "replacement_value": "1200", "rpo_target_hours": "24", "owner": "Test Owner", "warranty_expiry": (now.date() + datetime.timedelta(days=20)).isoformat(), "encryption_status": "unencrypted"})
    check("add_item", st == 200); a = json.loads(b)["id"]
    st, b, _ = req("/api/item", {"name": "FAKE-TEST Router Beta", "category": "Networking", "room": "Garage", "rpo_target_hours": "48"}); bid_item = json.loads(b)["id"]
    req("/api/item", {"name": "FAKE-TEST Desk Gamma", "category": "Furniture", "room": "Office", "replacement_value": "100"})
    check("add_requires_name", req("/api/item", {"category": "Computers"})[0] == 400)
    check("add_bad_room", req("/api/item", {"name": "FAKE x", "room": "Mars"})[0] == 400)
    check("add_bad_number", req("/api/item", {"name": "FAKE x", "replacement_value": "abc"})[0] == 400)
    check("edit", req(f"/api/item/{a}/edit", {"model": "FAKE-MODEL", "serial": ""})[0] == 200)
    check("log_backup", req(f"/api/item/{a}/log_backup", {"result": "success", "note": "fake"})[0] == 200)
    req(f"/api/item/{a}/log_backup", {"result": "partial", "date": (now - datetime.timedelta(days=3)).date().isoformat()})
    req(f"/api/item/{bid_item}/log_backup", {"result": "failed"})
    check("log_bad_result", req(f"/api/item/{a}/log_backup", {"result": "great"})[0] == 400)
    check("verify", json.loads(req(f"/api/item/{a}/verify", {})[1]) == {"verified": 1})
    check("pause_unpause", json.loads(req(f"/api/item/{bid_item}/pause", {})[1]) == {"paused": 1} and json.loads(req(f"/api/item/{bid_item}/pause", {})[1]) == {"paused": 0})
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    st, b, _ = req(f"/api/item/{a}/attach", {"kind": "photo", "name": "fake.png", "mime": "image/png", "data": base64.b64encode(png).decode()})
    check("attach_photo", st == 200); blob = json.loads(b)["id"]
    st, b, _ = req(f"/api/item/{a}/attach", {"kind": "receipt", "name": "fake.html", "mime": "text/html", "data": base64.b64encode(b"<script>alert(1)</script>").decode()})
    check("attach_receipt", st == 200); rblob = json.loads(b)["id"]
    blobfile = open(os.path.join(TMP, "blobs", blob + ".enc"), "rb").read()
    check("blob_encrypted_on_disk", png not in blobfile and blobfile[:5] == b"AVLT1")
    st, b, hd = req(f"/api/blob/{blob}")
    check("blob_stream", st == 200 and b == png and hd["Content-Type"] == "image/png" and hd["Cache-Control"] == "no-store")
    st, b, hd = req(f"/api/blob/{rblob}")
    check("blob_no_html_mime", hd["Content-Type"] == "application/octet-stream")
    check("blob_unreferenced_404", req("/api/blob/" + "0" * 32)[0] == 404)
    st, b, _ = req(f"/api/item/{a}"); D = json.loads(b)
    check("detail", st == 200 and D["item"]["serial"] is None and D["item"]["serial_masked"].endswith("1234") and D["rpo"]["state"] in ("Met", "At risk")
          and D["rpo"]["target_hours"] == 24 and len(D["item"]["photo_refs"]) == 1 and len(D["history"]) == 2 and D["warranty"] == "expiring" and "missing serial" not in D["flags"])
    check("detail_audit_trail", {"item_add", "item_edit", "backup_logged", "mark_verified", "attach_photo", "attach_receipt"} <= {x["action"] for x in D["audit"]})
    check("serial_reveal", json.loads(req(f"/api/item/{a}/serial")[1])["serial"] == "FAKESERIAL1234")
    check("detail_404", req("/api/item/99999")[0] == 400)
    S = json.loads(req("/api/state")[1]); byname = {i["name"]: i for i in S["items"]}
    A, B, G = byname["FAKE-TEST Laptop Alpha"], byname["FAKE-TEST Router Beta"], byname["FAKE-TEST Desk Gamma"]
    check("state_computed", A["serial_masked"].endswith("1234") and "FAKESERIAL" not in json.dumps(S) and A["unencrypted"] and A["warranty"] == "expiring"
          and A["strip"][-1]["state"] == "success" and B["rpo"] == "Breached" and B["flags"] == ["missing serial", "missing value"] and G["rpo"] == "Not scheduled" and G["flags"] == [])
    check("audit_no_sensitive", "FAKESERIAL" not in json.dumps(av.read_audit(k)) and "FAKE-TEST" not in json.dumps(av.read_audit(k)))
    check("delete_wrong_confirm", req(f"/api/item/{G['id']}/delete", {"confirm_name": "nope"})[0] == 400)
    check("delete", req(f"/api/item/{G['id']}/delete", {"confirm_name": "FAKE-TEST Desk Gamma"})[0] == 200)
    r415 = urllib.request.Request(base + "/api/item", data=b"name=x", headers={"Content-Type": "application/x-www-form-urlencoded"})
    try: urllib.request.urlopen(r415, timeout=10); code415 = 200
    except urllib.error.HTTPError as e: code415 = e.code
    check("non_json_415", code415 == 415)
    # sources rendering data (inject a fake failing source directly through the write path)
    con = av.open_db(k); con.execute("INSERT INTO sources(name,kind,last_sync,added,updated,skipped,health,detail) VALUES('FAKE Jamf','Jamf','2026-01-01',1,2,3,'failing','fake auth error')"); av.save_db(k, con); con.close()
    S = json.loads(req("/api/state")[1]); check("sources_listed", len(S["sources"]) == 1 and len(S["items"]) == 2)
    # A +09:00 timestamp is the same instant as server "now" and must be stored in vault TZ,
    # not as Tokyo wall time (which would fall off the New York 30-day strip).
    server_now = datetime.datetime.fromisoformat(json.loads(req("/api/state")[1])["now"])
    tokyo = server_now.astimezone(datetime.timezone(datetime.timedelta(hours=9))).isoformat(timespec="seconds")
    check("log_offset_date", req(f"/api/item/{a}/log_backup", {"result": "manual", "date": tokyo, "note": "tz"})[0] == 200)
    hist = json.loads(req(f"/api/item/{a}")[1])["history"]
    stored = next(h["date"] for h in hist if h.get("note") == "tz")
    check("log_offset_same_instant", abs((datetime.datetime.fromisoformat(stored) - server_now).total_seconds()) < 1)
    check("log_offset_vault_tz", stored.endswith("-04:00") or stored.endswith("-05:00"))
    paths = [os.path.join(TMP, "blobs", blob + ".enc"), os.path.join(TMP, "blobs", rblob + ".enc")]
    check("blobs_present_before_delete", all(os.path.exists(p) for p in paths))
    check("delete_attached", req(f"/api/item/{a}/delete", {"confirm_name": "FAKE-TEST Laptop Alpha"})[0] == 200)
    check("blobs_removed", all(not os.path.exists(p) for p in paths) and req("/api/blob/" + blob)[0] == 404 and req("/api/blob/" + rblob)[0] == 404)
    st, b, _ = req("/api/export", {"kind": "csv"})
    exported = json.loads(b)
    exp_path = os.path.join(TMP, exported.get("path") or "missing")
    check("export_api", st == 200 and exported.get("ok") and exported.get("kind") == "csv" and os.path.isfile(exp_path) and oct(os.stat(exp_path).st_mode & 0o777) == "0o600" and os.path.realpath(exp_path).startswith(os.path.realpath(os.path.join(TMP, "exports")) + os.sep))
    st, b, _ = req("/api/item", {"name": "FAKE-TEST Sync Target", "category": "Computers", "room": "Office", "model": "SyncModel"})
    check("sync_target_added", st == 200)
    sync_target = json.loads(b)["id"]
    fixture = {"rows": [{"hostname": "FAKE-TEST Sync Target", "model": "SyncModel", "serial": "SOFT9999XXXX"}]}
    class _Fix(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps(fixture["rows"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *args):
            pass
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Fix)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    con = av.open_db(k)
    cur = con.execute(
        "INSERT INTO sources(name, kind, connector, config, added, updated, skipped, not_seen) VALUES(?,?,?,?,0,0,0,0)",
        ("FAKE REST", "REST", "generic_rest", json.dumps({
            "url": "http://127.0.0.1:%d/devices" % port, "auth": "none", "allow_insecure": True,
            "pagination": "none", "mapping": {"name": "hostname", "serial": "serial", "model": "model"},
        })),
    )
    sid = cur.lastrowid
    av.save_db(k, con); con.close()
    before_ids = [i["id"] for i in json.loads(req("/api/state")[1])["items"]]
    st, b, _ = req("/api/source/%d/sync" % sid, {})
    synced = json.loads(b)
    after_ids = [i["id"] for i in json.loads(req("/api/state")[1])["items"]]
    check("sync_api", st == 200 and synced.get("ok") is True and synced.get("review", {}).get("id"))
    check("sync_keeps_local", after_ids == before_ids and sync_target in after_ids and "SOFT9999XXXX" not in b.decode())
    review_id = synced["review"]["id"]
    st, b, _ = req("/api/review/%d/verify" % review_id, {"index": 0})
    check("verify_api", st == 200 and json.loads(b).get("verified") is True)
    st, b, _ = req("/api/review/%d/commit" % review_id, {})
    check("commit_api", st == 200 and json.loads(b).get("ok") is True)
    detail = json.loads(req("/api/item/%d" % sync_target)[1])
    kept = detail["item"]
    revealed = json.loads(req("/api/item/%d/serial" % sync_target)[1])["serial"]
    check("commit_keeps_name", kept["name"] == "FAKE-TEST Sync Target" and kept.get("serial") is None and revealed == "SOFT9999XXXX" and "SOFT9999XXXX" not in json.dumps(detail))
    fixture["rows"] = [{"hostname": "FAKE-TEST Fresh", "model": "OtherModel", "serial": "FRESH123456"}]
    st, b, _ = req("/api/source/%d/sync" % sid, {})
    again = json.loads(b)
    check("sync_again", st == 200 and again.get("ok") is True and "FRESH123456" not in b.decode())
    ids_before_discard = {i["id"] for i in json.loads(req("/api/state")[1])["items"]}
    st, b, _ = req("/api/review/%d/discard" % again["review"]["id"], {})
    names_after = [i["name"] for i in json.loads(req("/api/state")[1])["items"]]
    ids_after_discard = {i["id"] for i in json.loads(req("/api/state")[1])["items"]}
    check("discard_api", st == 200 and json.loads(b).get("ok") is True and ids_after_discard == ids_before_discard and "FAKE-TEST Fresh" not in names_after)
    actions = {x["action"] for x in av.read_audit(k)}
    check("api_audited", {"export", "sync", "verify_soft", "commit", "discard", "item_delete"} <= actions)
    raw = open(os.path.join(TMP, "vault.db.enc"), "rb").read()
    check("db_encrypted", b"SQLite format" not in raw and b"FAKE-TEST" not in raw)
    # ---------- lock.sh
    p = subprocess.run(["bash", os.path.join(BIN, "lock.sh")], env=env, capture_output=True, text=True, timeout=30)
    time.sleep(0.3)
    check("lock_sh", srv.poll() is not None and not os.path.exists(uf) and not os.path.exists(os.path.join(TMP, ".dashboard.pid")))
    check("stop_audited", [x["action"] for x in av.read_audit(k)].count("dashboard_stop") == 1)
    # ---------- idle auto-shutdown (short timeout for test)
    srv2 = subprocess.Popen([PY, os.path.join(BIN, "dashboard.py")], env=dict(env, ASSETVAULT_IDLE_SECONDS="3"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try: srv2.wait(timeout=30)
    except subprocess.TimeoutExpired: srv2.kill()
    stops = [x for x in av.read_audit(k) if x["action"] == "dashboard_stop"]
    check("idle_shutdown", srv2.returncode is not None and stops[-1]["detail"]["reason"] == "idle" and not os.path.exists(uf))
    # ---------- no plaintext anywhere in temp root
    hits, leaks = [], []
    phrase = os.environ["ASSETVAULT_PASSPHRASE"].encode()
    for dp, _, fs in os.walk(TMP):
        for fn in fs:
            with open(os.path.join(dp, fn), "rb") as fh:
                data = fh.read()
            if b"SQLite format" in data: hits.append(fn)
            if phrase in data: leaks.append(os.path.join(dp, fn))
    check("no_plaintext_files", hits == [])
    check("passphrase_not_on_disk", leaks == [])
finally:
    if "httpd" in dir() and locals().get("httpd"):
        try: locals()["httpd"].shutdown()
        except Exception: pass
    for pr in ("srv", "srv2"):
        if pr in dir() and locals()[pr].poll() is None: locals()[pr].kill()
    shutil.rmtree(TMP, ignore_errors=True)
    R["temp_vault_deleted"] = not os.path.exists(TMP)
print(json.dumps(R, indent=0))
print("FAILED:", fails if fails else "none", f"({sum(R.values())}/{len(R)} passed)")
sys.exit(1 if fails else 0)
