"""Connect, sync, import, review, and export.

The CLI and the dashboard both call this module. It does not take the
dashboard lock and it does not print. Secrets stay in the environment;
audit lines carry counts and health only.
"""
import json, os

import avcore as av
import connectors
import exports
import importers
import merge
from connectors.base import ConnectorError, public_device
from errors import OpsError

def version_string():
    here = os.path.dirname(os.path.abspath(__file__))
    package = os.path.dirname(here)
    for path in (
        os.path.join(os.path.dirname(package), "VERSION"),
        os.path.join(package, "VERSION"),
        os.path.join(av.ROOT, "VERSION"),
    ):
        try:
            text = open(path, encoding="utf-8").read().strip()
        except OSError:
            continue
        if text:
            return text
    return "unknown"

def _with_db(fn, key=None):
    key = av.unlock() if key is None else key
    con = av.open_db(key)
    action = detail = None
    try:
        if av.schema_version(con) < av.SCHEMA_VERSION:
            con.close()
            con = None
            av.migrate(key)
            con = av.open_db(key)
        result, action, detail = fn(con)
        if action:
            av.save_db(key, con)
    finally:
        if con is not None:
            con.close()
    if action:
        av.audit(key, action, detail=detail)
    return result

def _counts(plan):
    return {
        "exact": len(plan.get("exact") or []),
        "soft": len(plan.get("soft") or []),
        "new": len(plan.get("new") or []),
        "not_seen": len(plan.get("not_seen") or []),
        "skipped": len(plan.get("skipped") or []),
    }

def _health(exc):
    health = getattr(exc, "health", None)
    if health not in ("OK", "Auth failed", "Unreachable"):
        health = "Unreachable"
    return health, av.scrub(str(exc))[:300]

def find_source(con, ref):
    if isinstance(ref, int) or (isinstance(ref, str) and ref.isdigit()):
        row = con.execute("SELECT * FROM sources WHERE id=?", (int(ref),)).fetchone()
        if row:
            return dict(row)
    name = str(ref)
    rows = [dict(r) for r in con.execute("SELECT * FROM sources")]
    exact = [r for r in rows if r["name"] == name]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise OpsError("ambiguous source")
    folded = [r for r in rows if (r["name"] or "").casefold() == name.casefold()]
    if len(folded) == 1:
        return folded[0]
    if len(folded) > 1:
        raise OpsError("ambiguous source")
    linked = [r for r in rows if r.get("connector") == name]
    if len(linked) == 1:
        return linked[0]
    if len(linked) > 1:
        raise OpsError("ambiguous source")
    raise OpsError("unknown source")

def _config_text(config):
    return json.dumps(config, sort_keys=True, separators=(",", ":"))

def _load_config(raw):
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        raise OpsError("stored config is unreadable") from None
    if not isinstance(data, dict):
        raise OpsError("stored config is unreadable")
    return data

def _review_out(con, review_id):
    row = con.execute("SELECT * FROM reviews WHERE id=?", (review_id,)).fetchone()
    if not row:
        raise OpsError("no such review")
    return merge.review_view(con, row)

def connect_source(connector, config, preview=False, display_name=None, key=None):
    """Save non-secret config and run test(). Auth failure still saves the source."""
    if connector not in connectors.CLASSES:
        raise OpsError("unknown connector")
    if not isinstance(config, dict):
        raise OpsError("config must be an object")
    config = dict(config)
    display = str(display_name or config.pop("name", None) or connector).strip()
    if not display or any(c in display for c in "\r\n\x00"):
        raise OpsError("invalid name")
    if len(display) > 200:
        raise OpsError("invalid name")
    try:
        built = connectors.build(connector, config)
        built.validate()
    except ConnectorError as exc:
        health, message = _health(exc)
        audit_key = key if key is not None else av.unlock()
        av.audit(audit_key, "connect", detail={"connector": connector, "health": health, "error": message})
        raise OpsError(message) from None
    kind = connectors.CLASSES[connector].kind

    def fn(con):
        existing = con.execute("SELECT * FROM sources WHERE name=?", (display,)).fetchone()
        if existing:
            if existing["connector"] and existing["connector"] != connector:
                raise OpsError("source name already used")
            if not existing["connector"] and existing["kind"] == "CSV import":
                raise OpsError("source name already used by an import")
            sid = existing["id"]
            con.execute(
                "UPDATE sources SET kind=?, connector=?, config=? WHERE id=?",
                (kind, connector, _config_text(config), sid),
            )
        else:
            cur = con.execute(
                "INSERT INTO sources(name, kind, connector, config, added, updated, skipped, not_seen) VALUES(?,?,?,?,0,0,0,0)",
                (display, kind, connector, _config_text(config)),
            )
            sid = cur.lastrowid
        try:
            conn = connectors.build(connector, config)
            result = conn.test()
            health, detail, devices = "OK", "connected", list(result.get("devices") or [])
        except ConnectorError as exc:
            health, detail = _health(exc)
            devices = []
        con.execute("UPDATE sources SET health=?, detail=? WHERE id=?", (health, detail, sid))
        out = {
            "ok": health == "OK", "source_id": sid, "name": display,
            "connector": connector, "health": health, "detail": detail,
        }
        if preview:
            out["preview"] = [public_device(dev) for dev in devices[:5]]
        if health != "OK":
            out["error"] = detail
        return out, "connect", {
            "source_id": sid, "connector": connector, "health": health, "preview": len(devices),
        }
    return _with_db(fn, key)

def sync_source(ref, key=None):
    """Full pull into a staged review. A failed pull does not flag devices not seen."""
    def fn(con):
        src = find_source(con, ref)
        if not src.get("connector"):
            raise OpsError("source has no connector")
        config = _load_config(src.get("config"))
        try:
            conn = connectors.build(src["connector"], config)
            devices = list(conn.pull())
        except ConnectorError as exc:
            health, detail = _health(exc)
            con.execute(
                "UPDATE sources SET health=?, detail=?, last_sync=? WHERE id=?",
                (health, detail, av.now(), src["id"]),
            )
            return (
                {"ok": False, "error": detail, "health": health, "source_id": src["id"]},
                "sync",
                {"source_id": src["id"], "connector": src["connector"], "health": health},
            )
        rid, plan = merge.stage(con, src["id"], devices, "sync")
        note = "review staged"
        extra = [av.scrub(item) for item in (getattr(conn, "notes", None) or []) if item]
        if extra:
            note = note + "; " + "; ".join(extra)
        con.execute(
            "UPDATE sources SET health='OK', detail=?, last_sync=? WHERE id=?",
            (note[:300], av.now(), src["id"]),
        )
        counts = _counts(plan)
        return (
            {"ok": True, "source_id": src["id"], "review": _review_out(con, rid), "counts": counts},
            "sync",
            {"source_id": src["id"], "connector": src["connector"], "health": "OK", **counts},
        )
    return _with_db(fn, key)

def disconnect_source(ref, key=None):
    def fn(con):
        src = find_source(con, ref)
        con.execute("DELETE FROM reviews WHERE source_id=? AND status='staged'", (src["id"],))
        con.execute(
            "UPDATE sources SET connector=NULL, config=NULL, health=NULL, detail=? WHERE id=?",
            ("disconnected", src["id"]),
        )
        return (
            {"ok": True, "source_id": src["id"], "name": src["name"]},
            "disconnect",
            {"source_id": src["id"], "connector": src.get("connector")},
        )
    return _with_db(fn, key)

def import_file(path, name=None, mapping=None, key=None):
    try:
        loaded = importers.load_import(path, mapping)
    except OpsError as exc:
        audit_key = key if key is not None else av.unlock()
        av.audit(audit_key, "import", detail={"error": av.scrub(str(exc))[:300]})
        raise
    label = str(name or loaded["label"]).strip()
    if not label or any(c in label for c in "\r\n\x00") or len(label) > 200:
        raise OpsError("invalid name")

    def fn(con):
        existing = con.execute("SELECT * FROM sources WHERE name=?", (label,)).fetchone()
        if existing and existing["connector"]:
            raise OpsError("source name already used by a connector")
        if existing and existing["kind"] not in (None, "", "CSV import"):
            raise OpsError("source name already used")
        if existing:
            sid = existing["id"]
            con.execute("UPDATE sources SET kind='CSV import' WHERE id=?", (sid,))
        else:
            cur = con.execute(
                "INSERT INTO sources(name, kind, added, updated, skipped, not_seen) VALUES(?, 'CSV import', 0, 0, 0, 0)",
                (label,),
            )
            sid = cur.lastrowid
        rid, plan = merge.stage(
            con, sid, loaded["devices"], "import",
            detected=loaded["detected"], mapping=loaded["mapping"],
        )
        con.execute(
            "UPDATE sources SET health='OK', detail=?, last_sync=? WHERE id=?",
            ("review staged", av.now(), sid),
        )
        counts = _counts(plan)
        return (
            {
                "ok": True, "source_id": sid, "detected": loaded["detected"],
                "mapping": _public_mapping(loaded["mapping"]), "rows": len(loaded["devices"]),
                "review": _review_out(con, rid), "counts": counts,
            },
            "import",
            {"source_id": sid, "detected": loaded["detected"], "rows": len(loaded["devices"]), **counts},
        )
    return _with_db(fn, key)

def _public_mapping(mapping):
    return merge._public_mapping(mapping)

def _one_review(con, review_id):
    if review_id is None:
        rows = list(con.execute("SELECT id FROM reviews WHERE status='staged' ORDER BY id"))
        if len(rows) != 1:
            raise OpsError("specify a review" if rows else "no staged review")
        return rows[0]["id"]
    return int(review_id)

def verify_soft(review_id, index, verified=None, key=None):
    def fn(con):
        flag = merge.set_verified(con, int(review_id), int(index), verified)
        return (
            {"ok": True, "review_id": int(review_id), "index": int(index), "verified": flag},
            "verify_soft",
            {"review_id": int(review_id), "index": int(index), "verified": flag},
        )
    return _with_db(fn, key)

def commit_staged(review_id=None, verify=None, key=None):
    def fn(con):
        rid = _one_review(con, review_id)
        for index in verify or []:
            merge.set_verified(con, rid, int(index), True)
        counts = merge.commit_review(con, rid)
        return (
            {"ok": True, "review_id": rid, "counts": counts},
            "commit",
            {"review_id": rid, **counts},
        )
    return _with_db(fn, key)

def discard_staged(review_id=None, key=None):
    def fn(con):
        rid = _one_review(con, review_id)
        info = merge.discard_review(con, rid)
        return (
            {"ok": True, "review_id": rid, "source_id": info["source_id"]},
            "discard",
            {"review_id": rid, "source_id": info["source_id"]},
        )
    return _with_db(fn, key)

def list_connectors(key=None):
    def fn(con):
        rows = []
        sql = "SELECT id, name, kind, connector, last_sync, added, updated, skipped, not_seen, health, detail FROM sources ORDER BY name"
        for row in con.execute(sql):
            rows.append(dict(row))
        return {"ok": True, "version": version_string(), "sources": rows, "available": connectors.describe_all()}, None, None
    return _with_db(fn, key)

def list_reviews(key=None):
    def fn(con):
        rows = []
        for row in con.execute("SELECT * FROM reviews WHERE status='staged' ORDER BY id"):
            rows.append(merge.review_view(con, row))
        return {"ok": True, "reviews": rows}, None, None
    return _with_db(fn, key)

def export_inventory(kind, key=None):
    key = av.unlock() if key is None else key
    con = av.open_db(key)
    try:
        if av.schema_version(con) < av.SCHEMA_VERSION:
            con.close()
            con = None
            av.migrate(key)
    finally:
        if con is not None:
            con.close()
    kind = (kind or "").strip().lower()
    if kind == "csv":
        filename, data, count = exports.build_csv(key)
    elif kind == "pdf":
        filename, data, count = exports.build_pdf(key, redacted=False)
    elif kind in ("pdf-redacted", "pdf_redacted", "redacted"):
        filename, data, count = exports.build_pdf(key, redacted=True)
        kind = "pdf-redacted"
    else:
        av.audit(key, "export", detail={"error": "unknown export"})
        raise OpsError("unknown export")
    av.write_export(filename, data)
    av.audit(key, "export", detail={"file": filename, "bytes": len(data), "items": count, "kind": kind})
    return {"ok": True, "filename": filename, "bytes": len(data), "items": count, "kind": kind, "path": "exports/" + filename}
