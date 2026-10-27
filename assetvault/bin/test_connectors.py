"""Connector, import, merge, export, and migration tests. No live network."""
import os, sys, json, csv, secrets, tempfile, shutil, subprocess, socket, sqlite3, uuid, base64

# This file lives at <repo>/assetvault/bin/ when run from a checkout, and at
# <ASSETVAULT_ROOT>/bin/ after install.sh. The repo root is the directory that
# contains install.sh. An installed tree has no install.sh beside it.
HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
REPO = os.path.dirname(PKG)
if not (os.path.isfile(os.path.join(REPO, "install.sh")) and os.path.isdir(os.path.join(REPO, "assetvault", "bin"))):
    REPO = None
INSTALL_ROOT = os.environ.get("ASSETVAULT_ROOT")

def _venv_python():
    """Prefer the venv next to the code (ASSETVAULT_ROOT or this tree). Fall back to this interpreter."""
    candidates = []
    if INSTALL_ROOT:
        candidates.append(os.path.join(INSTALL_ROOT, ".venv", "bin", "python"))
    candidates.append(os.path.join(PKG, ".venv", "bin", "python"))
    for cand in candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return sys.executable

PY = _venv_python()
TMP = tempfile.mkdtemp(prefix="avc-"); os.chmod(TMP, 0o700)
VAULT = os.path.join(TMP, "vault"); os.makedirs(VAULT); os.chmod(VAULT, 0o700)
INBOX = os.path.join(TMP, "inbox"); os.makedirs(INBOX)
os.environ["ASSETVAULT_ROOT"] = VAULT
os.environ["ASSETVAULT_PASSPHRASE"] = "throwaway-" + secrets.token_hex(16)
SECRET = "graph-secret-" + secrets.token_hex(8)
AD_PW = "ad-secret-" + secrets.token_hex(8)
JAMF_PW = "jamf-secret-" + secrets.token_hex(8)
REST_TOK = "rest-token-" + secrets.token_hex(8)
REST_PW = "rest-password-" + secrets.token_hex(8)
for _name in ("ASSETVAULT_GRAPH_SECRET", "ASSETVAULT_AD_PASSWORD", "ASSETVAULT_JAMF_SECRET", "ASSETVAULT_REST_TOKEN", "ASSETVAULT_REST_PASSWORD"):
    os.environ.pop(_name, None)
BIN = HERE
sys.path.insert(0, BIN)
import avcore as av
from connectors.base import HttpResponse, HttpClient, ConnectorError, device, jget, public_device
from connectors.entra import EntraConnector
from connectors.ad import AdConnector, filetime_to_iso, guid_str, parse_server
from connectors.jamf import JamfConnector
from connectors.generic_rest import GenericRestConnector
import connectors, merge, ops, importers

def _blocked(*_a, **_k):
    raise AssertionError("network blocked")
socket.create_connection = _blocked
socket.socket.connect = _blocked

R = {}; fails = []
def check(name, cond):
    if cond == "skipped":
        R[name] = "skipped"
        return
    R[name] = bool(cond)
    if not cond: fails.append(name)

def _under(path, root):
    if not root:
        return False
    path = os.path.realpath(path)
    root = os.path.realpath(root)
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False

def js(status, obj, headers=None):
    return HttpResponse(status, headers or {}, json.dumps(obj).encode())

class Script:
    def __init__(self):
        self.plan = []
        self.urls = []
        self.bodies = []
        self.sleeps = []
    def on(self, part, *outcomes):
        self.plan.append([part, list(outcomes)])
        return self
    def send(self, method, url, headers, body, timeout):
        self.urls.append(url)
        self.bodies.append(body)
        for row in self.plan:
            if row[0] in url and row[1]:
                out = row[1].pop(0)
                if isinstance(out, BaseException):
                    raise out
                return out
        raise AssertionError("unexpected " + url)
    def sleep(self, n):
        self.sleeps.append(n)

def entra_row(oid, did, name):
    return {"id": oid, "deviceId": did, "displayName": name, "operatingSystem": "Windows", "operatingSystemVersion": "11"}

def intune_row():
    return {"id": "mdm-1", "azureADDeviceId": "aad-1", "deviceName": "PC-1", "serialNumber": "SN-11111",
            "manufacturer": "Dell", "model": "X", "operatingSystem": "Windows", "osVersion": "10.0",
            "userPrincipalName": "a@contoso.test", "isEncrypted": True, "lastSyncDateTime": "2026-10-01T00:00:00Z",
            "wiFiMacAddress": "AA-BB-CC-DD-EE-FF"}

ENTRA_CFG = {"tenant_id": "contoso.onmicrosoft.com", "client_id": "app-id-1"}

try:
    # ---------- 0.1.0 vault upgrades in place
    av.init(["Office"], ["Computers"], 500)
    key = av.unlock()
    con = av.open_db(key)
    for name, decl in (
        ("owner", "TEXT"), ("mac", "TEXT"), ("os", "TEXT"),
        ("source", "TEXT DEFAULT 'Manual' CHECK(source IN ('Manual','CSV import','Entra-Intune','AD','Jamf') OR source IS NULL)"),
        ("external_ids", "TEXT DEFAULT '{}'"), ("last_checkin", "TEXT"), ("encryption_status", "TEXT"),
        ("rpo_target_hours", "INTEGER"), ("verified", "INTEGER DEFAULT 0"), ("paused", "INTEGER DEFAULT 0"),
    ):
        con.execute("ALTER TABLE items ADD COLUMN %s %s" % (name, decl))
    con.executescript("""
        CREATE TABLE backup_history(
         id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL, date TEXT NOT NULL,
         result TEXT NOT NULL CHECK(result IN ('success','partial','failed','manual')), note TEXT, created_at TEXT);
        CREATE TABLE sources(
         id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT, last_sync TEXT,
         added INTEGER DEFAULT 0, updated INTEGER DEFAULT 0, skipped INTEGER DEFAULT 0, health TEXT, detail TEXT);
        CREATE TABLE item_sources(
         item_id INTEGER NOT NULL, source_id INTEGER NOT NULL, seen_at TEXT, PRIMARY KEY(item_id, source_id));
        CREATE INDEX ix_bh_item ON backup_history(item_id, date);
    """)
    con.execute("INSERT OR REPLACE INTO config(k,v) VALUES('schema_version', ?)", (json.dumps(2),))
    con.execute("INSERT INTO items(name, serial, source, room, notes) VALUES('kept-device','KEEP1234','Manual','Office','keep me')")
    con.execute("INSERT INTO backup_history(item_id, date, result, created_at) VALUES(1, '2026-01-01T00:00:00', 'success', '2026-01-01T00:00:00')")
    av.save_db(key, con); con.close()
    changes = av.migrate(key)
    check("upgraded_from_010", "items.source_check_relaxed" in changes and "table reviews" in changes)
    check("migrate_twice", av.migrate(key) == [])
    con = av.open_db(key)
    kept = con.execute("SELECT id, serial, room, notes FROM items WHERE name='kept-device'").fetchone()
    check("kept_row", tuple(kept) == (1, "KEEP1234", "Office", "keep me"))
    check("check_probe_gone", con.execute("SELECT count(*) FROM items WHERE name='__av_check_rest__'").fetchone()[0] == 0)
    check("schema_is_3", av.schema_version(con) == 3)
    con.execute("INSERT INTO items(name, source) VALUES('rest-ok','REST')")
    check("rest_insert", con.execute("SELECT source FROM items WHERE name='rest-ok'").fetchone()[0] == "REST")
    con.execute("DELETE FROM items WHERE name='rest-ok'")
    con.execute("SAVEPOINT t")
    blocked = False
    try:
        con.execute("INSERT INTO items(name, backup_status) VALUES('bad-status','nope')")
    except sqlite3.IntegrityError:
        blocked = True
    con.execute("ROLLBACK TO t"); con.execute("RELEASE t")
    check("backup_check_kept", blocked)
    second = con.execute("INSERT INTO items(name) VALUES('second')")
    check("id_sequence", second.lastrowid > 1)
    con.execute("DELETE FROM items WHERE name='second'")
    hist = con.execute("SELECT result FROM backup_history WHERE item_id=1").fetchone()[0]
    check("history_kept", hist == "success")
    av.save_db(key, con); con.close()
    raw = open(av.DB, "rb").read()
    check("migrated_not_plaintext", b"SQLite format" not in raw and b"KEEP1234" not in raw and b"keep me" not in raw)

    # ---------- merge review
    def local(i, **kw):
        row = {"id": i, "serial": None, "mac": None, "name": None, "model": None, "external_ids": {}, "links": []}
        row.update(kw)
        return row
    now = "2026-10-25T00:00:00-04:00"
    plan = merge.plan_merge(
        [local(1, serial=""), local(2, serial=None)],
        [device(name="N", serial="", model="Z")], 7, now)
    check("empty_serial_not_exact", plan["exact"] == [] and len(plan["new"]) == 1)
    plan = merge.plan_merge(
        [local(1, serial="ABC123"), local(2, serial="abc123")],
        [device(name="N", serial="ABC123")], 7, now)
    check("ambiguous_serial_skipped", plan["exact"] == [] and plan["skipped"] and plan["skipped"][0]["reason"] == "ambiguous")
    plan = merge.plan_merge(
        [local(1, serial="ABC123", links=[{"source_id": 7, "external_id": "e"}]),
         local(2, serial="ABC123", links=[{"source_id": 7, "external_id": "f"}])],
        [device(name="N", serial="ABC123")], 7, now)
    check("ambiguous_not_flagged_missing", plan["not_seen"] == [])
    plan = merge.plan_merge(
        [local(1, mac="aa:bb:cc:dd:ee:ff"), local(2, mac="00:00:00:00:00:00")],
        [device(name="N", mac="AA-BB-CC-DD-EE-FF"), device(name="Z", mac="000000000000")], 7, now)
    check("mac_exact", len(plan["exact"]) == 1 and plan["exact"][0]["local_id"] == 1 and plan["exact"][0]["match_on"] == "mac")
    plan = merge.plan_merge(
        [local(1, external_ids={"7": "Obj-1"}, links=[{"source_id": 7, "external_id": "Obj-1"}]),
         local(2, external_ids={"8": "Obj-1"}, links=[{"source_id": 8, "external_id": "Obj-1"}])],
        [device(name="N", external_id="obj-1")], 7, now)
    check("external_id_per_source", len(plan["exact"]) == 1 and plan["exact"][0]["local_id"] == 1)
    plan = merge.plan_merge(
        [local(1, name="Alpha", model="M1"), local(2, name="Beta", model="M2", links=[{"source_id": 7}])],
        [device(name="alpha", model="m1")], 7, now)
    check("soft_not_auto", len(plan["soft"]) == 1 and plan["soft"][0]["verified"] is False and plan["soft"][0]["local_id"] == 1 and [row["local_id"] for row in plan["not_seen"]] == [2])
    plan = merge.plan_merge(
        [local(1, name="Same", model="M"), local(2, name="Same", model="M")],
        [device(name="Same", model="M")], 7, now)
    check("soft_ambiguous_not_new", plan["soft"] == [] and plan["new"] == [] and plan["skipped"][0]["reason"] == "ambiguous")
    plan = merge.plan_merge(
        [local(1, links=[{"source_id": 7}]), local(2, links=[{"source_id": 8}]), local(3)],
        [], 7, now)
    check("not_seen_only_this_source", [row["local_id"] for row in plan["not_seen"]] == [1])
    plan = merge.plan_merge(
        [local(1, serial="DUP")],
        [device(name="A", serial="DUP"), device(name="B", serial="DUP")], 7, now)
    check("duplicate_in_source", len(plan["exact"]) == 1 and plan["skipped"][0]["reason"] == "duplicate in source")
    plan = merge.plan_merge(
        [local(1, serial="DUP", mac="aa:bb:cc:dd:ee:01"),
         local(2, serial="OTHER", mac="aa:bb:cc:dd:ee:02", external_ids={"7": "ext-2"}, links=[{"source_id": 7, "external_id": "ext-2"}])],
        [device(name="A", serial="DUP"), device(name="B", serial="DUP", mac="aa:bb:cc:dd:ee:02", external_id="ext-2")], 7, now)
    check("duplicate_serial_not_weaker", [row["local_id"] for row in plan["exact"]] == [1] and plan["skipped"][0]["reason"] == "duplicate in source" and all(row.get("local_id") != 2 for row in plan["exact"]))
    plan = merge.plan_merge(
        [local(1, mac="aa:bb:cc:dd:ee:11"),
         local(2, external_ids={"7": "ext-mac"}, links=[{"source_id": 7, "external_id": "ext-mac"}])],
        [device(name="A", mac="aa:bb:cc:dd:ee:11"),
         device(name="B", mac="aa:bb:cc:dd:ee:11", external_id="ext-mac")], 7, now)
    check("duplicate_mac_not_external", [row["local_id"] for row in plan["exact"]] == [1] and plan["exact"][0]["match_on"] == "mac" and plan["skipped"][0]["reason"] == "duplicate in source" and all(row.get("local_id") != 2 for row in plan["exact"]))
    named = device(serial="ABCDEFGH1234", model="ThinkPad")
    blank = device(serial="ABCDEFGH1234")
    leaked = public_device({"name": "host-ABCDEFGH1234", "serial": "ABCDEFGH1234", "external_id": "id-ABCDEFGH1234", "model": "ThinkPad"})
    check("fallback_name_hides_serial", named["name"] == "ThinkPad (\u20261234)" and named.get("name_fallback") is True and blank["name"] == "Unnamed device" and "ABCDEFGH1234" not in named["name"] and "ABCDEFGH1234" not in json.dumps(public_device(named)) and "ABCDEFGH1234" not in json.dumps(leaked))
    con = av.open_db(key)
    cur = con.execute("INSERT INTO items(name, serial, model) VALUES(?,?,?)", ("Keep Me", "FALLBACK9999", "Old"))
    kept_id = cur.lastrowid
    merge._apply(con, kept_id, device(serial="FALLBACK9999", model="ZBook"), {"id": 99, "kind": "REST"}, now)
    kept_row = con.execute("SELECT name, model FROM items WHERE id=?", (kept_id,)).fetchone()
    cur = con.execute("INSERT INTO items(name, serial) VALUES('', 'NEWFALL9999')")
    empty_id = cur.lastrowid
    merge._apply(con, empty_id, device(serial="NEWFALL9999", model="Mini"), {"id": 99, "kind": "REST"}, now)
    empty_row = con.execute("SELECT name FROM items WHERE id=?", (empty_id,)).fetchone()
    con.execute("INSERT INTO items(name, serial) VALUES('ABCDEFGH1234','ABCDEFGH1234')")
    cur = con.execute("INSERT INTO sources(name, kind) VALUES('rev-src','REST')")
    sid = cur.lastrowid
    rid, _plan = merge.stage(con, sid, [device(serial="ABCDEFGH1234", model="ThinkPad")], "sync")
    view = merge.review_view(con, con.execute("SELECT * FROM reviews WHERE id=?", (rid,)).fetchone())
    view_text = json.dumps(view)
    con.close()
    check("fallback_does_not_replace_name", kept_row["name"] == "Keep Me" and kept_row["model"] == "ZBook" and empty_row["name"] == "Mini (\u20269999)" and "NEWFALL9999" not in empty_row["name"])
    check("review_hides_serial", "ABCDEFGH1234" not in view_text and view["exact"] and view["exact"][0]["local_name"] != "ABCDEFGH1234" and view["exact"][0]["incoming"]["name"] == "ThinkPad (\u20261234)")

    # ---------- HTTP client refuses writes, follows no redirects
    script = Script()
    client = HttpClient(["graph.microsoft.com"], allow_post=True, send=script.send, sleeper=script.sleep)
    for method, url in (("DELETE", "https://graph.microsoft.com/v1.0/devices/1"), ("PATCH", "https://graph.microsoft.com/v1.0/devices/1"), ("POST", "https://graph.microsoft.com/v1.0/devices")):
        try:
            client.request(method, url, {}, b"{}")
            check("write_refused_" + method, False)
        except ConnectorError as exc:
            check("write_refused_" + method, "write" in str(exc).lower() and not script.urls)
    script.urls.clear()
    try:
        client.request("GET", "https://evil.example/devices")
        check("host_refused", False)
    except ConnectorError as exc:
        check("host_refused", "unconfigured host" in str(exc) and not script.urls)
    script.on("graph.microsoft.com", js(302, {}, {"Location": "https://evil.example/"}))
    try:
        client.get("https://graph.microsoft.com/v1.0/devices")
        check("redirect_refused", False)
    except ConnectorError as exc:
        check("redirect_refused", "redirect" in str(exc) and len(script.urls) == 1)

    # ---------- Entra
    script = Script()
    script.on("/oauth2/v2.0/token", js(200, {"access_token": "tok"}))
    script.on("/v1.0/devices",
              js(200, {"value": [entra_row("obj-1", "aad-1", "PC-1")], "@odata.nextLink": "/v1.0/devices?$skiptoken=abc"}),
              js(200, {"value": [entra_row("obj-2", "aad-2", "PC-2")]}))
    script.on("managedDevices", js(200, {"value": [intune_row()]}))
    conn = EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}, send=script.send, sleeper=script.sleep)
    rows = list(conn.pull())
    check("entra_page_and_merge", len(rows) == 2 and rows[0]["external_id"] == "obj-1" and rows[0]["serial"] == "SN-11111"
          and rows[0]["managed_by"] == "Intune" and rows[0]["encryption_status"] == "encrypted" and rows[0]["mac"] == "aa:bb:cc:dd:ee:ff"
          and rows[1]["managed_by"] == "Entra ID"
          and any("$skiptoken=abc" in u and u.startswith("https://graph.microsoft.com/") for u in script.urls)
          and SECRET not in json.dumps(rows))
    preview = public_device(rows[0], [SECRET])
    check("preview_masks_serial", preview["serial"].endswith("1111") and "SN-11111" not in preview["serial"] and SECRET not in json.dumps(preview))
    script = Script()
    script.on("/oauth2/v2.0/token", js(200, {"access_token": "tok"}))
    script.on("/v1.0/devices", js(200, {"value": [entra_row("obj-3", "aad-3", "PC-3")]}))
    script.on("managedDevices", js(403, {"error": {"message": SECRET}}))
    conn = EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}, send=script.send)
    rows = list(conn.pull())
    check("entra_intune_degrade", len(rows) == 1 and rows[0]["name"] == "PC-3" and "Intune not permitted" in conn.notes and SECRET not in json.dumps(rows))

    script = Script()
    script.on("/oauth2/v2.0/token", js(401, {"error": SECRET}))
    conn = EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}, send=script.send)
    try:
        conn.pull()
        check("entra_401", False)
    except ConnectorError as exc:
        check("entra_401", exc.health == "Auth failed" and SECRET not in str(exc) and "error" not in str(exc).lower())

    script = Script()
    script.on("/oauth2/v2.0/token", js(200, {"access_token": "tok"}))
    script.on("/v1.0/devices", js(429, {}, {"Retry-After": "0"}), js(200, {"value": [entra_row("obj-9", "aad-9", "PC-9")]}))
    script.on("managedDevices", js(200, {"value": []}))
    conn = EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}, send=script.send, sleeper=script.sleep)
    got = list(conn.pull())
    check("entra_429", len(got) == 1 and script.sleeps == [0])

    script = Script()
    script.on("/oauth2/v2.0/token", TimeoutError("slow " + SECRET))
    conn = EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}, send=script.send)
    try:
        conn.pull()
        check("entra_timeout", False)
    except ConnectorError as exc:
        check("entra_timeout", str(exc) == "connection timed out" and SECRET not in str(exc) and exc.health == "Unreachable")

    script = Script()
    script.on("/oauth2/v2.0/token", js(200, {"access_token": "tok"}))
    script.on("/v1.0/devices", js(200, {"value": [entra_row("obj-1", "aad-1", "PC-1")], "@odata.nextLink": "https://evil.example/steal"}))
    conn = EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}, send=script.send)
    try:
        conn.pull()
        check("entra_next_host", False)
    except ConnectorError as exc:
        check("entra_next_host", "unconfigured host" in str(exc) and SECRET not in str(exc))

    try:
        EntraConnector(ENTRA_CFG, env={}, send=lambda *a: (_ for _ in ()).throw(AssertionError("should not send"))).pull()
        check("entra_missing_secret", False)
    except ConnectorError as exc:
        check("entra_missing_secret", "missing ASSETVAULT_GRAPH_SECRET" in str(exc) and exc.health == "Auth failed")
    try:
        EntraConnector({**ENTRA_CFG, "note": SECRET}, env={"ASSETVAULT_GRAPH_SECRET": SECRET}).validate()
        check("entra_config_rejects_secret", False)
    except ConnectorError as exc:
        check("entra_config_rejects_secret", str(exc) == "config must not contain secrets" and SECRET not in str(exc))
    try:
        EntraConnector(ENTRA_CFG, env={"ASSETVAULT_GRAPH_SECRET": SECRET}).pull()
        check("entra_blocks_network", False)
    except AssertionError as exc:
        check("entra_blocks_network", "network blocked" in str(exc))
    except ConnectorError:
        check("entra_blocks_network", False)

    # ---------- AD
    check("filetime", filetime_to_iso(116444736000000000) == "1969-12-31T19:00:00-05:00")
    sample = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    check("guid", guid_str(sample.bytes_le) == str(sample))
    for server, allow in (("ldap://dc.example", False), ("dc.example:389", False), ("dc.example:389", "true"), ("dc.example:389", 1)):
        try:
            parse_server({"server": server, "allow_insecure": allow})
            check("ad_refuse_%s_%s" % (server, allow), False)
        except ConnectorError as exc:
            check("ad_refuse_%s_%s" % (server, allow), "389" in str(exc))
    host, port, use_ssl = parse_server({"server": "dc.example"})
    check("ad_default_ldaps", (host, port, use_ssl) == ("dc.example", 636, True))
    host, port, use_ssl = parse_server({"server": "dc.example:389", "allow_insecure": True})
    check("ad_insecure_opt_in", (port, use_ssl) == (389, False))

    class Env(dict):
        def __init__(self):
            super().__init__()
            self.reads = []
        def get(self, k, default=None):
            self.reads.append(k)
            return super().get(k, default)

    env = Env()
    env["ASSETVAULT_AD_PASSWORD"] = AD_PW
    called = {"n": 0}
    def factory(*_a, **_k):
        called["n"] += 1
        raise AssertionError("factory called")
    try:
        AdConnector({"server": "ldap://dc.example", "base_dn": "DC=example,DC=test", "bind_user": "CN=svc,DC=example,DC=test", "allow_insecure": "true"}, env=env, ldap_factory=factory).pull()
        check("ad_refuses_before_bind", False)
    except ConnectorError as exc:
        check("ad_refuses_before_bind", called["n"] == 0 and "ASSETVAULT_AD_PASSWORD" not in env.reads and AD_PW not in str(exc))

    class LDAPBindError(Exception):
        pass
    class LDAPSocketReceiveTimeoutError(Exception):
        pass
    captured = {}
    def boom_factory(server_kwargs, conn_kwargs):
        captured["server"] = server_kwargs
        captured["conn"] = conn_kwargs
        raise LDAPBindError("bind failed password=" + conn_kwargs["password"])
    try:
        AdConnector({"server": "dc.example", "base_dn": "DC=example,DC=test", "bind_user": "CN=svc,DC=example,DC=test"}, env={"ASSETVAULT_AD_PASSWORD": AD_PW}, ldap_factory=boom_factory).pull()
        check("ad_bind_error", False)
    except ConnectorError as exc:
        check("ad_bind_error", exc.health == "Auth failed" and AD_PW not in str(exc) and captured["conn"]["read_only"] is True and captured["server"]["use_ssl"] is True
              and captured["conn"].get("auto_referrals") is False and captured["server"].get("allowed_referral_hosts") == [])
    def timeout_factory(*_a, **_k):
        raise LDAPSocketReceiveTimeoutError("timed out " + AD_PW)
    try:
        AdConnector({"server": "dc.example", "base_dn": "DC=example,DC=test", "bind_user": "CN=svc,DC=example,DC=test"}, env={"ASSETVAULT_AD_PASSWORD": AD_PW}, ldap_factory=timeout_factory).pull()
        check("ad_timeout", False)
    except ConnectorError as exc:
        check("ad_timeout", str(exc) == "connection timed out" and AD_PW not in str(exc))

    class FakeConn:
        def __init__(self):
            self.calls = 0
            self.entries = []
            self.result = {}
            self.unbound = False
        def search(self, **kw):
            assert kw["search_filter"] == "(&(objectCategory=computer)(objectClass=computer))"
            assert kw["paged_size"] == 200
            self.calls += 1
            if self.calls == 1:
                assert kw.get("paged_cookie") in (None, b"")
                self.entries = [{"name": "PC-A", "dNSHostName": "pc-a.example", "operatingSystem": "Windows", "operatingSystemVersion": "10", "lastLogonTimestamp": 116444736000000000, "description": "lab", "objectGUID": sample.bytes_le}]
                self.result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"next"}}}}
            else:
                assert kw["paged_cookie"] == b"next"
                self.entries = [{"name": "PC-B", "operatingSystem": "Linux", "objectGUID": uuid.uuid4().bytes_le}]
                self.result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b""}}}}
        def unbind(self):
            self.unbound = True
    fake = FakeConn()
    def ok_factory(server_kwargs, conn_kwargs):
        assert conn_kwargs["read_only"] is True and conn_kwargs["password"] == AD_PW
        return fake
    rows = list(AdConnector({"server": "ldaps://dc.example", "base_dn": "OU=Machines,DC=example,DC=test", "bind_user": "CN=svc,DC=example,DC=test"}, env={"ASSETVAULT_AD_PASSWORD": AD_PW}, ldap_factory=ok_factory).pull())
    check("ad_paging", fake.calls == 2 and fake.unbound and len(rows) == 2 and rows[0]["external_id"] == str(sample)
          and rows[0]["last_checkin"] == "1969-12-31T19:00:00-05:00" and rows[0]["notes"] == "lab" and rows[0]["managed_by"] == "Active Directory"
          and AD_PW not in json.dumps(rows))

    class RefConn:
        def __init__(self):
            self.searches = 0
            self.entries = [{"name": "should-not-import"}]
            self.result = {}
            self.unbound = False
        def search(self, **kw):
            self.searches += 1
            self.result = {"result": 10, "description": "referral", "referrals": ["ldap://evil.example:389/DC=example,DC=test"]}
        def unbind(self):
            self.unbound = True
    referral = RefConn()
    def ref_factory(server_kwargs, conn_kwargs):
        assert conn_kwargs.get("auto_referrals") is False
        assert server_kwargs.get("allowed_referral_hosts") == []
        assert conn_kwargs.get("password") == AD_PW
        return referral
    try:
        AdConnector({"server": "ldaps://dc.example", "base_dn": "DC=child,DC=example,DC=test", "bind_user": "CN=svc,DC=example,DC=test"}, env={"ASSETVAULT_AD_PASSWORD": AD_PW}, ldap_factory=ref_factory).pull()
        check("ad_referral_refused", False)
    except ConnectorError as exc:
        check("ad_referral_refused", exc.health == "Unreachable" and "referral" in str(exc) and referral.unbound and referral.searches == 1
              and "evil.example" not in str(exc) and AD_PW not in str(exc))

    class EmptyConn:
        def search(self, **kw):
            self.entries = []
            self.result = {"result": 0, "description": "success"}
        def unbind(self):
            pass
    empty_rows = list(AdConnector({"server": "ldaps://dc.example", "base_dn": "OU=Empty,DC=example,DC=test", "bind_user": "CN=svc,DC=example,DC=test"}, env={"ASSETVAULT_AD_PASSWORD": AD_PW}, ldap_factory=lambda *_a: EmptyConn()).pull())
    check("ad_empty_directory", empty_rows == [])

    # ---------- Jamf
    def jamf_computer(i):
        return {"id": i, "udid": "udid-%d" % i, "general": {"name": "mac-%d" % i, "assetTag": "A%d" % i},
                "hardware": {"serialNumber": "JAMF%04d" % i, "macAddress": "aa:bb:cc:dd:ee:%02x" % (i % 250), "make": "Apple", "model": "Mac"},
                "operatingSystem": {"name": "macOS", "version": "15"},
                "diskEncryption": {"fileVault2Enabled": True},
                "userAndLocation": {"email": "u%d@example.test" % i}}
    script = Script()
    script.on("/api/oauth/token", js(200, {"access_token": "jt"}))
    script.on("/api/v1/computers-inventory", js(404, {"httpStatus": 404}))
    script.on("/api/v3/computers-inventory", js(200, {"totalCount": 150, "results": [jamf_computer(i) for i in range(100)]}),
              js(200, {"totalCount": 150, "results": [jamf_computer(i) for i in range(100, 150)]}))
    script.on("/api/v2/mobile-devices", js(200, {"totalCount": 1, "results": [{"mobileDeviceId": 9, "general": {"displayName": "Phone", "osVersion": "18"}, "hardware": {"serialNumber": "MOB123456"}, "security": {"dataProtected": True}}]}))
    conn = JamfConnector({"url": "https://user:nope@contoso.jamfcloud.com/path?x=1", "client_id": "jamf-app"}, env={"ASSETVAULT_JAMF_SECRET": JAMF_PW}, send=script.send)
    try:
        conn.validate()
        check("jamf_rejects_userinfo", False)
    except ConnectorError as exc:
        check("jamf_rejects_userinfo", "credentials" in str(exc) and not script.urls)
    script = Script()
    script.on("/api/oauth/token", js(200, {"access_token": "jt"}))
    script.on("/api/v1/computers-inventory", js(404, {}))
    script.on("/api/v3/computers-inventory", js(200, {"totalCount": 150, "results": [jamf_computer(i) for i in range(100)]}),
              js(200, {"totalCount": 150, "results": [jamf_computer(i) for i in range(100, 150)]}))
    script.on("/api/v2/mobile-devices", js(200, {"totalCount": 1, "results": [{"mobileDeviceId": 9, "general": {"displayName": "Phone", "osVersion": "18"}, "hardware": {"serialNumber": "MOB123456"}, "security": {"dataProtected": True}}]}))
    conn = JamfConnector({"url": "https://contoso.jamfcloud.com/ignored", "client_id": "jamf-app"}, env={"ASSETVAULT_JAMF_SECRET": JAMF_PW}, send=script.send)
    rows = list(conn.pull())
    check("jamf_fallback_and_page", len(rows) == 151 and rows[0]["external_id"] == "computer:0" and rows[0]["encryption_status"] == "encrypted"
          and rows[-1]["external_id"] == "mobile:9" and rows[-1]["brand"] == "Apple"
          and any("/api/v3/computers-inventory" in u and "page=1" in u for u in script.urls)
          and not any("recovery" in u.lower() for u in script.urls) and JAMF_PW not in json.dumps(rows))
    script = Script()
    script.on("/api/oauth/token", js(401, {"error": JAMF_PW}))
    conn = JamfConnector({"url": "https://contoso.jamfcloud.com", "client_id": "jamf-app"}, env={"ASSETVAULT_JAMF_SECRET": JAMF_PW}, send=script.send)
    try:
        conn.pull()
        check("jamf_401", False)
    except ConnectorError as exc:
        check("jamf_401", exc.health == "Auth failed" and JAMF_PW not in str(exc))
    script = Script()
    script.on("/api/oauth/token", js(200, {"access_token": "jt"}))
    script.on("/api/v1/computers-inventory", js(200, {"totalCount": 1, "results": [jamf_computer(1)]}))
    script.on("/api/v2/mobile-devices", js(403, {"error": JAMF_PW}))
    conn = JamfConnector({"url": "https://contoso.jamfcloud.com", "client_id": "jamf-app"}, env={"ASSETVAULT_JAMF_SECRET": JAMF_PW}, send=script.send)
    rows = list(conn.pull())
    check("jamf_mobile_degrade", len(rows) == 1 and "mobile devices not permitted" in conn.notes)

    # ---------- generic REST
    check("jget_literal_key", jget({"a.b": 1, "a": {"b": 2}}, "a.b") == 1)
    check("jget_index", jget({"serials": ["ZZ", "YY"]}, "serials[0]") == "ZZ")
    cfg = {"url": "https://devices.example/api/devices", "auth": "bearer", "pagination": "next", "next_path": "links.next",
           "items_path": "data.devices", "mapping": {"name": "hostname", "serial": "serials[0]", "model": "hardware.model", "mac": "mac"}}
    script = Script()
    script.on("/api/devices",
              js(200, {"data": {"devices": [{"hostname": "r1", "serials": ["REST1111"], "hardware": {"model": "R"}, "mac": "aabbccddeeff"}, "skip-me"]}, "links": {"next": "https://devices.example/api/devices?page=2"}}),
              js(200, {"data": {"devices": [{"hostname": "r2", "serials": ["REST2222"], "hardware": {"model": "R"}}]}, "links": {}}))
    os.environ["ASSETVAULT_REST_TOKEN"] = REST_TOK
    conn = GenericRestConnector(cfg, env=os.environ, send=script.send)
    rows = list(conn.pull())
    check("rest_next_and_map", len(rows) == 2 and rows[0]["serial"] == "REST1111" and rows[0]["model"] == "R" and rows[0]["mac"] == "aa:bb:cc:dd:ee:ff" and rows[0]["source"] == "REST")
    script = Script()
    script.on("/api/devices", js(200, {"data": {"devices": [{"hostname": "r1"}]}, "links": {"next": "https://evil.example/out"}}))
    try:
        GenericRestConnector(cfg, env={"ASSETVAULT_REST_TOKEN": REST_TOK}, send=script.send).pull()
        check("rest_next_host", False)
    except ConnectorError as exc:
        check("rest_next_host", "unconfigured host" in str(exc) and REST_TOK not in str(exc))
    page_cfg = dict(cfg, pagination="page", page_param="page", page_start=1, page_size=1, page_size_param="per")
    script = Script()
    script.on("page=1", js(200, {"data": {"devices": [{"hostname": "p1", "serials": ["P111111"]}]}}))
    script.on("page=2", js(200, {"data": {"devices": [{"hostname": "p1", "serials": ["P111111"]}]}}))
    rows = list(GenericRestConnector(page_cfg, env={"ASSETVAULT_REST_TOKEN": REST_TOK}, send=script.send).pull())
    check("rest_page_stops_repeat", len(rows) == 1)
    zero_cfg = dict(page_cfg, page_start=0)
    script = Script()
    script.on("page=0", js(200, {"data": {"devices": [{"hostname": "z0", "serials": ["Z0001111"]}]}}))
    script.on("page=1", js(200, {"data": {"devices": []}}))
    rows = list(GenericRestConnector(zero_cfg, env={"ASSETVAULT_REST_TOKEN": REST_TOK}, send=script.send).pull())
    check("rest_page_start_zero", len(rows) == 1 and rows[0]["name"] == "z0" and script.urls and "page=0" in script.urls[0] and "page=1" not in script.urls[0])
    script = Script()
    script.on("/api/devices", js(401, {"token": REST_TOK}))
    try:
        GenericRestConnector(cfg, env={"ASSETVAULT_REST_TOKEN": REST_TOK}, send=script.send).pull()
        check("rest_401", False)
    except ConnectorError as exc:
        check("rest_401", exc.health == "Auth failed" and REST_TOK not in str(exc))
    try:
        GenericRestConnector(dict(cfg, url="http://devices.example/api/devices"), env={"ASSETVAULT_REST_TOKEN": REST_TOK}, send=script.send).pull()
        check("rest_https", False)
    except ConnectorError as exc:
        check("rest_https", "https" in str(exc))
    script = Script()
    script.on("devices.example", js(200, {"data": {"devices": [{"hostname": "h", "serials": ["ABCDE1234"]}]}}))
    basic = dict(cfg, url="http://devices.example/api/devices", auth="basic", username="reader", pagination="none", allow_insecure=True)
    rows = list(GenericRestConnector(basic, env={"ASSETVAULT_REST_PASSWORD": REST_PW}, send=script.send).pull())
    check("rest_basic_insecure", len(rows) == 1 and rows[0]["name"] == "h" and rows[0]["serial"] == "ABCDE1234" and REST_PW not in json.dumps(rows))
    header_cfg = dict(cfg, auth="header", header="X-Api-Key", pagination="none")
    script = Script()
    seen_headers = {}
    def capture(method, url, headers, body, timeout):
        seen_headers.update(headers)
        return js(200, {"data": {"devices": [{"hostname": "hdr", "serials": ["HDR12345"]}]}})
    rows = list(GenericRestConnector(header_cfg, env={"ASSETVAULT_REST_TOKEN": REST_TOK}, send=capture).pull())
    check("rest_custom_header", rows[0]["name"] == "hdr" and seen_headers.get("X-Api-Key") == REST_TOK)
    try:
        GenericRestConnector(dict(cfg, mapping={}), env={"ASSETVAULT_REST_TOKEN": REST_TOK}).validate()
        check("rest_mapping_required", False)
    except ConnectorError:
        check("rest_mapping_required", True)
    del os.environ["ASSETVAULT_REST_TOKEN"]

    # ---------- import detection and commit
    def write_csv(name, text):
        path = os.path.join(INBOX, name)
        open(path, "w", encoding="utf-8").write(text)
        return path
    intune = write_csv("intune.csv", "Device name,Serial number,Managed by,OS,Primary user UPN,Encrypted\nPC-1,INTUNE1234,Intune,Windows,a@contoso.test,Yes\n")
    loaded = importers.load_import(intune)
    check("detect_intune", loaded["detected"] == "intune" and loaded["devices"][0]["serial"] == "INTUNE1234" and loaded["devices"][0]["encryption_status"] == "encrypted")
    entra_csv = write_csv("entra.csv", "Display name,Device Id,Join type,OS\nEntra-PC,obj-9,Azure AD joined,Windows\n")
    check("detect_entra", importers.load_import(entra_csv)["detected"] == "entra")
    ad_csv = write_csv("ad.csv", "Name,OperatingSystem,ObjectGUID,DNSHostName,lastLogonTimestamp\nPC-A,Windows,00112233-4455-6677-8899-aabbccddeeff,pc-a,116444736000000000\n")
    ad_loaded = importers.load_import(ad_csv)
    check("detect_ad_filetime", ad_loaded["detected"] == "ad" and ad_loaded["devices"][0]["last_checkin"] == "1969-12-31T19:00:00-05:00")
    ad_headers = ["Name", "OperatingSystem", "ObjectGUID", "lastLogonTimestamp"]
    ad_profile, ad_mapping = importers.detect(ad_headers)
    def ad_row(stamp):
        return [{"Name": "PC-N", "OperatingSystem": "Windows", "ObjectGUID": "00112233-4455-6677-8899-aabbccddeeff", "lastLogonTimestamp": stamp}]
    check("ad_int_filetime", ad_profile == "ad" and importers.to_devices(ad_row(116444736000000000), ad_mapping, ad_profile)[0]["last_checkin"] == "1969-12-31T19:00:00-05:00")
    check("ad_float_filetime", importers.to_devices(ad_row(1.33e17), ad_mapping, ad_profile)[0]["last_checkin"] == filetime_to_iso(1.33e17) and "e17" not in importers.to_devices(ad_row(1.33e17), ad_mapping, ad_profile)[0]["last_checkin"].lower())
    sci = importers.to_devices(ad_row("1.33e17"), ad_mapping, ad_profile)[0]["last_checkin"]
    check("ad_sci_filetime", sci == filetime_to_iso(int(float("1.33e17"))) and "e17" not in sci.lower())
    jamf_csv = write_csv("jamf.csv", "Computer Name,Serial Number,Asset Tag,Model Identifier\nMac,JAMF9999,AT,MacBookPro\n")
    check("detect_jamf", importers.load_import(jamf_csv)["detected"] == "jamf")
    jamf_mark = write_csv("jamf-mark.csv", "Computer Name,Serial Number,Asset Tag,Last Inventory Update\nMac,JAMF1111,AT,2026-10-01\n")
    jamf_loaded = importers.load_import(jamf_mark)
    check("detect_jamf_markers", jamf_loaded["detected"] == "jamf" and jamf_loaded["devices"][0]["name"] == "Mac" and jamf_loaded["devices"][0]["managed_by"] == "Jamf")
    generic_csv = write_csv("generic.csv", "Hostname,Serial\nBox,GEN12345\n")
    check("detect_generic", importers.load_import(generic_csv)["detected"] == "generic" and importers.load_import(generic_csv)["devices"][0]["name"] == "Box")
    plain_csv = write_csv("plain.csv", "Name,Serial number,Asset tag\nLaptop,GENERIC9999,AT-9\n")
    plain = importers.load_import(plain_csv)
    check("generic_not_jamf", plain["detected"] == "generic" and plain["devices"][0]["name"] == "Laptop" and plain["devices"][0].get("managed_by") in (None, "") and "GENERIC9999" not in plain["devices"][0]["name"])
    for _headers, _label in (
        (["Computer name", "Serial number", "Model"], "computer_name"),
        (["Device name", "Serial number", "Model"], "device_name"),
        (["Hostname", "Serial number", "Managed"], "hostname_managed"),
    ):
        check("generic_sheet_" + _label, importers.detect(_headers)[0] == "generic")
    host_csv = write_csv("host-managed.csv", "Hostname,Serial number,Model,Managed\nhost-01,SERIAL12345,ThinkPad,Yes\n")
    host_loaded = importers.load_import(host_csv)
    host_dev = host_loaded["devices"][0]
    check("generic_hostname_not_jamf", host_loaded["detected"] == "generic" and host_dev["name"] == "host-01" and host_dev.get("managed_by") in (None, "") and host_dev["serial"] == "SERIAL12345" and host_dev["model"] == "ThinkPad")
    for _header in ("UDID", "FileVault 2 Status", "FileVault Status", "JSS Computer ID", "Last Inventory Update", "Model Identifier", "Jamf Pro ID", "Last Contact Time"):
        check("jamf_header_" + importers.norm_header(_header).replace(" ", "_"), importers.detect(["Serial Number", _header])[0] == "jamf")
    short_csv = write_csv("short-serial.csv", "Model,Serial number\nPi,AB12\n")
    short = ops.import_file(short_csv, name="Short serial", key=key)
    short_in = short["review"]["new"][0]["incoming"]
    short_view = json.dumps(short["review"])
    ops.commit_staged(short["review"]["id"], key=key)
    con = av.open_db(key)
    stored_short = con.execute("SELECT name FROM items WHERE serial='AB12'").fetchone()
    con.close()
    short_export = ops.export_inventory("csv", key=key)
    short_rows = list(csv.DictReader(open(os.path.join(VAULT, "exports", short_export["filename"]), encoding="utf-8")))
    short_names = [row.get("name") or "" for row in short_rows if row.get("serial") == "AB12"]
    check("short_serial_not_in_name", short_in["name"] == "Pi" and "AB12" not in short_in["name"] and "AB12" not in short_in["serial"] and "AB12" not in short_view and stored_short["name"] == "Pi" and "AB12" not in stored_short["name"] and short_names == ["Pi"] and all("AB12" not in name for name in short_names))
    try:
        importers.load_import(write_csv("old.xls", "name\n"))
        check("reject_xls", False)
    except Exception as exc:
        check("reject_xls", "xlsx" in str(exc))
    from openpyxl import Workbook
    book = Workbook(); sheet = book.active
    sheet.append(["Device name", "Serial number", "Managed by", "Primary user UPN"])
    sheet.append(["Sheet PC", "XLSX-SENTINEL-4455", "Intune", "b@contoso.test"])
    xlsx = os.path.join(INBOX, "intune.xlsx"); book.save(xlsx); book.close()
    check("detect_xlsx", importers.load_import(xlsx)["detected"] == "intune" and importers.load_import(xlsx)["devices"][0]["serial"] == "XLSX-SENTINEL-4455")
    book = Workbook(); sheet = book.active
    sheet.append(["Name", "OperatingSystem", "ObjectGUID", "lastLogonTimestamp"])
    sheet.append(["PC-Num", "Windows", "00112233-4455-6677-8899-aabbccddeeff", 116444736000000000])
    ad_xlsx = os.path.join(INBOX, "ad-times.xlsx"); book.save(ad_xlsx); book.close()
    ad_num = importers.load_import(ad_xlsx)
    stamp = ad_num["devices"][0]["last_checkin"]
    check("ad_xlsx_filetime", ad_num["detected"] == "ad" and stamp == filetime_to_iso(float(116444736000000000)) and "T" in stamp and "e+" not in stamp.lower())
    # Only temp files the importer can write. Skip this checkout, the install
    # tree, and the test's own inbox/vault so a copy of this file under /tmp
    # (it contains the sentinel) is not reported as a leftover spreadsheet.
    stray = []
    temp_root = tempfile.gettempdir()
    skip_roots = [INBOX, VAULT, REPO, INSTALL_ROOT, HERE, PKG]
    for dirpath, dirnames, files in os.walk(temp_root):
        # __pycache__ holds this file's compiled source (the sentinel literal).
        # The importer never writes bytecode; a leftover xlsx copy still matches.
        dirnames[:] = [d for d in dirnames if d != "__pycache__" and not any(_under(os.path.join(dirpath, d), root) for root in skip_roots)]
        if any(_under(dirpath, root) for root in skip_roots):
            continue
        for fn in files:
            if fn == "test_connectors.py" or fn.endswith(".pyc"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > 2000000:
                    continue
                if b"XLSX-SENTINEL-4455" in open(path, "rb").read():
                    stray.append(path)
            except OSError:
                pass
    check("xlsx_temp_shredded", stray == [])

    before = av.open_db(key)
    n_before = before.execute("SELECT count(*) FROM items").fetchone()[0]
    before.close()
    imported = ops.import_file(intune, key=key)
    check("import_stages", imported["detected"] == "intune" and imported["mapping"].get("serial") and imported["counts"]["new"] >= 1)
    con = av.open_db(key)
    check("import_not_committed", con.execute("SELECT count(*) FROM items").fetchone()[0] == n_before)
    con.close()
    done = ops.commit_staged(imported["review"]["id"], key=key)
    check("import_commit_new", done["counts"]["new"] >= 1)
    con = av.open_db(key)
    row = con.execute("SELECT source, managed_by, room FROM items WHERE serial='INTUNE1234'").fetchone()
    check("import_fields", row is not None and row["source"] == "CSV import" and row["managed_by"] == "Intune" and row["room"] is None)
    con.close()
    # soft match needs an explicit verify; a second import of a renamed row must not overwrite the room we set
    con = av.open_db(key)
    con.execute("UPDATE items SET room='Office', model='KeptModel', notes='' WHERE serial='INTUNE1234'")
    av.save_db(key, con); con.close()
    soft_csv = write_csv("soft.csv", "Hostname,Model,Serial\nPC-1,KeptModel,DIFFERENT999\n")
    # generic detection (Hostname) so it does not exact-match the Intune serial
    staged = ops.import_file(soft_csv, name="CSV import", key=key)
    check("soft_staged", staged["counts"]["soft"] == 1 and staged["review"]["soft"][0]["verified"] is False)
    # commit without verify leaves the serial alone
    ops.commit_staged(staged["review"]["id"], key=key)
    con = av.open_db(key)
    still = con.execute("SELECT serial, room, model FROM items WHERE name='PC-1'").fetchone()
    check("soft_not_applied", still["serial"] == "INTUNE1234" and still["room"] == "Office" and still["model"] == "KeptModel")
    con.close()
    staged = ops.import_file(soft_csv, name="CSV import", key=key)
    ops.commit_staged(staged["review"]["id"], verify=[0], key=key)
    con = av.open_db(key)
    changed = con.execute("SELECT serial, room FROM items WHERE name='PC-1'").fetchone()
    check("soft_verified_keeps_room", changed["serial"] == "DIFFERENT999" and changed["room"] == "Office")
    link = con.execute("SELECT external_id, not_seen_at FROM item_sources WHERE item_id=(SELECT id FROM items WHERE name='PC-1')").fetchone()
    check("link_recorded", link is not None and link["not_seen_at"] is None)
    con.close()

    # ---------- connector sync via ops, secrets stay out of the vault file
    os.environ["ASSETVAULT_GRAPH_SECRET"] = SECRET
    try:
        ops.connect_source("entra", {**ENTRA_CFG, "note": SECRET}, key=key)
        check("connect_rejects_secret", False)
    except ops.OpsError as exc:
        check("connect_rejects_secret", SECRET not in str(exc) and "secret" in str(exc))
    os.environ.pop("ASSETVAULT_GRAPH_SECRET", None)
    saved = ops.connect_source("entra", dict(ENTRA_CFG), preview=True, key=key)
    check("connect_auth_fail_saved", saved["ok"] is False and saved["health"] == "Auth failed")
    con = av.open_db(key)
    cfg_row = con.execute("SELECT config, health FROM sources WHERE id=?", (saved["source_id"],)).fetchone()
    check("config_has_no_secret", SECRET not in (cfg_row["config"] or "") and "tenant_id" in cfg_row["config"])
    con.execute("INSERT INTO item_sources(item_id, source_id, seen_at, external_id) VALUES((SELECT id FROM items WHERE name='kept-device'), ?, ?, 'keep-ext')", (saved["source_id"], av.now()))
    av.save_db(key, con); con.close()
    failed = ops.sync_source("entra", key=key)
    con = av.open_db(key)
    missed = con.execute("SELECT not_seen_at FROM item_sources WHERE source_id=?", (saved["source_id"],)).fetchone()[0]
    reviews = con.execute("SELECT count(*) FROM reviews WHERE source_id=? AND status='staged'", (saved["source_id"],)).fetchone()[0]
    con.close()
    check("failed_sync_no_not_seen", failed["ok"] is False and missed is None and reviews == 0)
    holder = {"mode": "ok"}
    real_build = connectors.build
    def fake_build(name, config, **kwargs):
        class Fake:
            notes = []
            def validate(self):
                return None
            def test(self):
                return {"health": "OK", "devices": [device(name="Preview PC", serial="PREV123456", source="REST")]}
            def pull(self, limit=None):
                if holder["mode"] == "boom":
                    raise ConnectorError("http 500", "Unreachable")
                return [device(name="Synced PC", serial="SYNC-SERIAL-7781", mac="11:22:33:44:55:66", model="Tower", external_id="ext-sync", source="REST", notes="from-source")]
        return Fake()
    connectors.build = fake_build
    try:
        linked = ops.connect_source("generic_rest", {"url": "https://devices.example/api", "auth": "none", "mapping": {"name": "hostname"}}, display_name="Lab REST", preview=True, key=key)
        check("connect_preview_masked", linked["ok"] and linked["preview"][0]["serial"].endswith("3456") and "PREV123456" not in json.dumps(linked))
        synced = ops.sync_source("Lab REST", key=key)
        check("sync_stages", synced["ok"] and synced["counts"]["new"] == 1 and "SYNC-SERIAL-7781" not in json.dumps(synced))
        blob = open(av.DB, "rb").read()
        audit = json.dumps(av.read_audit(key))
        check("sync_ciphertext", b"SYNC-SERIAL-7781" not in blob and b"SQLite format" not in blob and "SYNC-SERIAL-7781" not in audit and SECRET not in audit and AD_PW not in audit and JAMF_PW not in audit and REST_TOK not in audit and REST_PW not in audit)
        ops.commit_staged(synced["review"]["id"], key=key)
        con = av.open_db(key)
        got = con.execute("SELECT serial, notes FROM items WHERE name='Synced PC'").fetchone()
        check("sync_commit", got["serial"] == "SYNC-SERIAL-7781" and got["notes"] == "from-source")
        con.close()
        holder["mode"] = "boom"
        again = ops.sync_source("Lab REST", key=key)
        con = av.open_db(key)
        flag = con.execute("SELECT not_seen_at FROM item_sources WHERE external_id='ext-sync'").fetchone()[0]
        still = con.execute("SELECT count(*) FROM items WHERE name='Synced PC'").fetchone()[0]
        con.close()
        check("boom_does_not_flag", again["ok"] is False and flag is None and still == 1)
        ops.disconnect_source("Lab REST", key=key)
        con = av.open_db(key)
        src = con.execute("SELECT connector, config, health, detail FROM sources WHERE name='Lab REST'").fetchone()
        kept_item = con.execute("SELECT count(*) FROM items WHERE name='Synced PC'").fetchone()[0]
        kept_link = con.execute("SELECT count(*) FROM item_sources WHERE external_id='ext-sync'").fetchone()[0]
        con.close()
        check("disconnect_keeps_items", src["connector"] is None and src["config"] is None and src["detail"] == "disconnected" and kept_item == 1 and kept_link == 1)
    finally:
        connectors.build = real_build
    listed = ops.list_connectors(key=key)
    check("connectors_list", listed["version"] == "0.2.0" and {row["name"] for row in listed["available"]} == {"ad", "entra", "generic_rest", "jamf"}
          and any(row["name"] == "entra" and row["health"] == "Auth failed" for row in listed["sources"]) and all("config" not in row for row in listed["sources"]))

    # ---------- exports
    con = av.open_db(key)
    con.execute("UPDATE items SET name='=SUM(1)', purchase_price=10, replacement_value=20, condition='good', brand='Dell', model='X' WHERE name='Synced PC'")
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    bid = av.put_blob(key, png)
    con.execute("UPDATE items SET photo_refs=?, receipt_refs=? WHERE serial='SYNC-SERIAL-7781'", (json.dumps([{"id": bid, "name": "shot.png"}]), json.dumps([{"id": bid, "name": "receipt-secret.html"}])))
    con.execute("UPDATE sources SET name='=cmd' WHERE name='Lab REST'")
    av.save_db(key, con); con.close()
    csv_out = ops.export_inventory("csv", key=key)
    csv_bytes = open(os.path.join(VAULT, "exports", csv_out["filename"]), "rb").read()
    check("csv_export", csv_out["ok"] and b"SYNC-SERIAL-7781" in csv_bytes and b"'=SUM(1)" in csv_bytes and b"'=cmd" in csv_bytes and oct(os.stat(os.path.join(VAULT, "exports", csv_out["filename"])).st_mode & 0o777) == "0o600")
    pdf_out = ops.export_inventory("pdf", key=key)
    pdf_bytes = open(os.path.join(VAULT, "exports", pdf_out["filename"]), "rb").read()
    red_out = ops.export_inventory("pdf-redacted", key=key)
    red_bytes = open(os.path.join(VAULT, "exports", red_out["filename"]), "rb").read()
    check("pdf_export", pdf_bytes.startswith(b"%PDF") and b"SYNC-SERIAL-7781" in pdf_bytes and b"receipt-secret.html" in pdf_bytes and b"/Image" in pdf_bytes)
    check("pdf_redacted", b"SYNC-SERIAL-7781" not in red_bytes and b"receipt-secret.html" not in red_bytes and b"7781" in red_bytes)
    check("export_mode", oct(os.stat(os.path.join(VAULT, "exports", pdf_out["filename"])).st_mode & 0o777) == "0o600")
    phrase = os.environ["ASSETVAULT_PASSPHRASE"].encode()
    leaks = []
    for dirpath, _, files in os.walk(VAULT):
        for fn in files:
            path = os.path.join(dirpath, fn)
            data = open(path, "rb").read()
            if phrase in data or SECRET.encode() in data or AD_PW.encode() in data or JAMF_PW.encode() in data or REST_TOK.encode() in data or REST_PW.encode() in data:
                leaks.append(path)
            if b"SQLite format" in data:
                leaks.append("sqlite:" + path)
            if dirpath.endswith("/exports"):
                continue
            if b"SYNC-SERIAL-7781" in data or b"INTUNE1234" in data or b"KEEP1234" in data:
                leaks.append("plain:" + path)
    check("no_secrets_or_inventory_plaintext", leaks == [])

    # ---------- CLI
    # A checkout can run `python -m assetvault.connect` with the repo root on
    # PYTHONPATH. An installed tree has connect.py and no assetvault package.
    if REPO:
        cli_base = [PY, "-m", "assetvault.connect"]
        cli_env = dict(os.environ, PYTHONPATH=REPO)
        cli_cwd = REPO
    else:
        cli_base = [PY, os.path.join(BIN, "connect.py")]
        cli_env = dict(os.environ)
        cli_cwd = BIN
    proc = subprocess.run(cli_base + ["connectors"], env=cli_env, cwd=cli_cwd, capture_output=True, text=True, timeout=60)
    check("cli_connectors", proc.returncode == 0 and '"version": "0.2.0"' in proc.stdout and "Auth failed" in proc.stdout and SECRET not in proc.stdout and SECRET not in proc.stderr)
    proc = subprocess.run([PY, os.path.join(BIN, "connect.py"), "entra", "--config", json.dumps({**ENTRA_CFG, "note": SECRET}), "--test"], env=dict(cli_env, ASSETVAULT_GRAPH_SECRET=SECRET), cwd=cli_cwd, capture_output=True, text=True, timeout=60)
    check("cli_rejects_secret", proc.returncode == 1 and SECRET not in proc.stdout and SECRET not in proc.stderr and "secret" in proc.stdout)
    proc = subprocess.run(cli_base + ["sync", "missing-source"], env=cli_env, cwd=cli_cwd, capture_output=True, text=True, timeout=60)
    check("cli_unknown", proc.returncode == 1 and "unknown source" in proc.stdout and "Traceback" not in proc.stderr)

    # ---------- install.sh --update keeps a vault byte-for-byte
    # Skipped from an installed root: install.sh is not copied there.
    if not REPO:
        check("install_update", "skipped")
        check("install_mentions_deps", "skipped")
    else:
        inst = os.path.join(TMP, "installroot")
        os.makedirs(os.path.join(inst, "bin"))
        open(os.path.join(inst, "bin/avcore.py"), "w").write("# old\n")
        marker = b"NOT-A-REAL-VAULT-BUT-KEEP-ME-" + secrets.token_bytes(8)
        for rel in ("vault.db.enc", "vault.meta.json", "audit.log.enc", "blobs/keep.enc", "exports/keep.csv", "connectors/keep.txt"):
            path = os.path.join(inst, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "wb").write(marker)
        watched = ("vault.db.enc", "vault.meta.json", "audit.log.enc", "blobs/keep.enc", "exports/keep.csv", "connectors/keep.txt")
        before_bytes = {rel: open(os.path.join(inst, rel), "rb").read() for rel in watched}
        proc = subprocess.run(["bash", os.path.join(REPO, "install.sh"), "--update"], env=dict(os.environ, ASSETVAULT_ROOT=inst), cwd=REPO, capture_output=True, text=True, timeout=60)
        after = {rel: open(os.path.join(inst, rel), "rb").read() for rel in watched}
        check("install_update", proc.returncode == 0 and after == before_bytes and os.path.isfile(os.path.join(inst, "bin/connectors/entra.py")) and open(os.path.join(inst, "VERSION")).read().strip() == "0.2.0")
        check("install_mentions_deps", "requirements.txt" in proc.stderr)
finally:
    shutil.rmtree(TMP, ignore_errors=True)
print(json.dumps(R, indent=0))
_passed = sum(1 for v in R.values() if v is True)
_skipped = [name for name, v in R.items() if v == "skipped"]
print("FAILED:", fails if fails else "none", "(%d/%d passed%s)" % (_passed, len(R) - len(_skipped), (", skipped: " + ", ".join(_skipped)) if _skipped else ""))
sys.exit(1 if fails else 0)
