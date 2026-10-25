"""AssetVault core: AES-256-GCM encrypted SQLite store, blobs, audit log.
Key from env ASSETVAULT_PASSPHRASE via Argon2id (fallback scrypt). Plaintext DB lives only in memory."""
import os, sys, json, sqlite3, secrets, base64, datetime, re, tempfile
from contextlib import contextmanager
from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.environ.get("ASSETVAULT_ROOT", "/workspace/assetvault")
META = os.path.join(ROOT, "vault.meta.json")   # KDF params + salt + key-check only (no inventory data)
DB = os.path.join(ROOT, "vault.db.enc")
AUDIT = os.path.join(ROOT, "audit.log.enc")
BLOBS = os.path.join(ROOT, "blobs")
MAGIC = b"AVLT1"
KCV_PLAINTEXT = b"assetvault-key-check-v1"
TZ = ZoneInfo("America/New_York")

class UnlockError(Exception): pass

def _pass():
    p = os.environ.get("ASSETVAULT_PASSPHRASE")
    if not p: raise UnlockError("passphrase missing")
    return p.encode()

def _derive(meta):
    salt = base64.b64decode(meta["salt"])
    if meta["kdf"] == "argon2id":
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(_pass(), salt, time_cost=meta["t"], memory_cost=meta["m"], parallelism=meta["p"], hash_len=32, type=Type.ID)
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=meta["n"], r=8, p=1).derive(_pass())

def now(): return datetime.datetime.now(TZ).isoformat(timespec="seconds")

def enc(key, data, aad):
    salt = base64.b64decode(load_meta()["salt"])
    nonce = secrets.token_bytes(12)
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, data, aad)

def dec(key, blob, aad):
    if blob[:5] != MAGIC: raise ValueError("bad header")
    nonce = blob[21:33]
    return AESGCM(key).decrypt(nonce, blob[33:], aad)

def load_meta():
    with open(META) as f: return json.load(f)

def _atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o600); os.replace(tmp, path)

def unlock():
    meta = load_meta()
    key = _derive(meta)
    try:
        dec(key, base64.b64decode(meta["kcv"]), b"kcv")
    except Exception:
        _audit_fail()
        raise UnlockError("wrong passphrase")
    return key

def _audit_fail():
    # failed unlock is logged without the key: record as plaintext-free marker line encrypted is impossible; store a minimal non-sensitive line
    with open(os.path.join(ROOT, "audit.failed_unlocks"), "a") as f:
        f.write(now() + " failed_unlock\n")

# Env vars whose values must never land in audit lines, exceptions, or logs.
SECRET_ENV_NAMES = (
    "ASSETVAULT_PASSPHRASE",
    "ASSETVAULT_GRAPH_SECRET",
    "ASSETVAULT_AD_PASSWORD",
    "ASSETVAULT_JAMF_SECRET",
    "ASSETVAULT_REST_TOKEN",
    "ASSETVAULT_REST_PASSWORD",
)

def secret_values(env=None):
    env = os.environ if env is None else env
    vals = []
    for name in SECRET_ENV_NAMES:
        v = env.get(name)
        if v and len(v) >= 4 and v not in vals:
            vals.append(v)
    return vals

def scrub(text, secrets=None):
    """Replace known secret values, including JSON-escaped forms. None stays None."""
    if text is None:
        return None
    out = text if isinstance(text, str) else str(text)
    for s in (secret_values() if secrets is None else secrets):
        if not s or len(s) < 4:
            continue
        out = out.replace(s, "[redacted]")
        escaped = json.dumps(s)[1:-1]
        if escaped and escaped != s:
            out = out.replace(escaped, "[redacted]")
    return out

def _scrub_obj(obj, secrets):
    if isinstance(obj, str):
        return scrub(obj, secrets)
    if isinstance(obj, dict):
        return {str(k): _scrub_obj(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_scrub_obj(v, secrets) for v in obj]
    return obj

def audit(key, action, item_id=None, detail=None, actor=None):
    secrets = secret_values()
    actor = scrub(actor or os.environ.get("ASSETVAULT_ACTOR") or "owner", secrets)
    detail = _scrub_obj(detail, secrets)
    line = scrub(json.dumps({"ts": now(), "actor": actor, "action": action, "item_id": item_id, "detail": detail}, default=str), secrets)
    rec = base64.b64encode(enc(key, line.encode(), b"audit")).decode()
    with open(AUDIT, "a") as f:
        f.write(rec + "\n"); f.flush(); os.fsync(f.fileno())
    os.chmod(AUDIT, 0o600)

def read_audit(key):
    out = []
    if os.path.exists(AUDIT):
        for l in open(AUDIT):
            l = l.strip()
            if l: out.append(json.loads(dec(key, base64.b64decode(l), b"audit")))
    fu = os.path.join(ROOT, "audit.failed_unlocks")
    if os.path.exists(fu):
        for l in open(fu):
            ts, a = l.strip().split(" ", 1); out.append({"ts": ts, "action": a, "item_id": None, "detail": None})
    return sorted(out, key=lambda r: r["ts"])

def shred_file(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    try:
        with open(path, "r+b") as f:
            left = max(size, 1)
            while left:
                n = min(1024 * 1024, left)
                f.write(secrets.token_bytes(n))
                left -= n
            f.flush(); os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass

def shred_tree(path):
    if not path or not os.path.exists(path):
        return
    if not os.path.isdir(path):
        shred_file(path); return
    for root, dirs, files in os.walk(path, topdown=False):
        for fn in files:
            shred_file(os.path.join(root, fn))
        for dn in dirs:
            try: os.rmdir(os.path.join(root, dn))
            except OSError: pass
    try: os.rmdir(path)
    except OSError: pass

@contextmanager
def private_temp():
    """0700 scratch dir. Anything a library spills here is shredded on the way out."""
    d = tempfile.mkdtemp(prefix="av-")
    os.chmod(d, 0o700)
    prev = tempfile.tempdir
    tempfile.tempdir = d
    try:
        yield d
    finally:
        tempfile.tempdir = prev
        shred_tree(d)

def write_export(filename, data):
    """Write an export under ROOT/exports only, mode 0600. Caller asked for this plaintext file."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("export data must be bytes")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", filename or ""):
        raise ValueError("bad export name")
    directory = os.path.join(ROOT, "exports")
    os.makedirs(directory, exist_ok=True)
    os.chmod(directory, 0o700)
    dest = os.path.join(directory, filename)
    if os.path.dirname(os.path.realpath(dest)) != os.path.realpath(directory):
        raise ValueError("export path escaped")
    _atomic_write(dest, bytes(data))
    os.chmod(dest, 0o600)
    return dest

SCHEMA = """
CREATE TABLE config(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE items(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT, room TEXT, brand TEXT, model TEXT, serial TEXT,
 purchase_date TEXT, purchase_price REAL, current_value REAL, replacement_value REAL, condition TEXT,
 warranty_expiry TEXT, warranty_provider TEXT, backup_status TEXT CHECK(backup_status IN ('none','partial','current') OR backup_status IS NULL),
 backup_method TEXT, last_backup_date TEXT, rpo_target_days INTEGER, rpo_notes TEXT,
 photo_refs TEXT DEFAULT '[]', receipt_refs TEXT DEFAULT '[]', notes TEXT, created_at TEXT, updated_at TEXT);
"""

def open_db(key):
    con = sqlite3.connect(":memory:"); con.row_factory = sqlite3.Row
    with open(DB, "rb") as f: con.deserialize(dec(key, f.read(), b"db"))
    return con

def save_db(key, con):
    con.commit()
    _atomic_write(DB, enc(key, con.serialize(), b"db"))

def put_blob(key, data):
    bid = secrets.token_hex(16)
    _atomic_write(os.path.join(BLOBS, bid + ".enc"), enc(key, data, b"blob:" + bid.encode()))
    assert get_blob(key, bid) == data
    return bid

def get_blob(key, bid):
    with open(os.path.join(BLOBS, bid + ".enc"), "rb") as f: return dec(key, f.read(), b"blob:" + bid.encode())

def init(rooms, categories, threshold):
    if os.path.exists(META) or os.path.exists(DB): raise SystemExit("vault already initialized")
    os.makedirs(BLOBS, exist_ok=True)
    meta = {"version": 1, "kdf": "argon2id", "t": 3, "m": 65536, "p": 4, "salt": base64.b64encode(secrets.token_bytes(16)).decode()}
    try: import argon2  # noqa
    except ImportError: meta = {"version": 1, "kdf": "scrypt", "n": 2**15, "salt": meta["salt"]}
    with open(META, "w") as f: json.dump(meta, f)
    key = _derive(meta)
    meta["kcv"] = base64.b64encode(enc(key, KCV_PLAINTEXT, b"kcv")).decode()
    _atomic_write(META, json.dumps(meta).encode())
    con = sqlite3.connect(":memory:"); con.executescript(SCHEMA)
    for k, v in (("rooms", rooms), ("categories", categories), ("receipt_photo_threshold", threshold)):
        con.execute("INSERT INTO config VALUES(?,?)", (k, json.dumps(v)))
    save_db(key, con)
    audit(key, "setup", detail="vault initialized")
    return key


# ---------------------------------------------------------------- schema migration
# v2 is what 0.1.0 wrote. v3 adds connector config, staged reviews, and loosens items.source
# so a later connector can record its own kind. 0.1.0 vaults open and upgrade in place.
SCHEMA_VERSION = 3
SOURCES_ENUM = ("Manual", "CSV import", "Entra-Intune", "AD", "Jamf", "REST")
_V2_COLUMNS = [
    ("owner", "TEXT"), ("mac", "TEXT"), ("os", "TEXT"),
    ("source", "TEXT DEFAULT 'Manual'"),
    ("external_ids", "TEXT DEFAULT '{}'"), ("last_checkin", "TEXT"), ("encryption_status", "TEXT"),
    ("rpo_target_hours", "INTEGER"), ("verified", "INTEGER DEFAULT 0"), ("paused", "INTEGER DEFAULT 0"),
]
_V2_TABLES = {
    "backup_history": """CREATE TABLE IF NOT EXISTS backup_history(
 id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER NOT NULL, date TEXT NOT NULL,
 result TEXT NOT NULL CHECK(result IN ('success','partial','failed','manual')), note TEXT, created_at TEXT)""",
    "sources": """CREATE TABLE IF NOT EXISTS sources(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, kind TEXT, last_sync TEXT,
 added INTEGER DEFAULT 0, updated INTEGER DEFAULT 0, skipped INTEGER DEFAULT 0, health TEXT, detail TEXT)""",
    "item_sources": """CREATE TABLE IF NOT EXISTS item_sources(
 item_id INTEGER NOT NULL, source_id INTEGER NOT NULL, seen_at TEXT, PRIMARY KEY(item_id, source_id))""",
}
_V3_ITEM_COLUMNS = [("asset_tag", "TEXT"), ("os_version", "TEXT"), ("managed_by", "TEXT")]
_V3_SOURCE_COLUMNS = [("config", "TEXT"), ("connector", "TEXT"), ("not_seen", "INTEGER DEFAULT 0")]
_V3_LINK_COLUMNS = [("external_id", "TEXT"), ("not_seen_at", "TEXT")]

def schema_version(con):
    r = con.execute("SELECT v FROM config WHERE k='schema_version'").fetchone()
    return json.loads(r[0]) if r else 1

def _colnames(con, table):
    return {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}

def _tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}

def _add_columns(con, table, columns, changes):
    have = _colnames(con, table)
    for name, decl in columns:
        if name not in have:
            con.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, decl))
            changes.append(table + "." + name)

def _migrate_v2(con, changes):
    cols = _colnames(con, "items")
    for name, decl in _V2_COLUMNS:
        if name not in cols:
            con.execute("ALTER TABLE items ADD COLUMN %s %s" % (name, decl))
            changes.append("items." + name)
    tables = _tables(con)
    for t, ddl in _V2_TABLES.items():
        if t not in tables:
            con.execute(ddl); changes.append("table " + t)
    idx = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    if "ix_bh_item" not in idx:
        con.execute("CREATE INDEX ix_bh_item ON backup_history(item_id, date)")
        changes.append("index ix_bh_item")

def _source_check_blocks(con):
    """True when a 0.1.0 CHECK still rejects source kinds added after that release."""
    con.execute("SAVEPOINT av_src_check")
    try:
        con.execute("INSERT INTO items(name, source) VALUES('__av_check_rest__', 'REST')")
        return False
    except sqlite3.IntegrityError:
        return True
    finally:
        con.execute("ROLLBACK TO av_src_check")
        con.execute("RELEASE av_src_check")

def _coldef(row):
    name, typ, notnull, dflt, pk = row[1], row[2], row[3], row[4], row[5]
    if name == "id":
        return "id INTEGER PRIMARY KEY AUTOINCREMENT"
    if name == "source":
        return "source TEXT DEFAULT 'Manual'"
    if name == "backup_status":
        return "backup_status TEXT CHECK(backup_status IN ('none','partial','current') OR backup_status IS NULL)"
    parts = [name, typ or "TEXT"]
    if pk:
        parts.append("PRIMARY KEY")
    if notnull:
        parts.append("NOT NULL")
    if dflt is not None:
        parts.append("DEFAULT " + dflt)
    return " ".join(parts)

def _relax_source_check(con, changes):
    if not _source_check_blocks(con):
        return
    info = list(con.execute("PRAGMA table_info(items)"))
    defs = ", ".join(_coldef(r) for r in info)
    names = ", ".join(r[1] for r in info)
    con.execute("ALTER TABLE items RENAME TO items__old")
    con.execute("CREATE TABLE items (" + defs + ")")
    con.execute("INSERT INTO items(" + names + ") SELECT " + names + " FROM items__old")
    con.execute("DROP TABLE items__old")
    mx = con.execute("SELECT COALESCE(MAX(id), 0) FROM items").fetchone()[0]
    try:
        con.execute("UPDATE sqlite_sequence SET name='items' WHERE name='items__old'")
        if con.execute("SELECT 1 FROM sqlite_sequence WHERE name='items'").fetchone():
            con.execute("UPDATE sqlite_sequence SET seq=? WHERE name='items'", (mx,))
        else:
            con.execute("INSERT INTO sqlite_sequence(name, seq) VALUES('items', ?)", (mx,))
    except sqlite3.OperationalError:
        pass
    changes.append("items.source_check_relaxed")

def _migrate_v3(con, changes):
    _add_columns(con, "items", _V3_ITEM_COLUMNS, changes)
    if "sources" in _tables(con):
        _add_columns(con, "sources", _V3_SOURCE_COLUMNS, changes)
    if "item_sources" in _tables(con):
        _add_columns(con, "item_sources", _V3_LINK_COLUMNS, changes)
    if "reviews" not in _tables(con):
        con.execute("""CREATE TABLE reviews(
 id INTEGER PRIMARY KEY AUTOINCREMENT, source_id INTEGER, created_at TEXT,
 kind TEXT, payload TEXT, status TEXT DEFAULT 'staged')""")
        changes.append("table reviews")
    _relax_source_check(con, changes)

def migrate(key):
    """Idempotent upgrade toward SCHEMA_VERSION. 0.1.0 (v2) vaults upgrade in place.
    Legacy columns backup_status / rpo_target_days are kept. Audits only when something changed."""
    con = open_db(key)
    try:
        changes = []
        _migrate_v2(con, changes)
        _migrate_v3(con, changes)
        if schema_version(con) != SCHEMA_VERSION:
            con.execute("INSERT OR REPLACE INTO config(k,v) VALUES('schema_version',?)", (json.dumps(SCHEMA_VERSION),))
            changes.append("config.schema_version=%s" % SCHEMA_VERSION)
        if changes:
            save_db(key, con)
            audit(key, "migrate", detail={"to_version": SCHEMA_VERSION, "changes": changes})
        return changes
    finally:
        con.close()
