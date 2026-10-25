"""AssetVault core: AES-256-GCM encrypted SQLite store, blobs, audit log.
Key from env ASSETVAULT_PASSPHRASE via Argon2id (fallback scrypt). Plaintext DB lives only in memory."""
import os, sys, json, sqlite3, secrets, base64, datetime
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

def audit(key, action, item_id=None, detail=None):
    line = json.dumps({"ts": now(), "action": action, "item_id": item_id, "detail": detail}).encode()
    rec = base64.b64encode(enc(key, line, b"audit")).decode()
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


# ---------------------------------------------------------------- schema v2 migration
SCHEMA_VERSION = 2
SOURCES_ENUM = ("Manual", "CSV import", "Entra-Intune", "AD", "Jamf")
_V2_COLUMNS = [
    ("owner", "TEXT"), ("mac", "TEXT"), ("os", "TEXT"),
    ("source", "TEXT DEFAULT 'Manual' CHECK(source IN ('Manual','CSV import','Entra-Intune','AD','Jamf') OR source IS NULL)"),
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

def schema_version(con):
    r = con.execute("SELECT v FROM config WHERE k='schema_version'").fetchone()
    return json.loads(r[0]) if r else 1

def migrate(key):
    """Idempotent v1 -> v2 migration. Legacy columns backup_status / rpo_target_days are kept untouched.
    Returns the list of changes made (empty if already current). Audits 'migrate' only when something changed."""
    con = open_db(key)
    changes = []
    cols = {r[1] for r in con.execute("PRAGMA table_info(items)")}
    for name, decl in _V2_COLUMNS:
        if name not in cols:
            con.execute(f"ALTER TABLE items ADD COLUMN {name} {decl}")
            changes.append("items." + name)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t, ddl in _V2_TABLES.items():
        if t not in tables:
            con.execute(ddl); changes.append("table " + t)
    con.execute("CREATE INDEX IF NOT EXISTS ix_bh_item ON backup_history(item_id, date)")
    if schema_version(con) != SCHEMA_VERSION:
        con.execute("INSERT OR REPLACE INTO config(k,v) VALUES('schema_version',?)", (json.dumps(SCHEMA_VERSION),))
        changes.append(f"config.schema_version={SCHEMA_VERSION}")
    if changes:
        save_db(key, con)
        audit(key, "migrate", detail={"to_version": SCHEMA_VERSION, "changes": changes})
    con.close()
    return changes
