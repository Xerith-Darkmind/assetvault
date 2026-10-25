import sys, os, json, secrets
sys.path.insert(0, os.path.dirname(__file__))
import avcore as av
rooms = ["Office","Living Room","Bedroom","Kitchen","Garage","Storage"]
cats = ["Computers","Networking","Peripherals","Streaming/AV","Gaming","Phones/Tablets","Storage/Backup","Appliances","Furniture","Tools","Other"]
key = av.init(rooms, cats, 500)
r = {}
k2 = av.unlock(); r["unlock"] = k2 == key
con = av.open_db(k2)
r["config"] = json.loads(con.execute("select v from config where k='rooms'").fetchone()[0]) == rooms
con.execute("insert into items(name) values('__selftest__')"); av.save_db(k2, con)
con = av.open_db(k2); r["db_roundtrip"] = con.execute("select count(*) from items where name='__selftest__'").fetchone()[0] == 1
con.execute("delete from items where name='__selftest__'"); con.execute("delete from sqlite_sequence"); av.save_db(k2, con)
data = secrets.token_bytes(4096); bid = av.put_blob(k2, data); r["blob_roundtrip"] = av.get_blob(k2, bid) == data
os.remove(os.path.join(av.BLOBS, bid + ".enc"))
av.migrate(key)
con = av.open_db(key)
r["schema_v3"] = av.schema_version(con) == 3
r["reviews_table"] = con.execute("select 1 from sqlite_master where type='table' and name='reviews'").fetchone() is not None
con.close()
secret = "graphsecret-" + secrets.token_hex(8)
os.environ["ASSETVAULT_GRAPH_SECRET"] = secret
av.audit(key, "selftest_scrub", detail={"note": secret, "actor_should_not_matter": secret})
aud = json.dumps(av.read_audit(key))
r["secret_not_in_audit"] = secret not in aud and "[redacted]" in aud
r["secret_not_in_dbfile"] = secret.encode() not in open(av.DB, "rb").read() and secret.encode() not in open(av.AUDIT, "rb").read()
del os.environ["ASSETVAULT_GRAPH_SECRET"]
raw = open(av.DB,"rb").read(); r["db_not_plaintext"] = b"SQLite format" not in raw and b"Office" not in raw
os.environ["ASSETVAULT_PASSPHRASE"] = "wrong-" + secrets.token_hex(8)
try: av.unlock(); r["wrong_pass_rejected"] = False
except av.UnlockError: r["wrong_pass_rejected"] = True
os.remove(os.path.join(av.ROOT, "audit.failed_unlocks"))  # test artifact, not a real failed unlock
r["audit_readable"] = av.read_audit(key)[0]["action"] == "setup"
print(json.dumps(r))
