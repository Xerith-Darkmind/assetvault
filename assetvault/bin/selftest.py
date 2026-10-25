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
raw = open(av.DB,"rb").read(); r["db_not_plaintext"] = b"SQLite format" not in raw and b"Office" not in raw
os.environ["ASSETVAULT_PASSPHRASE"] = "wrong-" + secrets.token_hex(8)
try: av.unlock(); r["wrong_pass_rejected"] = False
except av.UnlockError: r["wrong_pass_rejected"] = True
os.remove(os.path.join(av.ROOT, "audit.failed_unlocks"))  # test artifact, not a real failed unlock
r["audit_readable"] = av.read_audit(key)[0]["action"] == "setup"
print(json.dumps(r))
