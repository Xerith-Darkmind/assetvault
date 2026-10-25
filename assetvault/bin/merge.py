"""Staged merge review shared by imports and syncs.

Match order: serial, then MAC, then external id for this source, then a soft
name+model match. Soft matches are stored unverified and are not applied
unless someone marks them. A sync never deletes a local item; devices that
belong to this source and were not matched are flagged not seen.
"""
import json

import avcore as av
from connectors.base import public_device, redact_serial_text
from errors import MergeError

_COLMAP = {
    "name": "name", "serial": "serial", "mac": "mac", "asset_tag": "asset_tag",
    "brand": "brand", "model": "model", "os": "os", "os_version": "os_version",
    "assigned_user": "owner", "last_checkin": "last_checkin",
    "encryption_status": "encryption_status", "managed_by": "managed_by",
}


def norm_serial(value):
    if value is None:
        return None
    text = str(value).strip().casefold()
    return text or None


def norm_mac(value):
    import re
    hexes = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(hexes) != 12:
        return None
    hexes = hexes.lower()
    if set(hexes) == {"0"}:
        return None
    return hexes


def norm_ext(value):
    if value is None:
        return None
    text = str(value).strip().casefold()
    return text or None


def norm_soft(value):
    text = " ".join(str(value or "").split()).casefold()
    return text or None


def _unique(pairs):
    found, bad = {}, set()
    for key, iid in pairs:
        if not key or key in bad:
            continue
        if key in found and found[key] != iid:
            bad.add(key)
            found.pop(key, None)
        else:
            found[key] = iid
    return found, bad


def _eids(item):
    raw = item.get("external_ids") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def plan_merge(local_items, incoming, source_id, now):
    sid = str(source_id)
    serial_pairs, mac_pairs, ext_pairs = [], [], []
    for item in local_items:
        iid = item["id"]
        if norm_serial(item.get("serial")):
            serial_pairs.append((norm_serial(item.get("serial")), iid))
        if norm_mac(item.get("mac")):
            mac_pairs.append((norm_mac(item.get("mac")), iid))
        ext = _eids(item).get(sid)
        if norm_ext(ext):
            ext_pairs.append((norm_ext(ext), iid))
        for link in item.get("links") or []:
            if link.get("source_id") == source_id and norm_ext(link.get("external_id")):
                ext_pairs.append((norm_ext(link.get("external_id")), iid))
    serial_ix, serial_bad = _unique(serial_pairs)
    mac_ix, mac_bad = _unique(mac_pairs)
    ext_ix, ext_bad = _unique(ext_pairs)
    used, seen, exact, skipped, pending = set(), set(), [], [], []
    incoming = list(incoming or [])
    for idx, inc in enumerate(incoming):
        taken = hit_used = ambiguous = False
        for kind, ix, bad, pairs, val in (
            ("serial", serial_ix, serial_bad, serial_pairs, norm_serial(inc.get("serial"))),
            ("mac", mac_ix, mac_bad, mac_pairs, norm_mac(inc.get("mac"))),
            ("external_id", ext_ix, ext_bad, ext_pairs, norm_ext(inc.get("external_id"))),
        ):
            if not val:
                continue
            if val in bad:
                ambiguous = True
                for key, iid in pairs:
                    if key == val:
                        seen.add(iid)
                break
            if val not in ix:
                continue
            iid = ix[val]
            if iid in used:
                hit_used = True
                # This serial or MAC already identified a row used earlier in the plan.
                # Falling through to a weaker key would update a different item.
                if kind in ("serial", "mac"):
                    break
                continue
            exact.append({"local_id": iid, "match_on": kind, "incoming": inc})
            used.add(iid)
            seen.add(iid)
            taken = True
            break
        if taken:
            continue
        if ambiguous:
            skipped.append({"reason": "ambiguous", "incoming": inc})
            continue
        if hit_used:
            skipped.append({"reason": "duplicate in source", "incoming": inc})
            continue
        pending.append(idx)
    soft_pairs = []
    for item in local_items:
        if item["id"] in used:
            continue
        key = (norm_soft(item.get("name")), norm_soft(item.get("model")))
        if key[0] and key[1]:
            soft_pairs.append((key, item["id"]))
    soft_ix, soft_bad = _unique(soft_pairs)
    soft, new = [], []
    for idx in pending:
        inc = incoming[idx]
        key = (norm_soft(inc.get("name")), norm_soft(inc.get("model")))
        if key[0] and key[1] and key in soft_bad:
            skipped.append({"reason": "ambiguous", "incoming": inc})
            for skey, iid in soft_pairs:
                if skey == key:
                    seen.add(iid)
            continue
        iid = soft_ix.get(key) if key[0] and key[1] else None
        if iid and iid not in used:
            soft.append({"local_id": iid, "match_on": "name+model", "verified": False, "incoming": inc})
            used.add(iid)
            seen.add(iid)
        else:
            new.append({"incoming": inc})
    not_seen = []
    for item in local_items:
        linked = any(link.get("source_id") == source_id for link in (item.get("links") or []))
        if linked and item["id"] not in seen:
            not_seen.append({"local_id": item["id"], "not_seen_at": now})
    return {"exact": exact, "soft": soft, "new": new, "not_seen": not_seen, "skipped": skipped}


def load_items(con):
    links = {}
    for row in con.execute("SELECT item_id, source_id, external_id, seen_at, not_seen_at FROM item_sources"):
        links.setdefault(row["item_id"], []).append({
            "source_id": row["source_id"], "external_id": row["external_id"],
            "seen_at": row["seen_at"], "not_seen_at": row["not_seen_at"],
        })
    items = []
    for row in con.execute("SELECT * FROM items"):
        item = dict(row)
        item["links"] = links.get(item["id"], [])
        items.append(item)
    return items


def stage(con, source_id, incoming, kind, detected=None, mapping=None):
    plan = plan_merge(load_items(con), incoming, source_id, av.now())
    plan["detected"] = detected
    plan["mapping"] = mapping
    plan["kind"] = kind
    con.execute("DELETE FROM reviews WHERE source_id=? AND status='staged'", (source_id,))
    cur = con.execute(
        "INSERT INTO reviews(source_id, created_at, kind, payload, status) VALUES(?,?,?,?, 'staged')",
        (source_id, av.now(), kind, json.dumps(plan)),
    )
    return cur.lastrowid, plan


def _row(con, review_id):
    row = con.execute("SELECT * FROM reviews WHERE id=? AND status='staged'", (review_id,)).fetchone()
    if not row:
        raise MergeError("no such review")
    return row


def set_verified(con, review_id, index, verified=None):
    row = _row(con, review_id)
    payload = json.loads(row["payload"])
    soft = payload.get("soft") or []
    if index < 0 or index >= len(soft):
        raise MergeError("soft match index out of range")
    soft[index]["verified"] = (not bool(soft[index].get("verified"))) if verified is None else bool(verified)
    payload["soft"] = soft
    con.execute("UPDATE reviews SET payload=? WHERE id=?", (json.dumps(payload), review_id))
    return bool(soft[index]["verified"])


def _link(con, item_id, source_id, external_id, now):
    con.execute(
        """INSERT INTO item_sources(item_id, source_id, seen_at, external_id, not_seen_at)
           VALUES(?,?,?,?,NULL)
           ON CONFLICT(item_id, source_id) DO UPDATE SET
             seen_at=excluded.seen_at,
             external_id=COALESCE(excluded.external_id, item_sources.external_id),
             not_seen_at=NULL""",
        (item_id, source_id, now, None if external_id in (None, "") else str(external_id)),
    )


def _name_is_fallback(incoming):
    """True when the incoming name was generated, not supplied by the source."""
    if incoming.get("name_fallback"):
        return True
    name = str(incoming.get("name") or "").strip()
    if name.casefold() in ("", "unnamed device"):
        return True
    serial = str(incoming.get("serial") or "").strip()
    if serial and name.casefold() == serial.casefold():
        return True
    ext = str(incoming.get("external_id") or "").strip()
    if ext and name.casefold() == ext.casefold():
        return True
    return False


def _apply(con, local_id, incoming, source, now):
    row = con.execute("SELECT * FROM items WHERE id=?", (local_id,)).fetchone()
    if not row:
        return False
    current = dict(row)
    updates = {}
    for src, dst in _COLMAP.items():
        val = incoming.get(src)
        if val not in (None, ""):
            if dst == "name" and _name_is_fallback(incoming) and (current.get("name") or "").strip():
                continue
            updates[dst] = val
    if incoming.get("notes") and not (current.get("notes") or "").strip():
        updates["notes"] = incoming.get("notes")
    if incoming.get("external_id"):
        try:
            eids = json.loads(current.get("external_ids") or "{}")
        except (TypeError, ValueError):
            eids = {}
        if not isinstance(eids, dict):
            eids = {}
        eids[str(source["id"])] = str(incoming["external_id"])
        updates["external_ids"] = json.dumps(eids)
    if current.get("source") in (None, "", "Manual") and source.get("kind"):
        updates["source"] = source["kind"]
    updates["updated_at"] = now
    con.execute(
        "UPDATE items SET " + ", ".join(k + "=?" for k in updates) + " WHERE id=?",
        [*updates.values(), local_id],
    )
    _link(con, local_id, source["id"], incoming.get("external_id"), now)
    return True


def _insert(con, incoming, source, now):
    vals = {}
    for src, dst in _COLMAP.items():
        val = incoming.get(src)
        if val not in (None, ""):
            vals[dst] = val
    if incoming.get("notes"):
        vals["notes"] = incoming["notes"]
    if not vals.get("name"):
        vals["name"] = "unnamed device"
    vals["source"] = source.get("kind") or "CSV import"
    eids = {}
    if incoming.get("external_id"):
        eids[str(source["id"])] = str(incoming["external_id"])
    vals["external_ids"] = json.dumps(eids)
    vals["created_at"] = vals["updated_at"] = now
    vals.setdefault("photo_refs", "[]")
    vals.setdefault("receipt_refs", "[]")
    cols = list(vals)
    cur = con.execute(
        "INSERT INTO items(" + ",".join(cols) + ") VALUES(" + ",".join("?" for _ in cols) + ")",
        [vals[c] for c in cols],
    )
    _link(con, cur.lastrowid, source["id"], incoming.get("external_id"), now)
    return cur.lastrowid


def commit_review(con, review_id):
    row = _row(con, review_id)
    payload = json.loads(row["payload"])
    src = con.execute("SELECT * FROM sources WHERE id=?", (row["source_id"],)).fetchone()
    if not src:
        raise MergeError("source is gone")
    source, now = dict(src), av.now()
    n_exact = sum(1 for entry in payload.get("exact") or [] if _apply(con, entry["local_id"], entry.get("incoming") or {}, source, now))
    n_soft, n_skip = 0, len(payload.get("skipped") or [])
    for entry in payload.get("soft") or []:
        if entry.get("verified"):
            if _apply(con, entry["local_id"], entry.get("incoming") or {}, source, now):
                n_soft += 1
        else:
            n_skip += 1
    n_new = 0
    for entry in payload.get("new") or []:
        _insert(con, entry.get("incoming") or {}, source, now)
        n_new += 1
    n_miss = 0
    for entry in payload.get("not_seen") or []:
        con.execute(
            "UPDATE item_sources SET not_seen_at=? WHERE item_id=? AND source_id=?",
            (entry.get("not_seen_at") or now, entry["local_id"], source["id"]),
        )
        n_miss += 1
    con.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    detail = "committed %d new, %d updated, %d skipped, %d not seen" % (n_new, n_exact + n_soft, n_skip, n_miss)
    con.execute(
        "UPDATE sources SET added=?, updated=?, skipped=?, not_seen=?, health=?, detail=? WHERE id=?",
        (n_new, n_exact + n_soft, n_skip, n_miss, "OK", detail, source["id"]),
    )
    return {"exact": n_exact, "soft": n_soft, "new": n_new, "not_seen": n_miss, "skipped": n_skip}


def discard_review(con, review_id):
    row = _row(con, review_id)
    con.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    con.execute("UPDATE sources SET detail=? WHERE id=?", ("review discarded", row["source_id"]))
    return {"source_id": row["source_id"]}


def _public_mapping(mapping):
    if not isinstance(mapping, dict):
        return mapping
    out = {}
    for key, value in mapping.items():
        name = av.scrub(str(key))
        out[name] = av.scrub(value) if isinstance(value, str) else value
    return out


def review_view(con, row):
    payload = json.loads(row["payload"])
    src = con.execute("SELECT id, name FROM sources WHERE id=?", (row["source_id"],)).fetchone()
    ids = []
    for bucket in ("exact", "soft", "not_seen"):
        for entry in payload.get(bucket) or []:
            if entry.get("local_id") is not None:
                ids.append(entry["local_id"])
    names, serials = {}, {}
    if ids:
        uniq = list(dict.fromkeys(ids))
        q = "SELECT id, name, serial FROM items WHERE id IN (%s)" % ",".join("?" for _ in uniq)
        for item in con.execute(q, uniq):
            names[item["id"]] = item["name"]
            serials[item["id"]] = item["serial"]

    def local_label(entry):
        text = names.get(entry.get("local_id"))
        text = redact_serial_text(text, serials.get(entry.get("local_id")))
        text = redact_serial_text(text, (entry.get("incoming") or {}).get("serial"))
        return text

    def pub(entry):
        return {
            "local_id": entry.get("local_id"),
            "local_name": local_label(entry),
            "match_on": entry.get("match_on"),
            "incoming": public_device(entry.get("incoming") or {}),
        }

    soft = []
    for index, entry in enumerate(payload.get("soft") or []):
        item = pub(entry)
        item["index"] = index
        item["verified"] = bool(entry.get("verified"))
        soft.append(item)
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "source_name": src["name"] if src else None,
        "kind": row["kind"],
        "created_at": row["created_at"],
        "detected": payload.get("detected"),
        "mapping": _public_mapping(payload.get("mapping")),
        "counts": {
            "exact": len(payload.get("exact") or []),
            "soft": len(payload.get("soft") or []),
            "new": len(payload.get("new") or []),
            "not_seen": len(payload.get("not_seen") or []),
            "skipped": len(payload.get("skipped") or []),
        },
        "exact": [pub(entry) for entry in payload.get("exact") or []],
        "soft": soft,
        "new": [{"incoming": public_device(entry.get("incoming") or {})} for entry in payload.get("new") or []],
        "not_seen": [{
            "local_id": entry.get("local_id"),
            "local_name": local_label(entry),
            "not_seen_at": entry.get("not_seen_at"),
        } for entry in payload.get("not_seen") or []],
        "skipped": [{
            "reason": entry.get("reason"),
            "incoming": public_device(entry.get("incoming") or {}),
        } for entry in payload.get("skipped") or []],
    }
