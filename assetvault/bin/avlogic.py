"""AssetVault derived-state logic (pure functions, no I/O)."""
import json, datetime
from avcore import TZ

ELECTRONICS = {"Computers", "Networking", "Peripherals", "Streaming/AV", "Gaming", "Phones/Tablets", "Storage/Backup"}
SUCCESS_RESULTS = ("success", "manual")   # a manually logged backup counts as a successful backup
UNENCRYPTED = {"unencrypted", "none", "off", "no", "false", "disabled", "not encrypted"}

def parse_dt(s):
    """ISO date or datetime -> aware datetime in TZ (dates become local midnight). None on blank/invalid."""
    if s is None or s == "": return None
    if isinstance(s, datetime.datetime): d = s
    else:
        s = str(s).strip().replace("Z", "+00:00")
        try: d = datetime.datetime.fromisoformat(s)
        except ValueError:
            try: d = datetime.datetime.combine(datetime.date.fromisoformat(s[:10]), datetime.time())
            except ValueError: return None
    return d.replace(tzinfo=TZ) if d.tzinfo is None else d.astimezone(TZ)

def _g(item, k):
    try: return item[k]
    except (KeyError, IndexError): return None

def rpo_target_hours(item):
    h = _g(item, "rpo_target_hours")
    return int(h) if h not in (None, "") and int(h) > 0 else None

def is_scheduled(item):
    return not _g(item, "paused") and rpo_target_hours(item) is not None

def last_success(history):
    ds = [parse_dt(h["date"]) for h in history if h["result"] in SUCCESS_RESULTS]
    ds = [d for d in ds if d]; return max(ds) if ds else None

def last_attempt(history):
    ds = [d for d in (parse_dt(h["date"]) for h in history) if d]; return max(ds) if ds else None

def rpo_state(item, history, now=None, at_risk_pct=0.5):
    """Met / At risk / Breached / No data / Not scheduled.
    At risk once the time since last success has used >= at_risk_pct of the RPO window."""
    now = now or datetime.datetime.now(TZ)
    if not is_scheduled(item): return "Not scheduled"
    if not history: return "No data"
    ls = last_success(history)
    if ls is None: return "Breached"          # attempts exist but none succeeded
    age_h = (now - ls).total_seconds() / 3600
    target = rpo_target_hours(item)
    if age_h > target: return "Breached"
    if age_h >= target * at_risk_pct: return "At risk"
    return "Met"

_RANK = {"success": 3, "manual": 3, "partial": 2, "failed": 1}

def day_strip(history, days=30, now=None, item=None):
    """Oldest -> newest list of {date, state, results}. state: success/partial/failed/no_result/not_scheduled.
    Best result of the day wins. Days with no result when the item is unscheduled (paused / no target) are not_scheduled."""
    now = now or datetime.datetime.now(TZ)
    today = now.astimezone(TZ).date()
    by_day = {}
    for h in history:
        d = parse_dt(h["date"])
        if d: by_day.setdefault(d.date(), []).append(h["result"])
    sched = True if item is None else is_scheduled(item)
    out = []
    for i in range(days - 1, -1, -1):
        day = today - datetime.timedelta(days=i)
        res = by_day.get(day, [])
        if res:
            best = max(res, key=lambda r: _RANK.get(r, 0))
            state = "success" if best in SUCCESS_RESULTS else best
        else:
            state = "no_result" if sched else "not_scheduled"
        out.append({"date": day.isoformat(), "state": state, "results": res})
    return out

def completeness(item, threshold):
    flags = []
    if _g(item, "category") in ELECTRONICS and not (_g(item, "serial") or "").strip(): flags.append("missing serial")
    rv = _g(item, "replacement_value")
    if rv is None: flags.append("missing value")
    elif threshold is not None and float(rv) >= float(threshold):
        if not _refs(_g(item, "receipt_refs")): flags.append("missing receipt")
        if not _refs(_g(item, "photo_refs")): flags.append("missing photo")
    if not (_g(item, "room") or "").strip(): flags.append("missing room")
    return flags

def _refs(v):
    if not v: return []
    try: r = json.loads(v) if isinstance(v, str) else v
    except ValueError: return []
    return r if isinstance(r, list) else []

def refs(v):
    """Normalize photo_refs/receipt_refs to [{id, name, mime, added}] (legacy entries may be bare ids)."""
    return [r if isinstance(r, dict) else {"id": str(r), "name": None, "mime": None, "added": None} for r in _refs(v)]

def warranty_status(item, now=None, window_days=60):
    """expired / expiring / ok / unknown (no expiry date)."""
    now = now or datetime.datetime.now(TZ)
    d = parse_dt(_g(item, "warranty_expiry"))
    if d is None: return "unknown"
    days = (d.date() - now.astimezone(TZ).date()).days
    if days < 0: return "expired"
    if days <= window_days: return "expiring"
    return "ok"

def is_unencrypted(item):
    return (_g(item, "encryption_status") or "").strip().lower() in UNENCRYPTED

def mask_serial(s, mark="••••"):
    """Show only the last 4 characters of a serial. Blank stays blank."""
    s = (s or "").strip()
    return (mark + " " + s[-4:]) if len(s) > 4 else (mark if s else "")
