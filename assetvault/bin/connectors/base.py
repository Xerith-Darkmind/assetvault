"""Connector interface, normalized devices, and a read-only HTTP client.

Secrets are read from the environment at call time. They are never written into
config, exceptions, or log lines. HTTP is GET, plus POST only to the OAuth
token URLs the built-in connectors use. Anything else is refused.
"""
import json, os, re, time, datetime, urllib.parse, urllib.request, urllib.error
from urllib.parse import urlsplit

import avcore as av
import avlogic

DEVICE_FIELDS = (
    "name", "serial", "mac", "asset_tag", "brand", "model", "os", "os_version",
    "assigned_user", "last_checkin", "encryption_status", "managed_by",
    "external_id", "source", "notes",
)
MAX_HTTP_BODY = 20 * 1024 * 1024
MAX_PAGES = 500
USER_AGENT = "AssetVault/0.2.0"
_TOKEN_SUFFIXES = ("/oauth2/v2.0/token", "/api/oauth/token")
_FORBIDDEN_KEYS = {
    "secret", "password", "token", "client_secret", "access_token", "authorization",
    "bind_password", "api_key", "apikey",
}
_ENC_ON = {"true", "yes", "encrypted", "enabled", "on", "filevault", "filevault 2", "filevault enabled"}
_ENC_OFF = {"false", "no", "unencrypted", "none", "off", "disabled", "not encrypted"}
_PATH = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


class ConnectorError(Exception):
    def __init__(self, message, health="Unreachable"):
        super().__init__(message)
        self.health = health  # "Auth failed" or "Unreachable"


class HttpResponse:
    def __init__(self, status, headers, body):
        self.status = int(status)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.body = bytes(body or b"")
        pairs = []
        if headers:
            try:
                pairs = list(headers.items())
            except Exception:
                pairs = []
        self.headers = {str(k).lower(): str(v) for k, v in pairs}

    def header(self, name):
        return self.headers.get((name or "").lower())

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            raise ConnectorError("invalid response", "Unreachable") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _token_path(url):
    path = urlsplit(url).path.rstrip("/")
    return any(path.endswith(suffix) for suffix in _TOKEN_SUFFIXES)


def _retry_after(resp):
    raw = resp.header("retry-after") or "1"
    try:
        delay = float(raw)
    except (TypeError, ValueError):
        delay = 1
    if delay < 0:
        delay = 0
    if delay > 30:
        delay = 30
    return delay


class HttpClient:
    """GET against the hosts the owner configured. POST only for OAuth token URLs."""

    def __init__(self, allowed_hosts, allow_post=False, allow_http=False, timeout=30, sleeper=None, send=None, max_retries=3):
        self.allowed_hosts = {h.lower() for h in allowed_hosts if h}
        self.allow_post = bool(allow_post)
        self.allow_http = bool(allow_http)
        self.timeout = timeout
        self.sleeper = sleeper or time.sleep
        self._send = send
        self.max_retries = max_retries

    def _check_url(self, url):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host not in self.allowed_hosts:
            raise ConnectorError("refused request to unconfigured host", "Unreachable")
        if parts.username or parts.password:
            raise ConnectorError("refused url with credentials", "Auth failed")
        if parts.scheme == "https":
            return
        if parts.scheme == "http" and self.allow_http:
            return
        raise ConnectorError("refused non-https request", "Unreachable")

    def request(self, method, url, headers=None, body=None):
        method = (method or "").upper()
        self._check_url(url)
        if method not in ("GET", "POST"):
            raise ConnectorError("write methods are not allowed", "Unreachable")
        if method == "POST" and not (self.allow_post and _token_path(url)):
            raise ConnectorError("write methods are not allowed", "Unreachable")
        retries = 0
        while True:
            resp = self._once(method, url, headers or {}, body)
            if len(resp.body) > MAX_HTTP_BODY:
                raise ConnectorError("response too large", "Unreachable")
            if resp.status in (301, 302, 303, 307, 308):
                raise ConnectorError("unexpected redirect", "Unreachable")
            if resp.status == 429 and retries < self.max_retries:
                self.sleeper(_retry_after(resp))
                retries += 1
                continue
            if resp.status == 429:
                raise ConnectorError("rate limited", "Unreachable")
            return resp

    def _once(self, method, url, headers, body):
        try:
            if self._send:
                resp = self._send(method, url, headers, body, self.timeout)
            else:
                resp = self._urllib(method, url, headers, body)
        except ConnectorError:
            raise
        except AssertionError:
            raise
        except TimeoutError:
            raise ConnectorError("connection timed out", "Unreachable") from None
        except Exception:
            raise ConnectorError("connection failed", "Unreachable") from None
        if not isinstance(resp, HttpResponse):
            raise ConnectorError("invalid response", "Unreachable")
        return resp

    def _urllib(self, method, url, headers, body):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                data = resp.read(MAX_HTTP_BODY + 1)
                return HttpResponse(getattr(resp, "status", 200), resp.headers, data)
        except ConnectorError:
            raise
        except AssertionError:
            raise
        except urllib.error.HTTPError as e:
            data = e.read(MAX_HTTP_BODY + 1) if getattr(e, "fp", None) else b""
            return HttpResponse(e.code, e.headers, data)
        except TimeoutError:
            raise ConnectorError("connection timed out", "Unreachable") from None
        except Exception:
            raise ConnectorError("connection failed", "Unreachable") from None

    def get(self, url, headers=None):
        h = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if headers:
            h.update(headers)
        return self.request("GET", url, h, None)

    def post_form(self, url, form):
        body = urllib.parse.urlencode(form).encode("utf-8")
        h = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
        }
        return self.request("POST", url, h, body)


def require_ok(resp):
    if resp.status in (401, 403):
        raise ConnectorError("authentication failed", "Auth failed")
    if resp.status != 200:
        raise ConnectorError("http %s" % resp.status, "Unreachable")
    return resp.json()


def bearer(token):
    return {"Authorization": "Bearer " + token, "Accept": "application/json"}


def _bad_key(key):
    k = str(key).lower().replace("-", "_")
    if k in _FORBIDDEN_KEYS:
        return True
    return k.endswith("_secret") or k.endswith("_password") or k.endswith("_token")


def assert_config_safe(config, secrets=None):
    """Non-secret config only. A secret value or a secret-shaped key is refused."""
    if not isinstance(config, dict):
        raise ConnectorError("config must be an object", "Unreachable")
    secrets = list(secrets or [])

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if _bad_key(k):
                    raise ConnectorError("config must not contain secrets", "Auth failed")
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str):
            for s in secrets:
                if s and len(s) >= 4 and s in obj:
                    raise ConnectorError("config must not contain secrets", "Auth failed")
    walk(config)


def clean(v, limit=500):
    if v is None:
        return None
    if isinstance(v, datetime.datetime):
        v = v.isoformat(timespec="seconds")
    elif isinstance(v, datetime.date):
        v = v.isoformat()
    elif isinstance(v, bool):
        v = "true" if v else "false"
    elif isinstance(v, float) and v.is_integer():
        v = str(int(v))
    elif isinstance(v, int):
        v = str(v)
    elif isinstance(v, list):
        return clean(v[0], limit) if v else None
    else:
        v = str(v).strip()
    if not v:
        return None
    return v[:limit]


def canon_mac(v):
    raw = clean(v, 100)
    if not raw:
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(hexes) != 12:
        return raw
    hexes = hexes.lower()
    if set(hexes) == {"0"}:
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))


def norm_encryption(v):
    if isinstance(v, bool):
        return "encrypted" if v else "unencrypted"
    s = clean(v, 100)
    if not s:
        return None
    low = s.lower()
    if low in _ENC_ON:
        return "encrypted"
    if low in _ENC_OFF:
        return "unencrypted"
    return s


def display_fallback(d):
    """A name that does not contain the raw serial."""
    model = d.get("model")
    serial = d.get("serial") or ""
    # Same cutoff as mask_serial: four characters is the whole serial, and
    # redact_serial_text will not strip a short serial out of a longer name.
    if model and len(serial) > 4:
        return "%s (…%s)" % (model, serial[-4:])
    if model:
        return model
    return "Unnamed device"


def device(**kw):
    d = {field: clean(kw.get(field)) for field in DEVICE_FIELDS}
    d["notes"] = clean(kw.get("notes"), 2000)
    d["mac"] = canon_mac(kw.get("mac"))
    d["encryption_status"] = norm_encryption(kw.get("encryption_status"))
    if not d["name"]:
        d["name"] = display_fallback(d)
        d["name_fallback"] = True
    return d


def jget(obj, path):
    """Dot / [index] lookup. A literal dict key wins over a nested path."""
    if path is None or path == "":
        return obj
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    cur = obj
    for match in _PATH.finditer(str(path)):
        key, idx = match.group(1), match.group(2)
        if cur is None:
            return None
        if idx is not None:
            i = int(idx)
            if not isinstance(cur, list) or i < 0 or i >= len(cur):
                return None
            cur = cur[i]
            continue
        if isinstance(cur, list) and key.isdigit():
            i = int(key)
            if i >= len(cur):
                return None
            cur = cur[i]
            continue
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def redact_serial_text(text, serial):
    """Remove a raw serial from a display string. Short serials are removed only on a full match."""
    if not isinstance(text, str):
        return text
    raw = str(serial or "").strip()
    if not raw:
        return text
    if len(raw) <= 4:
        if text.strip().casefold() == raw.casefold():
            return "Unnamed device"
        return text
    return re.compile(re.escape(raw), re.IGNORECASE).sub(avlogic.mask_serial(raw), text)


def public_device(dev, secrets=None):
    """Device preview safe to print: serial masked, known secrets removed."""
    dev = dev or {}
    secrets = av.secret_values() if secrets is None else secrets
    out = {}
    for field in DEVICE_FIELDS:
        val = dev.get(field)
        out[field] = av.scrub(val, secrets) if isinstance(val, str) else val
    serial = dev.get("serial")
    if any(s and serial is not None and s in str(serial) for s in secrets):
        out["serial"] = "[redacted]"
    else:
        out["serial"] = avlogic.mask_serial(serial)
    for field, val in list(out.items()):
        if field == "serial" or not isinstance(val, str):
            continue
        out[field] = redact_serial_text(val, serial)
    return out


def _no_newlines(value, message):
    if any(c in value for c in "\r\n\x00"):
        raise ConnectorError(message, "Auth failed")
    return value


class Connector:
    name = "base"
    kind = "Manual"
    title = "Connector"

    def __init__(self, config=None, env=None, send=None, sleeper=None, ldap_factory=None, timeout=30):
        self.config = config or {}
        self.env = os.environ if env is None else env
        self.send = send
        self.sleeper = sleeper or time.sleep
        self.ldap_factory = ldap_factory
        self.timeout = timeout
        self.notes = []

    def secret(self, name):
        value = self.env.get(name) if self.env else None
        if not value:
            raise ConnectorError("missing " + name, "Auth failed")
        return _no_newlines(value, "invalid secret")

    def validate(self):
        assert_config_safe(self.config, av.secret_values(self.env))

    def http(self, allowed_hosts, allow_post=False, allow_http=False):
        return HttpClient(
            allowed_hosts=allowed_hosts, allow_post=allow_post, allow_http=allow_http,
            timeout=self.timeout, sleeper=self.sleeper, send=self.send,
        )

    def test(self):
        devices = []
        for dev in self.pull(limit=5):
            devices.append(dev)
            if len(devices) >= 5:
                break
        return {"health": "OK", "devices": devices}

    def pull(self, limit=None):
        raise NotImplementedError

    def describe(self):
        return {"name": self.name, "title": self.title, "kind": self.kind}
