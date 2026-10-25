"""Active Directory computer objects over LDAPS.

Password comes from ASSETVAULT_AD_PASSWORD. Plain LDAP (port 389 or ldap://)
is refused unless config allow_insecure is the boolean True.
"""
import datetime, re, uuid
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from .base import Connector, ConnectorError, clean, device

_TZ = ZoneInfo("America/New_York")
_HOST = re.compile(r"[A-Za-z0-9._-]{1,253}")
_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_ATTRS = [
    "name", "cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "lastLogonTimestamp", "description", "objectGUID",
]


class AdConnector(Connector):
    name = "ad"
    kind = "AD"
    title = "Active Directory"

    def describe(self):
        return {
            "name": self.name,
            "title": self.title,
            "kind": self.kind,
            "secret_env": "ASSETVAULT_AD_PASSWORD",
            "config": ["name", "server", "base_dn", "bind_user", "allow_insecure"],
            "permissions": ["read computer objects over LDAPS"],
        }

    def _endpoint(self):
        return parse_server(self.config)

    def validate(self):
        super().validate()
        _dn(self.config.get("base_dn"), "base dn")
        _dn(self.config.get("bind_user"), "bind user")
        self._endpoint()

    def pull(self, limit=None):
        from .base import MAX_PAGES
        host, port, use_ssl = self._endpoint()
        base = _dn(self.config.get("base_dn"), "base dn")
        user = _dn(self.config.get("bind_user"), "bind user")
        password = self.secret("ASSETVAULT_AD_PASSWORD")
        factory = self.ldap_factory or default_ldap_factory
        server_kwargs = {"host": host, "port": port, "use_ssl": use_ssl, "connect_timeout": self.timeout}
        conn_kwargs = {
            "user": user, "password": password, "auto_bind": True, "receive_timeout": self.timeout,
            "read_only": True, "raise_exceptions": True,
        }
        try:
            conn = factory(server_kwargs, conn_kwargs)
        except ConnectorError:
            raise
        except AssertionError:
            raise
        except Exception as exc:
            message, health = _ldap_health(exc)
            raise ConnectorError(message, health) from None
        out, seen, pages, cookie = [], 0, 0, None
        try:
            while True:
                pages += 1
                if pages > MAX_PAGES:
                    raise ConnectorError("page limit exceeded", "Unreachable")
                conn.search(
                    search_base=base,
                    search_filter="(&(objectCategory=computer)(objectClass=computer))",
                    search_scope="SUBTREE",
                    attributes=_ATTRS,
                    paged_size=200,
                    paged_cookie=cookie,
                )
                for entry in getattr(conn, "entries", []) or []:
                    out.append(_map_entry(entry))
                    seen += 1
                    if limit is not None and seen >= limit:
                        return out
                cookie = _cookie(conn)
                if not cookie:
                    break
        except ConnectorError:
            raise
        except AssertionError:
            raise
        except Exception as exc:
            message, health = _ldap_health(exc)
            raise ConnectorError(message, health) from None
        finally:
            unbind = getattr(conn, "unbind", None)
            if unbind:
                try:
                    unbind()
                except Exception:
                    pass
        return out


def parse_server(config):
    """Return (host, port, use_ssl). Refuses plaintext LDAP unless allow_insecure is True."""
    raw = str((config or {}).get("server") or "").strip()
    if not raw:
        raise ConnectorError("server is required", "Unreachable")
    allow = (config or {}).get("allow_insecure") is True
    scheme, host, port = None, raw, None
    if "://" in raw:
        parts = urlsplit(raw)
        scheme = (parts.scheme or "").lower()
        host = parts.hostname
        port = parts.port
        if parts.username or parts.password:
            raise ConnectorError("server url must not contain credentials", "Auth failed")
    elif raw.count(":") == 1:
        host, maybe = raw.rsplit(":", 1)
        if maybe.isdigit():
            port = int(maybe)
    if not host or not _HOST.fullmatch(host):
        raise ConnectorError("invalid server", "Unreachable")
    if scheme == "ldaps" or (scheme is None and port in (None, 636)):
        return host, port or 636, True
    insecure = scheme == "ldap" or port == 389 or scheme is None
    if insecure:
        if not allow:
            raise ConnectorError("plain LDAP on 389 refused; set allow_insecure to boolean true to allow it", "Unreachable")
        return host, port or 389, False
    raise ConnectorError("invalid server", "Unreachable")


def _dn(value, label):
    text = str(value or "").strip()
    if not text or any(c in text for c in "\r\n\x00"):
        raise ConnectorError("invalid " + label, "Unreachable")
    return text


def _ldap_health(exc):
    name = type(exc).__name__
    if "Bind" in name or "Credential" in name:
        return "authentication failed", "Auth failed"
    if "Timeout" in name:
        return "connection timed out", "Unreachable"
    return "directory unreachable", "Unreachable"


def default_ldap_factory(server_kwargs, conn_kwargs):
    try:
        import ldap3
        from ldap3.utils.log import OFF, set_library_log_detail_level, set_library_log_hide_sensitive_data
    except ImportError:
        raise ConnectorError("ldap3 is not installed", "Unreachable") from None
    set_library_log_hide_sensitive_data(True)
    set_library_log_detail_level(OFF)
    import ssl
    sk = dict(server_kwargs)
    sk["get_info"] = ldap3.NONE
    if sk.get("use_ssl"):
        sk["tls"] = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
    server = ldap3.Server(**sk)
    return ldap3.Connection(server, **conn_kwargs)


def _cookie(conn):
    try:
        cookie = conn.result["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"]
    except Exception:
        return None
    return cookie or None


def _val(entry, attr):
    if isinstance(entry, dict):
        return entry.get(attr)
    obj = getattr(entry, attr, None)
    if obj is None:
        return None
    return getattr(obj, "value", obj)


def filetime_to_iso(value):
    if value is None or value == "" or value == 0 or value == "0":
        return None
    if isinstance(value, datetime.datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(_TZ).isoformat(timespec="seconds")
    if isinstance(value, (list, tuple)):
        return filetime_to_iso(value[0]) if value else None
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return clean(value)
    if ticks <= 0:
        return None
    try:
        dt = _EPOCH + datetime.timedelta(microseconds=ticks / 10)
    except OverflowError:
        return None
    return dt.astimezone(_TZ).isoformat(timespec="seconds")


def guid_str(value):
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, bytes) and len(value) == 16:
        return str(uuid.UUID(bytes_le=value))
    return clean(value)


def _map_entry(entry):
    name = _val(entry, "name") or _val(entry, "cn") or _val(entry, "dNSHostName")
    desc = _val(entry, "description")
    if isinstance(desc, (list, tuple)):
        desc = desc[0] if desc else None
    return device(
        name=name,
        os=_val(entry, "operatingSystem"),
        os_version=_val(entry, "operatingSystemVersion"),
        last_checkin=filetime_to_iso(_val(entry, "lastLogonTimestamp")),
        notes=desc,
        external_id=guid_str(_val(entry, "objectGUID")),
        managed_by="Active Directory",
        source="AD",
    )
