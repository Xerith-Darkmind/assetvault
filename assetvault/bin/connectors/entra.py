"""Microsoft Graph: Entra devices, and Intune managed devices when permitted.

Read-only. Client-credentials token from ASSETVAULT_GRAPH_SECRET. Intune 401/403
is not fatal: Entra devices are still returned.
"""
import re

from .base import Connector, ConnectorError, bearer, clean, device, require_ok

_HOSTS = ("login.microsoftonline.com", "graph.microsoft.com")
_ID = re.compile(r"[A-Za-z0-9._-]{1,253}")
_GRAPH = "https://graph.microsoft.com/v1.0"


class EntraConnector(Connector):
    name = "entra"
    kind = "Entra-Intune"
    title = "Microsoft Entra ID / Intune"

    def describe(self):
        return {
            "name": self.name,
            "title": self.title,
            "kind": self.kind,
            "secret_env": "ASSETVAULT_GRAPH_SECRET",
            "config": ["name", "tenant_id", "client_id"],
            "permissions": ["Device.Read.All", "DeviceManagementManagedDevices.Read.All"],
        }

    def _ids(self):
        tenant = str(self.config.get("tenant_id") or "").strip()
        client = str(self.config.get("client_id") or "").strip()
        if not _ID.fullmatch(tenant):
            raise ConnectorError("invalid tenant id", "Unreachable")
        if not _ID.fullmatch(client):
            raise ConnectorError("invalid client id", "Unreachable")
        return tenant, client

    def validate(self):
        super().validate()
        self._ids()

    def _token(self, http):
        tenant, client = self._ids()
        secret = self.secret("ASSETVAULT_GRAPH_SECRET")
        resp = http.post_form(
            "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tenant,
            {
                "client_id": client,
                "client_secret": secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        if resp.status in (400, 401, 403):
            raise ConnectorError("authentication failed", "Auth failed")
        data = require_ok(resp)
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise ConnectorError("authentication failed", "Auth failed")
        return token

    def _paged(self, http, token, url, limit):
        from .base import MAX_PAGES
        out, seen, pages = [], set(), 0
        while url:
            if url in seen:
                break
            seen.add(url)
            pages += 1
            if pages > MAX_PAGES:
                raise ConnectorError("page limit exceeded", "Unreachable")
            data = require_ok(http.get(url, bearer(token)))
            if not isinstance(data, dict):
                raise ConnectorError("invalid response", "Unreachable")
            rows = data.get("value") or []
            if not isinstance(rows, list):
                raise ConnectorError("invalid response", "Unreachable")
            out.extend(rows)
            if limit is not None and len(out) >= limit:
                return out[:limit]
            nxt = data.get("@odata.nextLink")
            url = _abs(nxt) if nxt else None
        return out

    def _intune(self, http, token, limit):
        url = _GRAPH + "/deviceManagement/managedDevices"
        resp = http.get(url, bearer(token))
        if resp.status in (401, 403):
            self.notes.append("Intune not permitted")
            return []
        data = require_ok(resp)
        rows = list(data.get("value") or [])
        if not isinstance(rows, list):
            raise ConnectorError("invalid response", "Unreachable")
        if limit is not None and len(rows) >= limit:
            return rows[:limit]
        nxt = data.get("@odata.nextLink")
        if nxt:
            more = self._paged(http, token, _abs(nxt), None if limit is None else max(limit - len(rows), 0))
            rows.extend(more)
        return rows[:limit] if limit is not None else rows

    def pull(self, limit=None):
        http = self.http(_HOSTS, allow_post=True)
        token = self._token(http)
        entra_rows = self._paged(http, token, _GRAPH + "/devices", limit)
        # A short preview does not need every Intune page; a full sync (limit None) does.
        intune_rows = self._intune(http, token, limit)
        return _merge(entra_rows, intune_rows, limit)


def _abs(url):
    if not url:
        return None
    if str(url).startswith("/"):
        return "https://graph.microsoft.com" + str(url)
    return str(url)


def _merge(entra_rows, intune_rows, limit):
    by_aad = {}
    for row in intune_rows:
        aid = clean(row.get("azureADDeviceId") if isinstance(row, dict) else None)
        if aid:
            by_aad.setdefault(aid.lower(), row)
    used, out = set(), []

    def push(item):
        out.append(item)
        return limit is not None and len(out) >= limit

    for row in entra_rows:
        if not isinstance(row, dict):
            continue
        device_id = clean(row.get("deviceId"))
        match = by_aad.get(device_id.lower()) if device_id else None
        if match is not None:
            used.add(id(match))
            if push(_from_both(row, match)):
                return out
        elif push(_from_entra(row)):
            return out
    for row in intune_rows:
        if not isinstance(row, dict) or id(row) in used:
            continue
        if push(_from_intune(row)):
            return out
    return out


def _from_entra(row):
    return device(
        name=row.get("displayName"),
        os=row.get("operatingSystem"),
        os_version=row.get("operatingSystemVersion"),
        last_checkin=row.get("approximateLastSignInDateTime"),
        brand=row.get("manufacturer"),
        model=row.get("model"),
        external_id=row.get("id") or row.get("deviceId"),
        managed_by="Entra ID",
        source="Entra-Intune",
    )


def _from_intune(row):
    return device(
        name=row.get("deviceName") or row.get("managedDeviceName"),
        serial=row.get("serialNumber"),
        mac=row.get("wiFiMacAddress") or row.get("ethernetMacAddress"),
        brand=row.get("manufacturer"),
        model=row.get("model"),
        os=row.get("operatingSystem"),
        os_version=row.get("osVersion"),
        assigned_user=row.get("userPrincipalName") or row.get("userDisplayName"),
        last_checkin=row.get("lastSyncDateTime"),
        encryption_status=row.get("isEncrypted"),
        managed_by="Intune",
        external_id=row.get("azureADDeviceId") or row.get("id"),
        source="Entra-Intune",
    )


def _from_both(entra, managed):
    base = _from_intune(managed)
    # Entra object id stays stable across syncs when both directories know the device.
    ext = clean(entra.get("id")) or base["external_id"]
    base["external_id"] = ext
    if not base.get("os"):
        base["os"] = clean(entra.get("operatingSystem"))
    if not base.get("os_version"):
        base["os_version"] = clean(entra.get("operatingSystemVersion"))
    if not base.get("last_checkin"):
        base["last_checkin"] = clean(entra.get("approximateLastSignInDateTime"))
    if base.get("name_fallback"):
        shown = clean(entra.get("displayName"))
        if shown:
            base["name"] = shown
            base.pop("name_fallback", None)
    return base
