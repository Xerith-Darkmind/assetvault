"""Jamf Pro computers and mobile devices. Client secret: ASSETVAULT_JAMF_SECRET.

Reads /api/oauth/token, then /api/v1/computers-inventory (falls back to
/api/v3/computers-inventory when v1 answers 404) and /api/v2/mobile-devices/detail.
Mobile inventory defaults to the General section, which has no serial, model,
MAC, user, or encryption. Those sections are requested explicitly. Mobile
401/403 is skipped; computers are still returned. Recovery-key routes are
never called.
"""
import re
from urllib.parse import urlencode, urlsplit

from .base import Connector, ConnectorError, bearer, clean, device, require_ok

_ID = re.compile(r"[A-Za-z0-9._~-]{1,200}")
_SECTIONS = ("GENERAL", "HARDWARE", "OPERATING_SYSTEM", "DISK_ENCRYPTION", "USER_AND_LOCATION")
# General alone omits serialNumber, model, wifiMacAddress, the user, and dataProtected.
_MOBILE_SECTIONS = ("GENERAL", "HARDWARE", "USER_AND_LOCATION", "SECURITY")
_FALLBACK = object()


class JamfConnector(Connector):
    name = "jamf"
    kind = "Jamf"
    title = "Jamf Pro"

    def describe(self):
        return {
            "name": self.name,
            "title": self.title,
            "kind": self.kind,
            "secret_env": "ASSETVAULT_JAMF_SECRET",
            "config": ["name", "url", "client_id"],
            "permissions": ["Read Computers", "Read Mobile Devices"],
        }

    def _origin(self):
        return parse_origin(self.config.get("url"))

    def validate(self):
        super().validate()
        self._origin()
        client = str(self.config.get("client_id") or "").strip()
        if not _ID.fullmatch(client):
            raise ConnectorError("invalid client id", "Unreachable")

    def _token(self, http, origin):
        secret = self.secret("ASSETVAULT_JAMF_SECRET")
        client = str(self.config.get("client_id") or "").strip()
        resp = http.post_form(origin + "/api/oauth/token", {
            "grant_type": "client_credentials",
            "client_id": client,
            "client_secret": secret,
        })
        if resp.status in (400, 401, 403):
            raise ConnectorError("authentication failed", "Auth failed")
        data = require_ok(resp)
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise ConnectorError("authentication failed", "Auth failed")
        return token

    def pull(self, limit=None):
        origin, host = self._origin()
        http = self.http((host,), allow_post=True)
        token = self._token(http, origin)
        computers = self._computers(http, token, origin, limit)
        mobiles = self._mobiles(http, token, origin, None if limit is None else max(limit - len(computers), 0))
        out = [_map_computer(r) for r in computers if isinstance(r, dict)]
        if limit is not None and len(out) >= limit:
            return out[:limit]
        out.extend(_map_mobile(r) for r in mobiles if isinstance(r, dict))
        return out[:limit] if limit is not None else out

    def _computers(self, http, token, origin, limit):
        for path in ("/api/v1/computers-inventory", "/api/v3/computers-inventory"):
            got = self._paged(http, token, origin + path, True, limit, allow_404=path.startswith("/api/v1/"))
            if got is _FALLBACK:
                continue
            return got
        raise ConnectorError("http 404", "Unreachable")

    def _mobiles(self, http, token, origin, limit):
        if limit == 0:
            return []
        url = origin + "/api/v2/mobile-devices/detail"
        resp = self._first(http, token, url, _MOBILE_SECTIONS)
        if resp.status in (401, 403):
            self.notes.append("mobile devices not permitted")
            return []
        return self._consume(http, token, url, _MOBILE_SECTIONS, limit, resp)

    def _first(self, http, token, url, sections):
        return http.get(self._page_url(url, 0, sections), bearer(token))

    def _paged(self, http, token, url, sections, limit, allow_404=False):
        resp = self._first(http, token, url, sections)
        if allow_404 and resp.status == 404:
            return _FALLBACK
        return self._consume(http, token, url, sections, limit, resp)

    def _consume(self, http, token, url, sections, limit, first):
        from .base import MAX_PAGES
        data = require_ok(first)
        rows = _rows(data)
        page = 0
        total = data.get("totalCount") if isinstance(data, dict) else None
        while True:
            if limit is not None and len(rows) >= limit:
                return rows[:limit]
            if not _rows(data):
                break
            if total is not None and len(rows) >= int(total):
                break
            if len(_rows(data)) < 100:
                break
            page += 1
            if page > MAX_PAGES:
                raise ConnectorError("page limit exceeded", "Unreachable")
            resp = http.get(self._page_url(url, page, sections), bearer(token))
            data = require_ok(resp)
            chunk = _rows(data)
            if not chunk:
                break
            rows.extend(chunk)
            if isinstance(data, dict) and data.get("totalCount") is not None:
                total = int(data["totalCount"])
        return rows[:limit] if limit is not None else rows

    def _page_url(self, url, page, sections):
        params = [("page", str(page)), ("page-size", "100")]
        if sections is True:
            sections = _SECTIONS
        if sections:
            params = [("section", s) for s in sections] + params
        return url + "?" + urlencode(params)


def parse_origin(url):
    parts = urlsplit(str(url or "").strip())
    if parts.username or parts.password:
        raise ConnectorError("url must not contain credentials", "Auth failed")
    if parts.scheme != "https" or not parts.hostname:
        raise ConnectorError("jamf url must be https", "Unreachable")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", parts.hostname):
        raise ConnectorError("invalid jamf url", "Unreachable")
    port = ":%s" % parts.port if parts.port else ""
    return "https://%s%s" % (parts.hostname, port), parts.hostname.lower()


def _rows(data):
    if isinstance(data, dict):
        rows = data.get("results")
        if rows is None:
            rows = data.get("computers") or data.get("mobileDevices") or []
    elif isinstance(data, list):
        rows = data
    else:
        raise ConnectorError("invalid response", "Unreachable")
    if not isinstance(rows, list):
        raise ConnectorError("invalid response", "Unreachable")
    return rows


def _map_computer(rec):
    general = rec.get("general") or {}
    hardware = rec.get("hardware") or {}
    system = rec.get("operatingSystem") or {}
    disk = rec.get("diskEncryption") or {}
    user = rec.get("userAndLocation") or {}
    enc = disk.get("fileVault2Enabled")
    if enc is None:
        boot = disk.get("bootPartitionEncryptionDetails") or {}
        enc = boot.get("partitionFileVault2State") or boot.get("fileVault2State")
    ext = rec.get("id")
    return device(
        name=general.get("name"),
        asset_tag=general.get("assetTag"),
        last_checkin=general.get("lastContactTime") or general.get("lastContactTimeUtc"),
        serial=hardware.get("serialNumber"),
        mac=hardware.get("macAddress") or hardware.get("altMacAddress"),
        brand=hardware.get("make"),
        model=hardware.get("model") or hardware.get("modelIdentifier"),
        os=system.get("name"),
        os_version=system.get("version"),
        assigned_user=user.get("username") or user.get("email") or user.get("realname") or user.get("realName"),
        encryption_status=enc,
        managed_by="Jamf",
        external_id=("computer:" + str(ext)) if ext is not None else rec.get("udid"),
        source="Jamf",
    )


def _map_mobile(rec):
    general = rec.get("general") or {}
    hardware = rec.get("hardware") or {}
    user = rec.get("userAndLocation") or {}
    security = rec.get("security") or {}
    enc = security.get("dataProtected")
    if enc is None:
        enc = security.get("blockLevelEncryptionCapable")
    ext = rec.get("mobileDeviceId")
    if ext is None:
        ext = rec.get("id")
    return device(
        name=general.get("displayName") or general.get("name") or general.get("deviceName"),
        asset_tag=general.get("assetTag"),
        last_checkin=general.get("lastInventoryUpdateDate") or general.get("lastInventoryUpdate"),
        serial=hardware.get("serialNumber") or general.get("serialNumber"),
        mac=hardware.get("wifiMacAddress") or hardware.get("wiFiMacAddress"),
        brand="Apple",
        model=hardware.get("model") or hardware.get("modelIdentifier") or rec.get("deviceType"),
        os=general.get("osType") or rec.get("deviceType"),
        os_version=general.get("osVersion"),
        assigned_user=user.get("username") or user.get("emailAddress") or user.get("realName"),
        encryption_status=enc,
        managed_by="Jamf",
        external_id=("mobile:" + str(ext)) if ext is not None else None,
        source="Jamf",
    )
