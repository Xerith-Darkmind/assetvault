"""Read-only pull from any JSON device API the owner points at.

Auth is none, bearer (ASSETVAULT_REST_TOKEN), basic (username in config,
password in ASSETVAULT_REST_PASSWORD), or a custom header whose value is
ASSETVAULT_REST_TOKEN. Pagination is none, a next-link field, or a page
parameter. Field mapping is source JSON path -> normalized field.
"""
import base64, re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .base import DEVICE_FIELDS, Connector, ConnectorError, clean, device, jget, require_ok

_HEADER = re.compile(r"[A-Za-z0-9-]{1,64}")
_AUTHS = ("none", "bearer", "basic", "header")
_PAGERS = ("none", "next", "page")


class GenericRestConnector(Connector):
    name = "generic_rest"
    kind = "REST"
    title = "Generic REST"

    def describe(self):
        return {
            "name": self.name,
            "title": self.title,
            "kind": self.kind,
            "secret_env": {
                "bearer": "ASSETVAULT_REST_TOKEN",
                "header": "ASSETVAULT_REST_TOKEN",
                "basic": "ASSETVAULT_REST_PASSWORD",
                "none": None,
            },
            "config": ["name", "url", "auth", "username", "header", "items_path", "pagination", "next_path", "page_param", "page_start", "page_size", "page_size_param", "mapping", "allow_insecure", "managed_by"],
        }

    def _url_parts(self):
        raw = str(self.config.get("url") or "").strip()
        parts = urlsplit(raw)
        if parts.username or parts.password:
            raise ConnectorError("url must not contain credentials", "Auth failed")
        allow_http = self.config.get("allow_insecure") is True
        if parts.scheme == "http" and not allow_http:
            raise ConnectorError("refused non-https request", "Unreachable")
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ConnectorError("invalid url", "Unreachable")
        return parts, allow_http

    def validate(self):
        super().validate()
        self._url_parts()
        auth = str(self.config.get("auth") or "none").lower()
        if auth not in _AUTHS:
            raise ConnectorError("invalid auth", "Unreachable")
        if auth == "header" and not _HEADER.fullmatch(str(self.config.get("header") or "").strip()):
            raise ConnectorError("invalid header name", "Unreachable")
        if auth == "basic" and not str(self.config.get("username") or "").strip():
            raise ConnectorError("username is required", "Auth failed")
        pager = str(self.config.get("pagination") or "none").lower()
        if pager not in _PAGERS:
            raise ConnectorError("invalid pagination", "Unreachable")
        if pager == "next" and not str(self.config.get("next_path") or "").strip():
            raise ConnectorError("next_path is required", "Unreachable")
        mapping = self.config.get("mapping")
        if not isinstance(mapping, dict) or not mapping:
            raise ConnectorError("mapping is required", "Unreachable")

    def pull(self, limit=None):
        parts, allow_http = self._url_parts()
        self.validate()
        http = self.http((parts.hostname.lower(),), allow_post=False, allow_http=allow_http)
        headers = self._auth_headers()
        pager = str(self.config.get("pagination") or "none").lower()
        if pager == "page":
            rows = self._by_page(http, headers, limit)
        elif pager == "next":
            rows = self._by_next(http, headers, parts.geturl(), limit)
        else:
            rows = self._once(http, headers, parts.geturl(), limit)
        return rows

    def _auth_headers(self):
        auth = str(self.config.get("auth") or "none").lower()
        headers = {"Accept": "application/json"}
        if auth == "none":
            return headers
        if auth == "bearer":
            headers["Authorization"] = "Bearer " + self.secret("ASSETVAULT_REST_TOKEN")
            return headers
        if auth == "header":
            headers[str(self.config.get("header")).strip()] = self.secret("ASSETVAULT_REST_TOKEN")
            return headers
        user = str(self.config.get("username") or "")
        if any(c in user for c in "\r\n"):
            raise ConnectorError("invalid username", "Auth failed")
        password = self.secret("ASSETVAULT_REST_PASSWORD")
        token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + token
        return headers

    def _once(self, http, headers, url, limit):
        data = require_ok(http.get(url, headers))
        return self._map_page(extract_items(data, self.config.get("items_path")), limit)

    def _by_next(self, http, headers, url, limit):
        from .base import MAX_PAGES
        path = str(self.config.get("next_path"))
        out, seen, pages = [], set(), 0
        while url:
            if url in seen:
                break
            seen.add(url)
            pages += 1
            if pages > MAX_PAGES:
                raise ConnectorError("page limit exceeded", "Unreachable")
            data = require_ok(http.get(url, headers))
            items = extract_items(data, self.config.get("items_path"))
            out.extend(self._map_page(items, None if limit is None else limit - len(out)))
            if limit is not None and len(out) >= limit:
                return out[:limit]
            nxt = jget(data, path)
            if not nxt:
                break
            url = urljoin(url, str(nxt))
        return out

    def _by_page(self, http, headers, limit):
        from .base import MAX_PAGES
        base = self._url_parts()[0].geturl()
        param = str(self.config.get("page_param") or "page")
        raw_start = self.config.get("page_start")
        start = 1 if raw_start is None or raw_start == "" else int(raw_start)
        size = self.config.get("page_size")
        size_param = self.config.get("page_size_param")
        out, seen_fp, page = [], set(), start
        for _ in range(MAX_PAGES + 1):
            if page > start + MAX_PAGES:
                raise ConnectorError("page limit exceeded", "Unreachable")
            extra = {param: page}
            if size and size_param:
                extra[str(size_param)] = size
            data = require_ok(http.get(with_query(base, extra), headers))
            items = extract_items(data, self.config.get("items_path"))
            if not items:
                break
            fingerprint = json_fp(items[0])
            if fingerprint in seen_fp:
                break
            seen_fp.add(fingerprint)
            out.extend(self._map_page(items, None if limit is None else limit - len(out)))
            if limit is not None and len(out) >= limit:
                return out[:limit]
            if size and len(items) < int(size):
                break
            page += 1
        return out

    def _map_page(self, items, remaining):
        mapping = self.config.get("mapping") or {}
        managed = clean(self.config.get("managed_by"))
        out = []
        for rec in items:
            if remaining is not None and len(out) >= remaining:
                break
            if not isinstance(rec, dict):
                continue
            kw = {"source": "REST"}
            if managed:
                kw["managed_by"] = managed
            for field, path in mapping.items():
                if field not in DEVICE_FIELDS or not isinstance(path, str):
                    continue
                kw[field] = jget(rec, path)
            out.append(device(**kw))
        return out


def extract_items(data, path):
    if path:
        got = jget(data, path)
        if not isinstance(got, list):
            raise ConnectorError("items path not found", "Unreachable")
        return got
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("value", "results", "devices", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    raise ConnectorError("items path not found", "Unreachable")


def with_query(url, extra):
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    for k, v in extra.items():
        query[str(k)] = str(v)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def json_fp(obj):
    try:
        import json
        return json.dumps(obj, sort_keys=True, default=str)[:500]
    except Exception:
        return repr(obj)[:500]
