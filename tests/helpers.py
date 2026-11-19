"""Offline fakes for vcd_shadow_cleaner tests: a fake requests session, no network."""
import fnmatch
import json
from urllib.parse import parse_qs, urlsplit

import requests

T = "https://vcd.example/api/vAppTemplate/vappTemplate-"
S = "https://vcd.example/api/admin/extension/shadowVm/"
ORG_A = "https://vcd.example/api/org/aaaaaaaa-0000-0000-0000-00000000000a"
ORG_B = "https://vcd.example/api/org/bbbbbbbb-0000-0000-0000-00000000000b"


class Resp:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self._text = text

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body

    @property
    def text(self):
        if self._text is not None:
            return self._text
        return json.dumps(self._body) if self._body is not None else ""

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.exceptions.HTTPError(f"{self.status_code} Error for url")
            err.response = self
            raise err


class Call:
    def __init__(self, method, url, params, headers, timeout, data, auth):
        self.method = method.upper()
        # The URL exactly as requests would build it (the fragment is never sent).
        self.prepared = requests.Request(method, url, params=params).prepare().url
        sp = urlsplit(self.prepared)
        self.host = sp.netloc
        self.path = sp.path
        self.fragment = sp.fragment
        self.raw_query = sp.query
        self.query = {k: v[0] for k, v in parse_qs(sp.query, keep_blank_values=True).items()}
        self.headers = headers or {}
        self.timeout = timeout
        self.data = data
        self.auth = auth

    def __repr__(self):
        return f"<Call {self.method} {self.prepared}>"


class FakeSession:
    """routes: query type -> handler, or 'METHOD /path' -> handler, or 'METHOD' -> handler.

    A handler is a callable(call) -> Resp, or a list of Resps returned in turn (the last
    one repeats). Every request is recorded in .calls.
    """

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []
        self.verify = False
        self._seq = {}

    def request(self, method, url, params=None, headers=None, timeout=None, data=None, auth=None, **kw):
        call = Call(method, url, params, headers, timeout, data, auth)
        self.calls.append(call)
        key = None
        if call.method == "GET" and call.path.endswith("/api/query"):
            key = call.query.get("type", "")
        for cand in (key, f"{call.method} {call.path}", call.method):
            if cand is not None and cand in self.routes:
                handler = self.routes[cand]
                break
        else:
            return Resp(404, {"message": "no route"})
        if isinstance(handler, Exception):
            raise handler
        if isinstance(handler, list):
            i = self._seq.get(id(handler), 0)
            self._seq[id(handler)] = i + 1
            item = handler[min(i, len(handler) - 1)]
            if isinstance(item, Exception):
                raise item
            return item(call) if callable(item) else item
        return handler(call)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def delete(self, url, **kw):
        return self.request("DELETE", url, **kw)

    def of(self, method=None, qtype=None):
        out = []
        for c in self.calls:
            if method and c.method != method:
                continue
            if qtype and c.query.get("type") != qtype:
                continue
            out.append(c)
        return out


def _filter_records(recs, fexpr):
    """Apply a simple FIQL 'a==b;c==d' filter (with '*' as a wildcard, as VCD may do)."""
    if not fexpr:
        return recs
    out = list(recs)
    for cond in fexpr.split(";"):
        if "==" not in cond:
            continue
        fld, val = cond.split("==", 1)
        if "*" in val:
            out = [r for r in out if fnmatch.fnmatchcase(str(r.get(fld, "")), val)]
        else:
            out = [r for r in out if str(r.get(fld, "")) == val]
    return out


def paged(recs, cap=None, total=None, fail_pages=(), honor_filter=True):
    """Query handler serving recs page by page (page/pageSize), optionally capped."""

    def handler(call):
        page = int(call.query.get("page", "1") or 1)
        size = int(call.query.get("pageSize", "25") or 25)
        if cap:
            size = min(size, cap)
        if page in fail_pages:
            return Resp(503, {"message": "unavailable"})
        data = _filter_records(recs, call.query.get("filter")) if honor_filter else list(recs)
        chunk = data[(page - 1) * size: page * size]
        return Resp(200, {"total": len(data) if total is None else total, "record": chunk,
                          "page": page, "pageSize": size})

    return handler


def make_client(vsc, routes, host="vcd.example"):
    c = vsc.VCDClient(host)
    c.session = FakeSession(routes)
    c.access_token = "t"
    return c


def shadows_of(result):
    """Matched shadows from a scan result (new ScanResult, or the old plain list)."""
    return list(getattr(result, "shadows", result))


def by_name(result):
    return {s.name: s for s in shadows_of(result)}
