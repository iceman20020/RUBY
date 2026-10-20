"""shared core: HTTP client, banner, UI, injection helper, utilities."""

import asyncio
import base64
import json
import os
import random
import re
import ssl
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote_plus

import aiohttp


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


class C:
    RED = "\033[91m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    DIM = "\033[2m"
    RST = "\033[0m"
    BLD = "\033[1m"
    R1 = "\033[38;5;203m"
    R2 = "\033[38;5;62m"
    R3 = "\033[38;5;210m"
    R4 = "\033[38;5;69m"


_BANNER_ROWS = [
    "\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2557 \u2588\u2588\u2557   \u2588\u2588\u2557",
    "\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d",
    "\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d \u255a\u2588\u2588\u2588\u2588\u2554\u255d ",
    "\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2557  \u255a\u2588\u2588\u2554\u255d  ",
    "\u2588\u2588\u2551  \u2588\u2588\u2551\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d   \u2588\u2588\u2551   ",
    "\u255a\u2550\u255d  \u255a\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d \u255a\u2550\u2550\u2550\u2550\u2550\u255d    \u255a\u2550\u255d   ",
]


def _gradient_line(line, row_idx):
    out = []
    total = len(line)
    for i, ch in enumerate(line):
        if ch == " ":
            out.append(ch)
            continue
        t = (i / max(total - 1, 1) + row_idx * 0.09) % 1.0
        out.append((C.R1 if t < 0.5 else C.R2) + ch)
    return "".join(out) + C.RST


def render_banner():
    print()
    print(C.DIM + "  " + "\u2500" * 60 + C.RST)
    print()
    for i, row in enumerate(_BANNER_ROWS):
        print("  " + _gradient_line(row, i))
    print()
    print(f"  {C.R1}\u25c6{C.RST} {C.DIM}recon{C.RST}   "
          f"{C.R2}\u25c6{C.RST} {C.DIM}vuln scan{C.RST}   "
          f"{C.R1}\u25c6{C.RST} {C.DIM}param discovery{C.RST}   "
          f"{C.R2}\u25c6{C.RST} {C.DIM}30 modules{C.RST}")
    print()
    print(C.DIM + "  " + "\u2500" * 60 + C.RST)
    print()


def section(title):
    print()
    print(f"  {C.R1}\u258e{C.RST} {C.BLD}{C.WHT}{title}{C.RST}")
    print(C.DIM + "  " + "\u2500" * 66 + C.RST)


def kv(k, v, color=None):
    c = color or C.WHT
    print(f"  {C.DIM}\u2502{C.RST} {C.DIM}{k:<22}{C.RST} {c}{v}{C.RST}")


def bullet(text, color=None):
    c = color or C.DIM
    print(f"  {C.DIM}\u2502{C.RST} {c}\u00b7{C.RST} {text}")


def find_line(text, color=None):
    c = color or C.GRN
    print(f"  {C.DIM}\u2502{C.RST} {c}\u2713{C.RST} {text}")


def warn_line(text):
    print(f"  {C.DIM}\u2502{C.RST} {C.YEL}!{C.RST} {text}")


def err_line(text):
    print(f"  {C.DIM}\u2502{C.RST} {C.RED}\u2717{C.RST} {text}")


def info_line(text):
    print(f"  {C.DIM}\u2502{C.RST} {C.R2}\u2192{C.RST} {text}")


def load_json(name):
    path = os.path.join(DATA_DIR, name)
    if not os.path.isfile(path):
        raise RuntimeError(f"missing data file: {path}")
    with open(path) as f:
        return json.load(f)


def load_lines(name):
    path = os.path.join(DATA_DIR, name)
    if not os.path.isfile(path):
        raise RuntimeError(f"missing data file: {path}")
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def startup_check():
    required = [
        "waf_signatures.json", "vuln_templates.json", "db_paths.txt",
        "success_words.json", "exploit_payloads.json",
    ]
    missing = [f for f in required
               if not os.path.isfile(os.path.join(DATA_DIR, f))]
    return missing


def is_ok(r):
    return isinstance(r, dict) and "error" not in r and r.get("status", 0) > 0


def b64d(s):
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return b""


class HTTPClient:
    """
    Async client.

    scope_origin: "scheme://host" of the scan target. When set, request()
    automatically skips auth (headers + cookies) on any URL whose origin
    doesn't match. Modules fetching crt.sh, dns.google, or subdomains are
    protected by default — a new module can't leak credentials accidentally.
    """

    def __init__(self, timeout=8, proxy=None, auth=None, scope_origin=None):
        self.timeout = timeout
        self.proxy = proxy
        self.auth_headers = (auth or {}).get("headers", {}) or {}
        self.auth_cookies = (auth or {}).get("cookies", {}) or {}
        self.scope_origin = scope_origin.rstrip("/") if scope_origin else None
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        self.ssl_ctx = ssl_ctx
        self._session = None

    def _same_origin(self, url):
        if not self.scope_origin:
            return True
        p = urlparse(url)
        origin = f"{p.scheme}://{p.netloc}".rstrip("/")
        return origin == self.scope_origin

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self.ssl_ctx, limit=100)
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector,
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def request(self, method, url, allow_redirects=True, headers=None,
                      timeout=None, cookies=None, auth=True, **kwargs):
        if auth and not self._same_origin(url):
            auth = False

        h = {"User-Agent": random.choice(USER_AGENTS)}
        if auth:
            h.update(self.auth_headers)
        if headers:
            h.update(headers)

        merged_cookies = None
        if (self.auth_cookies and auth) or cookies:
            base = self.auth_cookies if auth else {}
            merged_cookies = {**base, **(cookies or {})}

        per_req_timeout = aiohttp.ClientTimeout(total=timeout) if timeout else None
        if per_req_timeout:
            kwargs["timeout"] = per_req_timeout

        try:
            async with self._session.request(
                method, url, headers=h, allow_redirects=allow_redirects,
                proxy=self.proxy, ssl=self.ssl_ctx,
                cookies=merged_cookies, **kwargs
            ) as resp:
                body = await resp.text(errors="replace")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "cookies": {c.key: c.value for c in resp.cookies.values()},
                    "body": body,
                    "url": str(resp.url),
                    "length": len(body),
                }
        except asyncio.TimeoutError:
            return {"error": "timeout", "url": url}
        except aiohttp.ClientError as e:
            return {"error": str(e), "url": url}
        except Exception as e:
            return {"error": str(e), "url": url}

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)


def inject_param(url, param, payload):
    """Injects payload. Preserves duplicate keys and their order."""
    parsed = urlparse(url)
    raw_pairs = []
    if parsed.query:
        for pair in parsed.query.split("&"):
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
            else:
                k, v = pair, ""
            raw_pairs.append((k, v))

    replaced = False
    for i, (k, v) in enumerate(raw_pairs):
        if unquote_plus(k) == param:
            raw_pairs[i] = (k, payload)
            replaced = True
    if not replaced:
        raw_pairs.append((param, payload))

    new_query = "&".join(f"{k}={v}" for k, v in raw_pairs)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, new_query, parsed.fragment))


def get_params(url):
    return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def host_of(url):
    return urlparse(url).hostname or ""


def scheme_of(url):
    return urlparse(url).scheme or "http"


def split_set_cookie(raw):
    """
    Split multiple Set-Cookie blocks. Handles Expires=Wed, 21 Oct...
    by treating a comma as separator only when followed by a new name=.
    """
    if not raw:
        return []
    parts = []
    cur = ""
    for chunk in raw.split(","):
        if re.match(r"\s*[A-Za-z0-9_\-]+\s*=", chunk) and cur:
            parts.append(cur.strip())
            cur = chunk
        else:
            cur = (cur + "," + chunk) if cur else chunk
    if cur:
        parts.append(cur.strip())
    return parts


__all__ = [
    "C", "HTTPClient", "DATA_DIR", "USER_AGENTS",
    "load_json", "load_lines", "startup_check", "is_ok", "b64d",
    "inject_param", "get_params", "host_of", "scheme_of", "split_set_cookie",
    "render_banner", "section", "kv", "bullet", "find_line",
    "warn_line", "err_line", "info_line",
]
