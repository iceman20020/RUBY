"""auto param + endpoint discovery — feeds injection modules."""

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from .core import host_of

MAX_PAGES = 20
MAX_DEPTH = 2
MAX_PARAMS_PER_ENDPOINT = 30


def _extract_links(html, base_url):
    links = set()
    for pat in [
        r'href=["\']([^"\'#]+)',
        r'action=["\']([^"\']+)',
        r'src=["\']([^"\'#]+)',
    ]:
        for m in re.finditer(pat, html, re.I):
            href = m.group(1).strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                continue
            try:
                links.add(urljoin(base_url, href))
            except Exception:
                continue
    return links


def _extract_forms(html, base_url):
    forms = []
    for form_match in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.I | re.S):
        form_tag = form_match.group(0)
        body = form_match.group(1)

        action_m = re.search(r'action=["\']([^"\']*)', form_tag, re.I)
        action = urljoin(base_url, action_m.group(1)) if action_m else base_url

        method_m = re.search(r'method=["\'](\w+)', form_tag, re.I)
        method = (method_m.group(1) if method_m else "GET").upper()

        params = []
        for inp in re.finditer(r'<(?:input|textarea|select)\b[^>]*>', body, re.I):
            tag = inp.group(0)
            name_m = re.search(r'name=["\']([^"\']+)', tag, re.I)
            if name_m:
                params.append(name_m.group(1))
        forms.append({"action": action, "method": method, "params": params})
    return forms


def _extract_params_from_url(u):
    parsed = urlparse(u)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


def _is_same_host(url, target_host):
    try:
        return host_of(url) == target_host
    except Exception:
        return False


def _build_test_url(endpoint, params):
    parsed = urlparse(endpoint)
    test_vals = {p: "1" for p in params}
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                       parsed.params, urlencode(test_vals), ""))


async def discover(client, target, ctx):
    target_host = host_of(target)
    visited = set()
    endpoints = {}
    queue = [(target, 0)]

    target_params = _extract_params_from_url(target)
    if target_params:
        endpoints[(target, "GET")] = {
            "url": target, "params": target_params,
            "method": "GET", "source": "entry",
        }

    while queue:
        url, depth = queue.pop(0)
        if url in visited or depth > MAX_DEPTH or len(visited) >= MAX_PAGES:
            continue
        visited.add(url)

        r = await client.get(url)
        if "error" in r:
            continue
        html = r["body"]

        for form in _extract_forms(html, url):
            if not _is_same_host(form["action"], target_host):
                continue
            if not form["params"]:
                continue
            params = form["params"][:MAX_PARAMS_PER_ENDPOINT]
            key = (form["action"], form["method"])
            if key not in endpoints:
                endpoints[key] = {
                    "url": form["action"], "params": params,
                    "method": form["method"], "source": f"form@{url}",
                }
            else:
                existing = set(endpoints[key]["params"])
                endpoints[key]["params"] = list(existing.union(params))[:MAX_PARAMS_PER_ENDPOINT]

        for link in _extract_links(html, url):
            if not _is_same_host(link, target_host):
                continue
            params = _extract_params_from_url(link)
            if params:
                key = (link, "GET")
                if key not in endpoints:
                    endpoints[key] = {
                        "url": link, "params": params,
                        "method": "GET", "source": f"link@{url}",
                    }
            if depth < MAX_DEPTH and link not in visited:
                queue.append((link, depth + 1))

    ep_list = list(endpoints.values())
    all_params = set(target_params)
    for ep in ep_list:
        all_params.update(ep["params"])

    return {
        "endpoints": ep_list,
        "endpoint_count": len(ep_list),
        "all_params": sorted(all_params),
        "pages_crawled": len(visited),
    }


async def build_scan_targets(client, target, ctx):
    if ctx.get("scan_targets"):
        return ctx["scan_targets"]

    if "discovery" not in ctx:
        ctx["discovery"] = await discover(client, target, ctx)

    discovery = ctx["discovery"]
    targets = []

    for p in _extract_params_from_url(target):
        targets.append((target, p, "GET"))

    for ep in discovery["endpoints"]:
        if ep["url"] == target:
            continue
        url_with_all = _build_test_url(ep["url"], ep["params"])
        for p in ep["params"]:
            targets.append((url_with_all, p, ep["method"]))

    seen = set()
    unique = []
    for t in targets:
        k = (t[0], t[1], t[2])
        if k not in seen:
            seen.add(k)
            unique.append(t)

    ctx["scan_targets"] = unique
    ctx["params"] = sorted(set(t[1] for t in unique))
    return unique
