"""modules 13-22: full injection suite with auto param discovery."""

import asyncio
import re
import time
from urllib.parse import urlparse

from .core import inject_param, load_json
from .crawler import build_scan_targets


async def _prep(client, target, ctx):
    return await build_scan_targets(client, target, ctx)


def _get_targets(targets):
    return [(u, p) for (u, p, m) in targets if m == "GET"]


async def m13(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["sqli_error"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(8)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            r = await client.get(test_url)
            if "error" in r:
                return None
            for pat in tmpl["patterns"]:
                if re.search(pat, r["body"], re.I):
                    return {"param": param, "payload": payload,
                            "evidence": pat, "url": test_url}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets
             for pl in tmpl["payloads"]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    seen = set()
    for r in results:
        if isinstance(r, dict):
            key = (r["param"], r["evidence"])
            if key not in seen:
                findings.append(r)
                seen.add(key)

    return {
        "params_tested": sorted(set(t[1] for t in targets)),
        "endpoints_tested": len(set(t[0] for t in targets)),
        "tested": len(tasks), "findings": findings,
        "payload_count": len(tmpl["payloads"]),
        "pattern_count": len(tmpl["patterns"]),
    }


async def m14(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["sqli_blind"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    threshold = tmpl["delay_threshold"]
    sem = asyncio.Semaphore(4)
    get_targets = _get_targets(targets)

    async def time_test(base_url, param, payload, flavor):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            t0 = time.monotonic()
            r = await client.get(test_url)
            dt = time.monotonic() - t0
            if "error" not in r and dt >= threshold:
                return {"type": "time", "param": param, "flavor": flavor,
                        "payload": payload, "delay": round(dt, 2),
                        "url": test_url}
            return None

    tasks = []
    for (bu, p) in get_targets:
        for flavor, payloads in tmpl["time_payloads"].items():
            for pl in payloads:
                tasks.append(time_test(bu, p, pl, flavor))
    time_results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in time_results:
        if isinstance(r, dict):
            findings.append(r)

    async def bool_test(base_url, param, pair):
        async with sem:
            u1 = inject_param(base_url, param, pair[0])
            u2 = inject_param(base_url, param, pair[1])
            r1 = await client.get(u1)
            r2 = await client.get(u2)
            if "error" in r1 or "error" in r2:
                return None
            l1, l2 = r1["length"], r2["length"]
            if l1 == 0 or l2 == 0:
                return None
            diff = abs(l1 - l2) / max(l1, l2)
            if diff >= tmpl["diff_ratio"]:
                return {"type": "boolean", "param": param, "pair": pair,
                        "len1": l1, "len2": l2, "diff": round(diff, 2)}
            return None

    bool_tasks = [bool_test(bu, p, pair) for (bu, p) in get_targets
                  for pair in tmpl["boolean_pairs"]]
    bool_results = await asyncio.gather(*bool_tasks, return_exceptions=True)
    for r in bool_results:
        if isinstance(r, dict):
            findings.append(r)

    return {
        "params_tested": sorted(set(t[1] for t in targets)),
        "tested_time": len(tasks), "tested_bool": len(bool_tasks),
        "findings": findings,
        "threshold_sec": threshold,
    }


async def m15(client, url, ctx):
    payloads = load_json("vuln_templates.json")["xss_reflected"]["payloads"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(8)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            r = await client.get(test_url)
            if "error" in r:
                return None
            if payload in r["body"]:
                idx = r["body"].find(payload)
                context = r["body"][max(0, idx - 20):idx + len(payload) + 20]
                return {"param": param, "payload": payload,
                        "reflection": "verbatim", "context": context,
                        "url": test_url}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets for pl in payloads]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return {
        "params_tested": sorted(set(t[1] for t in targets)),
        "endpoints_tested": len(set(t[0] for t in targets)),
        "tested": len(tasks), "findings": findings,
        "payload_count": len(payloads),
    }


async def m16(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["xss_blind"]
    bxss_host = ctx.get("bxss_host")
    if not bxss_host:
        return {"note": "no --bxss host — set with --bxss your.xss.host"}
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    headers = tmpl["headers"]
    get_targets = _get_targets(targets)

    for payload_tmpl in tmpl["payloads"]:
        payload = payload_tmpl.replace("BXSS_HOST", bxss_host)
        for hdr in headers:
            r = await client.get(url, headers={hdr: payload})
            if "error" not in r:
                findings.append({"vector": f"header:{hdr}",
                                 "payload": payload[:80],
                                 "status": r["status"]})
        for (bu, p) in get_targets:
            test_url = inject_param(bu, p, payload)
            r = await client.get(test_url)
            if "error" not in r:
                findings.append({"vector": f"param:{p}",
                                 "payload": payload[:80],
                                 "status": r["status"]})

    return {
        "callback_host": bxss_host,
        "note": "watch callback server — payloads fire client-side or in admin panels",
        "delivered": len(findings),
        "vectors": findings,
        "header_count": len(headers),
    }


async def m17(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["lfi"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(8)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            r = await client.get(test_url)
            if "error" in r:
                return None
            for pat in tmpl["patterns"]:
                if re.search(pat, r["body"], re.I):
                    return {"param": param, "payload": payload,
                            "evidence": pat, "url": test_url}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets
             for pl in tmpl["payloads"]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return {"params_tested": sorted(set(t[1] for t in targets)),
            "tested": len(tasks), "findings": findings,
            "payload_count": len(tmpl["payloads"])}


async def m18(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["rce"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(6)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            r = await client.get(test_url)
            if "error" in r:
                return None
            for pat in tmpl["patterns"]:
                if re.search(pat, r["body"]):
                    return {"type": "output", "param": param,
                            "payload": payload, "evidence": pat,
                            "url": test_url}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets
             for pl in tmpl["payloads"]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    async def time_test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            t0 = time.monotonic()
            r = await client.get(test_url)
            dt = time.monotonic() - t0
            if "error" not in r and dt >= 3.0:
                return {"type": "timing", "param": param,
                        "payload": payload, "delay": round(dt, 2)}
            return None

    time_tasks = [time_test(bu, p, pl) for (bu, p) in get_targets
                  for pl in tmpl["timing"]]
    time_results = await asyncio.gather(*time_tasks, return_exceptions=True)
    for r in time_results:
        if isinstance(r, dict):
            findings.append(r)
    return {"params_tested": sorted(set(t[1] for t in targets)),
            "tested": len(tasks) + len(time_tasks), "findings": findings}


async def m19(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["ssrf"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(6)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            t0 = time.monotonic()
            r = await client.get(test_url)
            dt = time.monotonic() - t0
            if "error" in r:
                return None
            for pat in tmpl["patterns"]:
                if re.search(pat, r["body"], re.I):
                    return {"type": "content", "param": param,
                            "payload": payload, "evidence": pat,
                            "url": test_url}
            if dt > 5.0 and ("127.0.0.1" in payload or "169.254" in payload):
                return {"type": "timing", "param": param,
                        "payload": payload, "delay": round(dt, 2)}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets
             for pl in tmpl["payloads"]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return {"params_tested": sorted(set(t[1] for t in targets)),
            "tested": len(tasks), "findings": findings}


async def m20(client, url, ctx):
    payloads = load_json("vuln_templates.json")["open_redirect"]["payloads"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(8)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            r = await client.get(test_url, allow_redirects=False)
            if "error" in r:
                return None
            if r["status"] in (301, 302, 303, 307, 308):
                loc = r["headers"].get("Location", "")
                if "evil.com" in loc or "google.com" in loc:
                    return {"param": param, "payload": payload,
                            "location": loc}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets for pl in payloads]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return {"params_tested": sorted(set(t[1] for t in targets)),
            "tested": len(tasks), "findings": findings}


async def m21(client, url, ctx):
    payloads = load_json("vuln_templates.json")["crlf"]["payloads"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    get_targets = _get_targets(targets)
    for (bu, param) in get_targets:
        for payload in payloads:
            test_url = inject_param(bu, param, payload)
            r = await client.get(test_url, allow_redirects=False)
            if "error" in r:
                continue
            h = {k.lower(): v for k, v in r["headers"].items()}
            joined = " ".join(f"{k}: {v}" for k, v in h.items())
            if "crlf=injected" in joined or "x-injected" in joined:
                findings.append({"param": param, "payload": payload,
                                 "evidence": joined[:200]})
            if "location" in h and "evil.com" in h["location"]:
                findings.append({"param": param, "payload": payload,
                                 "evidence": f"redirect via CRLF: {h['location']}"})
    return {"params_tested": sorted(set(t[1] for t in targets)),
            "tested": len(get_targets) * len(payloads),
            "findings": findings}


async def m22(client, url, ctx):
    tmpl = load_json("vuln_templates.json")["ssti"]
    targets = await _prep(client, url, ctx)
    if not targets:
        return {"note": "no params discovered", "findings": [], "tested": 0}

    findings = []
    sem = asyncio.Semaphore(8)
    get_targets = _get_targets(targets)

    async def test(base_url, param, payload):
        async with sem:
            test_url = inject_param(base_url, param, payload)
            r = await client.get(test_url)
            if "error" in r:
                return None
            for pat in tmpl["patterns"]:
                if re.search(pat, r["body"]):
                    return {"param": param, "payload": payload,
                            "evidence": pat, "url": test_url}
            return None

    tasks = [test(bu, p, pl) for (bu, p) in get_targets
             for pl in tmpl["payloads"]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            findings.append(r)
    return {"params_tested": sorted(set(t[1] for t in targets)),
            "tested": len(tasks), "findings": findings}


MODULES = [
    ("13_sqli", "SQL injection (error-based, auto params)", m13),
    ("14_sqli_blind", "SQL injection (blind: time + boolean, auto params)", m14),
    ("15_xss", "XSS (reflected, auto params)", m15),
    ("16_xss_blind", "Blind XSS (headers + auto params → callback)", m16),
    ("17_lfi", "LFI / path traversal (auto params)", m17),
    ("18_rce", "RCE / command injection (auto params)", m18),
    ("19_ssrf", "SSRF (auto params)", m19),
    ("20_redirect", "Open redirect (auto params)", m20),
    ("21_crlf", "CRLF injection (auto params)", m21),
    ("22_ssti", "SSTI (auto params)", m22),
]
