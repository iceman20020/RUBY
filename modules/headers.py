"""modules 10-12: security headers, cookies, cors."""

import asyncio
import re
from http.cookies import SimpleCookie

from .core import is_ok, split_set_cookie


HEADER_CHECKS = {
    "Strict-Transport-Security": "hsts",
    "Content-Security-Policy": "csp",
    "Content-Security-Policy-Report-Only": "csp_report",
    "X-Content-Type-Options": "xcto",
    "X-Frame-Options": "xfo",
    "Referrer-Policy": "referrer",
    "Permissions-Policy": "permissions",
    "Feature-Policy": "feature_policy",
    "X-XSS-Protection": "xxss",
    "Cross-Origin-Opener-Policy": "coop",
    "Cross-Origin-Resource-Policy": "corp",
    "Cross-Origin-Embedder-Policy": "coep",
    "Expect-CT": "expect_ct",
    "X-Permitted-Cross-Domain-Policies": "xpcdp",
    "X-Download-Options": "xdo",
    "X-DNS-Prefetch-Control": "xdp",
    "Server-Timing": "server_timing",
    "X-Robots-Tag": "robots_tag",
}


async def m10(client, url, ctx):
    r = await client.get(url)
    if not is_ok(r):
        return {"error": r.get("error", "request failed")}
    h = {k.lower(): v for k, v in r["headers"].items()}

    present, missing = {}, []
    for hdr, key in HEADER_CHECKS.items():
        if hdr.lower() in h:
            present[key] = h[hdr.lower()]
        else:
            missing.append(hdr)

    issues = []

    if "csp" in present:
        csp = present["csp"].lower()
        if "unsafe-inline" in csp:
            issues.append({"severity": "high",
                           "issue": "CSP allows unsafe-inline"})
        if "unsafe-eval" in csp:
            issues.append({"severity": "high",
                           "issue": "CSP allows unsafe-eval"})
        if "*" in csp:
            issues.append({"severity": "medium",
                           "issue": "CSP allows wildcard *"})
        if "data:" in csp and "script-src" in csp:
            issues.append({"severity": "medium",
                           "issue": "CSP allows data: for scripts"})
        if "http:" in csp:
            issues.append({"severity": "medium",
                           "issue": "CSP allows http: (mixed content)"})
    else:
        issues.append({"severity": "high", "issue": "no Content-Security-Policy"})

    if "csp_report" in present and "csp" not in present:
        issues.append({"severity": "low",
                       "issue": "CSP in report-only mode (not enforced)"})

    if "xfo" in present:
        xfo = present["xfo"].lower()
        if xfo not in ("deny", "sameorigin"):
            issues.append({"severity": "medium",
                           "issue": f"X-Frame-Options weak: {xfo}"})
    elif "csp" not in present:
        issues.append({"severity": "high",
                       "issue": "no X-Frame-Options and no CSP (clickjacking)"})

    if "hsts" in present:
        hsts = present["hsts"].lower()
        if "max-age=0" in hsts:
            issues.append({"severity": "high",
                           "issue": "HSTS max-age=0 (disabled)"})
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:
                issues.append({"severity": "low",
                               "issue": f"HSTS max-age short: {m.group(1)}"})
        if "includesubdomains" not in hsts:
            issues.append({"severity": "low",
                           "issue": "HSTS missing includeSubDomains"})
        if "preload" not in hsts:
            issues.append({"severity": "info", "issue": "HSTS missing preload"})
    else:
        issues.append({"severity": "medium", "issue": "no HSTS header"})

    if "xcto" in present:
        if present["xcto"].lower() != "nosniff":
            issues.append({"severity": "medium",
                           "issue": "X-Content-Type-Options not nosniff"})

    if "referrer" in present:
        ref = present["referrer"].lower()
        if ref in ("unsafe-url", "no-referrer-when-downgrade"):
            issues.append({"severity": "low",
                           "issue": f"Referrer-Policy weak: {ref}"})

    if "permissions" not in present and "feature_policy" not in present:
        issues.append({"severity": "info",
                       "issue": "no Permissions-Policy header"})

    if "server" in h and re.search(r"\d+\.\d+", h["server"]):
        issues.append({"severity": "info",
                       "issue": f"server header leaks version: {h['server']}"})
    if "x-powered-by" in h:
        issues.append({"severity": "low",
                       "issue": f"x-powered-by leaks tech: {h['x-powered-by']}"})

    return {"present": present, "missing": missing, "issues": issues}


async def m11(client, url, ctx):
    r = await client.get(url)
    if not is_ok(r):
        return {"error": r.get("error", "request failed")}

    raw = r["headers"].get("Set-Cookie", "")
    live_cookies = r.get("cookies") or {}
    if not raw and not live_cookies:
        return {"cookies": [], "note": "no Set-Cookie on root response"}

    cookies_out = []
    issues = []
    weak_names = {"session", "sessionid", "sid", "auth", "token", "jsessionid"}

    blocks = split_set_cookie(raw)
    parsed_any = False

    for block in blocks:
        sc = SimpleCookie()
        try:
            sc.load(block)
        except Exception:
            continue
        for name, morsel in sc.items():
            parsed_any = True
            httponly = bool(morsel.get("httponly"))
            secure = bool(morsel.get("secure"))
            samesite = morsel.get("samesite") or ""
            max_age = morsel.get("max-age") or ""
            domain = morsel.get("domain") or ""
            path = morsel.get("path") or ""

            cissues = []
            if not httponly:
                cissues.append("missing HttpOnly")
            if not secure:
                cissues.append("missing Secure")
            if not samesite:
                cissues.append("missing SameSite")
            elif samesite.lower() == "none" and not secure:
                cissues.append("SameSite=None without Secure")

            if name.lower() in weak_names:
                cissues.append(f"weak session name '{name}'")
            if len(morsel.value) < 16 and name.lower() in weak_names:
                cissues.append(f"short cookie value ({len(morsel.value)} chars)")
            if domain and domain.startswith("."):
                cissues.append(f"cookie domain wide: {domain}")
            if max_age:
                try:
                    if int(max_age) > 365 * 24 * 3600:
                        cissues.append("max-age > 1 year")
                except (TypeError, ValueError):
                    pass

            cookies_out.append({
                "name": name,
                "flags": {"httponly": httponly, "secure": secure,
                          "samesite": samesite, "max-age": max_age,
                          "domain": domain, "path": path},
                "issues": cissues, "length": len(morsel.value),
            })
            issues.extend(f"{name}: {i}" for i in cissues)

    if not parsed_any:
        for name, value in live_cookies.items():
            cissues = []
            if name.lower() in weak_names:
                cissues.append(f"weak session name '{name}'")
            if len(value) < 16 and name.lower() in weak_names:
                cissues.append(f"short cookie value ({len(value)} chars)")
            cissues.append("flags not readable from Set-Cookie header")
            cookies_out.append({"name": name, "flags": {},
                                "issues": cissues, "length": len(value)})
            issues.extend(f"{name}: {i}" for i in cissues)

    return {"cookies": cookies_out, "issues": issues, "count": len(cookies_out)}


async def m12(client, url, ctx):
    host = ctx.get("host") or ""
    tests = [
        {"Origin": "https://evil.com", "label": "arbitrary"},
        {"Origin": "null", "label": "null"},
        {"Origin": f"https://{host}.evil.com", "label": "suffix"},
        {"Origin": f"https://evil{host}", "label": "prefix"},
        {"Origin": f"https://{host}", "label": "self"},
        {"Origin": f"http://{host}", "label": "self-http"},
        {"Origin": f"https://sub.{host}", "label": "subdomain"},
        {"Origin": "https://evil.com:443", "label": "port-exploit"},
        {"Origin": f"https://evil.com\\{host}", "label": "backslash"},
    ]

    findings = []
    for t in tests:
        r = await client.get(url, headers=t, allow_redirects=False)
        if not is_ok(r):
            continue
        h = {k.lower(): v for k, v in r["headers"].items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "")
        acam = h.get("access-control-allow-methods", "")
        acah = h.get("access-control-allow-headers", "")

        if acao == "*" and acac.lower() == "true":
            findings.append({"origin": t["Origin"], "label": t["label"],
                             "issue": "wildcard + credentials (invalid per spec, still exploitable)",
                             "severity": "critical"})
        elif acao == "*":
            findings.append({"origin": t["Origin"], "label": t["label"],
                             "issue": "wildcard ACAO", "severity": "low"})
        elif t["Origin"] in acao or acao == t["Origin"]:
            if t["label"] in ("arbitrary", "null", "suffix", "prefix",
                              "port-exploit", "backslash"):
                findings.append({
                    "origin": t["Origin"], "label": t["label"],
                    "issue": "reflects attacker origin",
                    "credentials": acac, "methods": acam, "headers": acah,
                    "severity": "high" if acac.lower() == "true" else "medium",
                })
        elif acao == "null" and t["Origin"] == "null":
            findings.append({"origin": "null", "label": "null",
                             "issue": "accepts null origin",
                             "severity": "high"})

    preflight = await client.request("OPTIONS", url, headers={
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Custom-Header",
    })
    preflight_info = {}
    if is_ok(preflight):
        ph = {k.lower(): v for k, v in preflight["headers"].items()}
        preflight_info = {
            "acao": ph.get("access-control-allow-origin", ""),
            "acac": ph.get("access-control-allow-credentials", ""),
            "acam": ph.get("access-control-allow-methods", ""),
            "acah": ph.get("access-control-allow-headers", ""),
        }
        if preflight_info["acao"] and "evil.com" in preflight_info["acao"]:
            if preflight_info["acac"].lower() == "true":
                findings.append({
                    "origin": "preflight-evil.com",
                    "issue": "preflight accepts evil origin with credentials",
                    "severity": "critical",
                })

    return {"findings": findings, "tested": len(tests),
            "preflight": preflight_info}


MODULES = [
    ("10_headers", "Security headers audit (18 headers, 20 issue rules)", m10),
    ("11_cookies", "Cookie security audit (per-block SimpleCookie, live fallback)", m11),
    ("12_cors", "CORS misconfig (9 origin probes + preflight analysis)", m12),
]
