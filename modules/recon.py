"""modules 1-4: basic recon, waf, sensitive files, dir fuzz."""

import asyncio
import json
import re
from urllib.parse import urljoin

from .core import is_ok, load_json, load_lines


TECH_SIGS = {
    "WordPress": {"body": ["wp-content", "wp-includes", "/wp-json/", "wp-emoji"],
                  "headers": [], "cookies": ["wordpress_", "wp-settings-"]},
    "Drupal": {"body": ["drupal", "sites/default/files", "x-generator: drupal"],
               "headers": ["x-generator"], "cookies": []},
    "Joomla": {"body": ["joomla", "/components/com_", "content=\"joomla"],
               "headers": [], "cookies": []},
    "Django": {"body": ["csrfmiddlewaretoken", "__admin__", "django-admin"],
               "headers": [], "cookies": ["csrftoken", "sessionid"]},
    "Flask": {"body": ["werkzeug"], "headers": ["server: werkzeug"],
              "cookies": ["session"]},
    "Express": {"body": [], "headers": ["x-powered-by: express"],
                "cookies": ["connect.sid"]},
    "Laravel": {"body": ["laravel_session", "xsrf-token"], "headers": [],
                "cookies": ["laravel_session", "XSRF-TOKEN"]},
    "Rails": {"body": ["_rails", "csrf-token"], "headers": ["x-runtime"],
              "cookies": ["_session_id", "_rails"]},
    "ASP.NET": {"body": ["asp.net", "__viewstate", "webresource.axd"],
                "headers": ["x-aspnet-version", "x-powered-by"],
                "cookies": ["ASP.NET_SessionId"]},
    "PHP": {"body": [], "headers": ["x-powered-by: php"],
            "cookies": ["PHPSESSID"]},
    "React": {"body": ["_next/static", "data-reactroot", "react"],
              "headers": [], "cookies": []},
    "Vue": {"body": ["__vue__", "data-v-", "vue.js"], "headers": [],
            "cookies": []},
    "Angular": {"body": ["ng-version", "angular"], "headers": [], "cookies": []},
    "Svelte": {"body": ["svelte-", "__svelte"], "headers": [], "cookies": []},
    "Nginx": {"body": [], "headers": ["server: nginx"], "cookies": []},
    "Apache": {"body": [], "headers": ["server: apache"], "cookies": []},
    "IIS": {"body": [], "headers": ["server: microsoft-iis"], "cookies": []},
    "Tomcat": {"body": [], "headers": ["server: apache-coyote"],
               "cookies": ["JSESSIONID"]},
    "Jetty": {"body": [], "headers": ["server: jetty"], "cookies": []},
    "Shopify": {"body": ["cdn.shopify.com", "shopify"],
                "headers": ["x-shopid", "x-shopify-stage"],
                "cookies": ["_shopify_s", "_shopify_y"]},
    "Magento": {"body": ["mage/cookies", "magento"], "headers": [],
                "cookies": ["frontend", "adminhtml"]},
    "Ghost": {"body": ["ghost-url", "content=\"ghost"], "headers": [],
              "cookies": []},
    "Discourse": {"body": ["discourse"], "headers": [], "cookies": ["_t"]},
    "Grafana": {"body": ["grafana"], "headers": [],
                "cookies": ["grafana_sess"]},
    "Kibana": {"body": ["kibana"], "headers": ["kbn-name"], "cookies": []},
    "Jenkins": {"body": ["jenkins"], "headers": ["x-jenkins"],
                "cookies": ["JSESSIONID"]},
    "GitLab": {"body": ["gitlab"], "headers": [],
               "cookies": ["_gitlab_session"]},
    "Nextcloud": {"body": ["nextcloud"], "headers": [],
                  "cookies": ["nc_sameSiteCookielax", "oc_sessionPassphrase"]},
    "Cloudflare": {"body": [], "headers": ["cf-ray", "server: cloudflare"],
                   "cookies": ["__cfduid", "cf_clearance"]},
    "Akamai": {"body": [],
               "headers": ["server: akamaighost", "x-akamai-transformed"],
               "cookies": []},
}


async def m01(client, url, ctx):
    r = await client.get(url)
    if not is_ok(r):
        return {"error": r.get("error", "request failed")}

    h = {k.lower(): v.lower() for k, v in r["headers"].items()}
    hstr = " ".join(f"{k}: {v}" for k, v in h.items())
    body = r["body"].lower()
    cookies = r["cookies"]
    cookie_names = " ".join(cookies.keys()).lower()
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")

    detected = []
    for name, sig in TECH_SIGS.items():
        score = 0
        hits = []
        for sig_body in sig.get("body", []):
            if sig_body in body:
                score += 2
                hits.append(f"body:{sig_body}")
        for sig_hdr in sig.get("headers", []):
            if sig_hdr in hstr:
                score += 2
                hits.append(f"header:{sig_hdr}")
        for sig_cookie in sig.get("cookies", []):
            if sig_cookie.lower() in cookie_names:
                score += 2
                hits.append(f"cookie:{sig_cookie}")
        if score >= 2:
            detected.append({"tech": name, "score": score, "evidence": hits})
    detected.sort(key=lambda x: -x["score"])

    extra = {}
    for path, key in [("/robots.txt", "robots"),
                      ("/sitemap.xml", "sitemap"),
                      ("/.well-known/security.txt", "security_txt"),
                      ("/humans.txt", "humans")]:
        rr = await client.get(url.rstrip("/") + path)
        if is_ok(rr) and rr["status"] == 200 and rr["length"] > 20:
            extra[key] = rr["body"][:2000]

    m = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
        r["body"], re.I)
    generator = m.group(1) if m else None

    meta_frameworks = {}
    for pat, name in [
        (r'<meta\s+name=["\']framework["\']\s+content=["\']([^"\']+)', "framework"),
        (r'<meta\s+name=["\']application-name["\']\s+content=["\']([^"\']+)', "app"),
    ]:
        mm = re.search(pat, r["body"], re.I)
        if mm:
            meta_frameworks[name] = mm.group(1)

    tm = re.search(r"<title[^>]*>([^<]+)", r["body"], re.I)
    title = tm.group(1).strip()[:100] if tm else None

    return {
        "status": r["status"],
        "server": server,
        "powered_by": powered,
        "length": r["length"],
        "title": title,
        "generator": generator,
        "meta": meta_frameworks,
        "tech": [d["tech"] for d in detected],
        "tech_evidence": detected,
        "cookies": list(cookies.keys()),
        "robots": extra.get("robots"),
        "sitemap": extra.get("sitemap"),
        "security_txt": extra.get("security_txt"),
        "humans": extra.get("humans"),
        "has_robots": "robots" in extra,
        "has_sitemap": "sitemap" in extra,
        "headers_present": list(h.keys()),
    }


WAF_PROBES = [
    ("sqli", "/?id=1' OR '1'='1"),
    ("xss", "/?q=<script>alert(1)</script>"),
    ("lfi", "/?file=../../../../etc/passwd"),
    ("rce", "/?cmd=;id"),
    ("sqli_union", "/?x=1 UNION SELECT NULL--"),
    ("traversal", "/?p=..%2f..%2fetc%2fpasswd"),
    ("xxe", "/?xml=<!DOCTYPE+foo+[<!ENTITY+bar+SYSTEM+%27file:///etc/passwd%27>]>"),
    ("crlf", "/?p=%0d%0aX-Injected:crlf"),
    ("ssti", "/?t={{7*7}}"),
    ("scanner", "/?x=){{"),
    ("cmd2", "/?cmd=|whoami"),
    ("admin_scan", "/admin/"),
    ("wp_scan", "/wp-login.php"),
    ("dot_git", "/.git/config"),
]


async def m02(client, url, ctx):
    sigs = load_json("waf_signatures.json")
    base = await client.get(url)
    if not is_ok(base):
        return {"error": base.get("error", "request failed")}

    bh = {k.lower(): v for k, v in base["headers"].items()}
    bc = base["cookies"]
    bb = base["body"].lower()
    bs = base["status"]

    probes_hit = []
    blocked = False
    block_status = None
    for label, p in WAF_PROBES:
        r = await client.get(url.rstrip("/") + p)
        if not is_ok(r):
            continue
        if r["status"] in (403, 406, 419, 501, 503, 1020) and bs not in (403, 406, 419, 501, 503, 1020):
            probes_hit.append({"probe": label, "status": r["status"], "path": p})
            blocked = True
            block_status = r["status"]
            break

    hits = []
    for name, sig in sigs.items():
        score = 0
        ev = []
        for hdr, pats in sig.get("headers", {}).items():
            if hdr in bh:
                if not pats:
                    score += 1
                    ev.append(f"header:{hdr}")
                else:
                    for p in pats:
                        if p and p.lower() in bh[hdr].lower():
                            score += 2
                            ev.append(f"header:{hdr}={p[:20]}")
                            break
        for c in sig.get("cookies", []):
            for k in bc:
                if c in k:
                    score += 2
                    ev.append(f"cookie:{k}")
                    break
        for bp in sig.get("body_patterns", []):
            if bp.lower() in bb:
                score += 2
                ev.append(f"body:{bp[:30]}")
                break
        if blocked and bs in sig.get("status_codes", []):
            score += 1
            ev.append("blocked-probe")
        if score >= 2:
            hits.append({"waf": name, "score": score, "evidence": ev})
    hits.sort(key=lambda x: -x["score"])

    return {
        "detected": [h["waf"] for h in hits],
        "details": hits,
        "blocked_on_probe": blocked,
        "block_status": block_status,
        "probes_hit": probes_hit,
        "probes_tested": len(WAF_PROBES),
    }


SENSITIVE_SIGNATURES = {
    "env_file": ["DB_PASSWORD", "DB_USER", "APP_KEY", "SECRET_KEY",
                 "API_KEY", "STRIPE_SECRET"],
    "git_config": ["[core]", "[remote", "url =", "repositoryformatversion"],
    "sql_dump": ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "MySQL dump",
                 "PostgreSQL database dump"],
    "ssh_key": ["-----BEGIN OPENSSH PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY",
                "-----BEGIN DSA PRIVATE KEY", "-----BEGIN EC PRIVATE KEY"],
    "aws_cred": ["aws_access_key_id", "aws_secret_access_key"],
    "dockerfile": ["FROM ", "RUN ", "CMD ", "EXPOSE "],
    "composer": ["\"require\"", "\"autoload\"", "composer"],
    "package_json": ["\"name\"", "\"version\"", "\"dependencies\""],
    "htpasswd": [":$apr1$", ":{SHA}", ":$2y$"],
    "htaccess": ["RewriteEngine", "AuthUserFile", "Order deny"],
    "nginx_conf": ["server_name", "proxy_pass", "listen "],
    "apache_conf": ["VirtualHost", "DocumentRoot", "ServerName"],
    "phpinfo": ["phpinfo()", "PHP Version", "Configuration File"],
    "actuator": ["\"status\":\"UP\"", "\"activeProfiles\"", "\"beans\""],
    "swagger": ["\"swagger\"", "\"openapi\"", "\"paths\""],
    "jenkins": ["Jenkins", "hudson", "job/"],
    "ds_store": ["Bud1"],
    "proc_environ": ["PATH=", "HOME=", "USER="],
}


async def m03(client, url, ctx):
    paths = load_lines("db_paths.txt")
    sem = asyncio.Semaphore(25)

    async def check(p):
        async with sem:
            r = await client.get(url.rstrip("/") + p)
            if not is_ok(r):
                return None
            st = r["status"]
            if st in (200, 206, 301, 302, 401, 403):
                if st == 200 and r["length"] < 20:
                    return None
                body_lower = r["body"][:2000].lower()
                matched_sig = None
                for sig_name, patterns in SENSITIVE_SIGNATURES.items():
                    for pat in patterns:
                        if pat.lower() in body_lower:
                            matched_sig = sig_name
                            break
                    if matched_sig:
                        break
                return {
                    "path": p, "status": st, "length": r["length"],
                    "type": r["headers"].get("Content-Type", ""),
                    "snippet": r["body"][:200].replace("\n", " ").replace("\r", ""),
                    "signature": matched_sig,
                }
            return None

    results = await asyncio.gather(*[check(p) for p in paths],
                                   return_exceptions=True)
    found = sorted([r for r in results if isinstance(r, dict)],
                   key=lambda x: x["status"])
    return {"scanned": len(paths), "found": found}


DIR_WORDS = [
    "admin", "administrator", "admin.php", "admin.html", "admin/", "admin/login",
    "administrator/index.php", "adminpanel", "adminpanel/", "controlpanel", "panel",
    "dashboard", "manage", "manager", "management", "console", "web-console",
    "cpanel", "whm", "plesk", "directadmin",
    "login", "signin", "signup", "register", "register.php", "logout",
    "user", "users", "user/login", "account", "profile", "settings",
    "password", "password-reset", "forgot", "forgot-password",
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/admin",
    "api/users", "api/config", "api/docs", "api/swagger.json",
    "api/openapi.json", "rest", "rest/v1", "rest/api",
    "graphql", "graphiql", "v1", "v2", "v3",
    "config", "configuration", "settings", "setup", "install",
    "install/", "installer", "installer.php", "install.php",
    "backup", "backups", "backup.zip", "backup.tar.gz", "backup.sql",
    "old", "old/", "old_site", "oldsite", "before", "prev", "previous",
    "archive", "archives",
    "dev", "development", "developers", "staging", "stage", "test", "tests",
    "beta", "alpha", "preview", "demo", "sandbox",
    "debug", "phpinfo.php", "info.php", "test.php", "test.html",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "administrator/components", "components", "modules", "plugins", "themes",
    "typo3", "typo3conf", "magento", "joomla", "drupal",
    "upload", "uploads", "upload.php", "download", "downloads",
    "files", "file", "file.php", "files.php", "dl.php",
    "assets", "static", "media", "images", "img", "css", "js", "fonts",
    "public", "private", "tmp", "temp", "logs", "log",
    "server-status", "server-info", "nginx_status", "nginx-status",
    "status", "health", "healthz", "ping", "metrics", "actuator",
    "actuator/health", "actuator/env", "actuator/mappings",
    "cgi-bin", "cgi-bin/", "cgi-bin/test.cgi",
    "docs", "documentation", "readme", "readme.html", "README.md",
    "CHANGELOG.md", "changelog", "license", "LICENSE",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
    "redoc", "api-docs",
    "robots.txt", "sitemap.xml", "security.txt", "crossdomain.xml",
    "clientaccesspolicy.xml", "humans.txt", "ads.txt",
    "traffic", "webstats", "stats", "analytics", "tracking",
    "webmail", "mail", "roundcube", "phpmyadmin", "pma", "adminer.php",
    "dbadmin", "mysql", "mysqladmin", "pgadmin", "phppgadmin",
    ".well-known", ".well-known/security.txt",
]


async def m04(client, url, ctx):
    sem = asyncio.Semaphore(30)

    random_path = "/this-should-not-exist-" + str(hash(url))[:8] + "/"
    ref = await client.get(url.rstrip("/") + random_path)
    ref_len = ref["length"] if is_ok(ref) else 0
    ref_status = ref["status"] if is_ok(ref) else 404

    async def probe(w):
        async with sem:
            r = await client.get(url.rstrip("/") + "/" + w)
            if not is_ok(r):
                return None
            if r["status"] in (200, 204, 301, 302, 401, 403):
                if r["status"] == ref_status and abs(r["length"] - ref_len) < 50:
                    return None
                return {"path": "/" + w, "status": r["status"],
                        "length": r["length"]}
            return None

    results = await asyncio.gather(*[probe(w) for w in DIR_WORDS],
                                   return_exceptions=True)
    found = sorted([r for r in results if isinstance(r, dict)],
                   key=lambda x: x["status"])
    return {"scanned": len(DIR_WORDS), "found": found, "soft404_filter": True}


MODULES = [
    ("01_basic_recon", "Basic recon (headers, 30 tech sigs, robots, sitemap, security.txt)", m01),
    ("02_waf", "WAF fingerprint (21 sigs + 14 attack probes)", m02),
    ("03_sensitive", "Sensitive file / db finder (~150 paths, signature match)", m03),
    ("04_dirfuzz", "Directory fuzzer (~190 paths, soft-404 filter)", m04),
]
