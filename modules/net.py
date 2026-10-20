"""modules 5-9: subdomains, ports, ssl, dns, http methods."""

import asyncio
import json
import socket
import ssl

from .core import is_ok, USER_AGENTS


BRUTE_PREFIXES = [
    "www","mail","ftp","smtp","pop","pop3","imap","webmail","email",
    "ns1","ns2","ns3","ns4","dns","dns1","dns2",
    "admin","administrator","api","apis","dev","develop","staging","stage",
    "test","testing","qa","uat","prod","production","beta","alpha",
    "portal","vpn","remote","gateway","gw","proxy","edge","lb","load",
    "blog","shop","store","app","apps","m","mobile","wap",
    "cdn","static","assets","media","img","images","files","download",
    "secure","ssl","login","auth","sso","id",
    "git","gitlab","github","jenkins","ci","build","builds","deploy",
    "db","database","mysql","postgres","redis","mongo","mongodb",
    "monitor","monitoring","metrics","status","health",
    "docs","wiki","confluence","jira","support","help","helpdesk",
    "crm","erp","hr","intranet","extranet",
    "old","legacy","backup","backups","archive",
    "web1","web2","web3","server1","server2","host1","host2",
    "mx1","mx2","mail1","mail2",
]


async def m05(client, url, ctx):
    host = ctx.get("host") or ""
    if not host:
        return {"error": "no host in context"}

    domain = host
    if domain.count(".") > 1:
        parts = domain.split(".")
        domain = ".".join(parts[-2:])

    subs = set()
    sources = {}

    crt_subs = set()
    for attempt in range(3):
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            r = await client.get(
                crt_url,
                headers={"User-Agent": USER_AGENTS[attempt % len(USER_AGENTS)]},
                timeout=15,
                auth=False,
            )
        except Exception:
            r = {"error": "exception"}
        if is_ok(r) and r.get("status") == 200:
            try:
                for entry in json.loads(r["body"]):
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and "*" not in name:
                            crt_subs.add(name)
            except Exception:
                pass
            break
        await asyncio.sleep(1.5 * (attempt + 1))

    if crt_subs:
        sources["crt.sh"] = len(crt_subs)
        subs.update(crt_subs)

    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(20)
    brute_subs = set()

    async def resolve(p):
        async with sem:
            fqdn = f"{p}.{domain}"
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(fqdn, 0, family=socket.AF_INET,
                                     type=socket.SOCK_STREAM),
                    timeout=3.0,
                )
                if infos:
                    brute_subs.add(fqdn)
                    return fqdn
            except (socket.gaierror, asyncio.TimeoutError):
                return None
            except Exception:
                return None
            return None

    await asyncio.gather(*[resolve(p) for p in BRUTE_PREFIXES],
                         return_exceptions=True)

    if brute_subs:
        sources["brute"] = len(brute_subs)
        subs.update(brute_subs)

    return {
        "domain": domain,
        "subdomains": sorted(subs),
        "count": len(subs),
        "sources": sources,
        "brute_tested": len(BRUTE_PREFIXES),
    }


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3128, 3306,
    3389, 4443, 4444, 5000, 5432, 5555, 5601, 5900, 5984, 6379, 7001, 7002,
    7070, 8000, 8008, 8009, 8080, 8081, 8086, 8090, 8161, 8443, 8888, 9000,
    9042, 9090, 9200, 9300, 10000, 11211, 15672, 27017, 27018, 50000,
]

BANNER_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5432, 6379}

PORT_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 15672: "rabbitmq-mgmt",
}


async def _grab_banner(reader):
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=2.0)
        return data.decode(errors="replace").strip()[:100]
    except Exception:
        return ""


async def m06(client, url, ctx):
    host = ctx.get("host") or ""
    if not host:
        return {"error": "no host in context"}
    if not ctx.get("aggressive"):
        return {"note": "aggressive mode required (--aggressive) for port scan",
                "tested": 0, "open": []}

    sem = asyncio.Semaphore(80)

    async def try_port(p):
        async with sem:
            try:
                rd, wr = await asyncio.wait_for(
                    asyncio.open_connection(host, p), timeout=1.5)
                banner = await _grab_banner(rd) if p in BANNER_PORTS else ""
                wr.close()
                try:
                    await wr.wait_closed()
                except Exception:
                    pass
                return {"port": p, "banner": banner}
            except Exception:
                return None

    results = await asyncio.gather(
        *[try_port(p) for p in COMMON_PORTS], return_exceptions=True)
    open_ports = sorted([r for r in results if isinstance(r, dict)],
                        key=lambda x: x["port"])

    services = sorted({PORT_MAP[p["port"]] for p in open_ports
                       if p["port"] in PORT_MAP})

    return {
        "host": host,
        "scanned": len(COMMON_PORTS),
        "open": open_ports,
        "open_ports": [p["port"] for p in open_ports],
        "services": services,
    }


async def m07(client, url, ctx):
    host = ctx.get("host") or ""
    if not host:
        return {"error": "no host in context"}

    info = {"host": host, "port": 443}

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        rd, wr = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ssl_ctx,
                                    server_hostname=host),
            timeout=5)
        obj = wr.get_extra_info("ssl_object")
        cert = wr.get_extra_info("peercert")
        cipher = wr.get_extra_info("cipher")

        info["tls_version"] = obj.version() if obj else None
        info["cipher"] = cipher
        if cert:
            info["subject"] = dict(x[0] for x in cert.get("subject", []))
            info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            info["notBefore"] = cert.get("notBefore")
            info["notAfter"] = cert.get("notAfter")
            info["san"] = [s[1] for s in cert.get("subjectAltName", [])]
            try:
                from datetime import datetime
                exp = datetime.strptime(cert["notAfter"],
                                        "%b %d %H:%M:%S %Y %Z")
                info["days_until_expiry"] = (exp - datetime.utcnow()).days
            except Exception:
                pass
        wr.close()
        try:
            await wr.wait_closed()
        except Exception:
            pass

        weak = []
        for ver_name, ver in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]:
            try:
                weak_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                weak_ctx.check_hostname = False
                weak_ctx.verify_mode = ssl.CERT_NONE
                weak_ctx.minimum_version = ver
                weak_ctx.maximum_version = ver
                _, wr2 = await asyncio.wait_for(
                    asyncio.open_connection(host, 443, ssl=weak_ctx,
                                            server_hostname=host),
                    timeout=3)
                weak.append(ver_name)
                wr2.close()
                try:
                    await wr2.wait_closed()
                except Exception:
                    pass
            except Exception:
                pass
        info["weak_protocols"] = weak

        weak_cipher_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak_cipher_ctx.check_hostname = False
        weak_cipher_ctx.verify_mode = ssl.CERT_NONE
        ciphers_ok = True
        try:
            weak_cipher_ctx.set_ciphers(
                "RC4-SHA:DES-CBC3-SHA:NULL-SHA:@SECLEVEL=0")
        except ssl.SSLError:
            ciphers_ok = False

        if not ciphers_ok:
            info["weak_ciphers_accepted"] = "untested"
        else:
            try:
                _, wr3 = await asyncio.wait_for(
                    asyncio.open_connection(host, 443, ssl=weak_cipher_ctx,
                                            server_hostname=host),
                    timeout=3)
                c = wr3.get_extra_info("cipher")
                info["weak_cipher_accepted"] = c[0] if c else None
                info["weak_ciphers_accepted"] = True
                wr3.close()
                try:
                    await wr3.wait_closed()
                except Exception:
                    pass
            except Exception:
                info["weak_ciphers_accepted"] = False

    except Exception as e:
        info["error"] = str(e)
    return info


async def m08(client, url, ctx):
    host = ctx.get("host") or ""
    if not host:
        return {"error": "no host in context"}

    out = {"host": host}

    async def doh(name, rtype):
        try:
            r = await client.get(
                f"https://dns.google/resolve?name={name}&type={rtype}",
                timeout=8,
                auth=False,
            )
            if not is_ok(r):
                return None
            data = json.loads(r["body"])
            return [a.get("data") for a in data.get("Answer", [])]
        except Exception:
            return None

    for rt in ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA", "SRV"]:
        out[rt] = await doh(host, rt)

    base = host.split(".", 1)[1] if host.count(".") >= 1 else host

    out["DMARC"] = await doh(f"_dmarc.{base}", "TXT")
    out["_dmarc"] = await doh(f"_dmarc.{host}", "TXT")
    out["DKIM_default"] = await doh(f"default._domainkey.{base}", "TXT")
    out["DKIM_selector1"] = await doh(f"selector1._domainkey.{base}", "TXT")
    out["DKIM_selector2"] = await doh(f"selector2._domainkey.{base}", "TXT")
    out["BIMI"] = await doh(f"default._bimi.{base}", "TXT")
    out["SPF"] = out.get("TXT")

    spf_record = None
    if out.get("TXT"):
        for t in out["TXT"]:
            if isinstance(t, str) and t.startswith("v=spf1"):
                spf_record = t
                break
    out["spf_record"] = spf_record
    out["has_spf"] = spf_record is not None
    out["has_dmarc"] = bool(out.get("DMARC") or out.get("_dmarc"))

    random_sub = f"wildcard-test-{abs(hash(host)) % 999999}.{host}"
    wildcard = await doh(random_sub, "A")
    out["wildcard_dns"] = bool(wildcard)

    return out


SIMPLE_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


async def m09(client, url, ctx):
    allowed = []
    findings = []

    for m in SIMPLE_METHODS:
        r = await client.request(m, url)
        if not is_ok(r):
            continue
        st = r["status"]
        if st < 400 or st in (401, 403, 405):
            allowed.append({"method": m, "status": st})
        if m in ("PUT", "DELETE") and st < 300:
            findings.append({"method": m, "issue": f"{m} allowed (status {st})",
                             "severity": "high"})

    try:
        trace = await client.request("TRACE", url)
        if is_ok(trace) and trace["status"] < 400:
            allowed.append({"method": "TRACE", "status": trace["status"]})
            findings.append({"method": "TRACE",
                             "issue": "TRACE enabled (XST risk)",
                             "severity": "medium"})
    except Exception:
        pass

    override_tests = []
    for hdr in ["X-HTTP-Method-Override", "X-HTTP-Method",
                "X-Method-Override"]:
        r = await client.post(url, headers={hdr: "PUT"})
        if is_ok(r) and r["status"] < 300:
            override_tests.append({"header": hdr, "status": r["status"]})

    base = await client.get(url)
    allow_hdr = ""
    if is_ok(base):
        allow_hdr = base.get("headers", {}).get("Allow", "")

    return {
        "tested": SIMPLE_METHODS + ["TRACE"],
        "results": allowed,
        "allow_header": allow_hdr,
        "findings": findings,
        "override_support": override_tests,
    }


MODULES = [
    ("05_subdomains", "Subdomain enumeration (crt.sh + 100-prefix brute, async DNS)", m05),
    ("06_ports", "Port scanner (60 ports, banner grab, service ID, aggressive)", m06),
    ("07_ssl", "SSL/TLS analyzer (cert, cipher, weak protocols + ciphers)", m07),
    ("08_dns", "DNS recon DoH (A/AAAA/MX/TXT/NS/SOA/CNAME/CAA/SRV/DMARC/DKIM/BIMI/SPF)", m08),
    ("09_methods", "HTTP methods check (7 verbs + TRACE + override tests)", m09),
]
