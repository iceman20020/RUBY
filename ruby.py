#!/usr/bin/env python3
"""RUBY — recon + vuln + verify + exploit, 30 modules, auto param discovery."""

import asyncio
import os
import sys
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    print("[!] install deps: pip install -r requirements.txt")
    sys.exit(1)

from modules.core import (
    C, HTTPClient, render_banner, section, kv, bullet, find_line,
    warn_line, err_line, info_line, get_params, host_of, scheme_of,
    startup_check,
)
from modules.crawler import discover
from modules.exploit import verify_and_maybe_exploit, verdict_line
from modules.chaining import run_hook
from modules import ALL_MODULES

MODULES = ALL_MODULES


def print_menu():
    section("modules")
    for i, (key, desc, _) in enumerate(MODULES, 1):
        print(f"  {C.DIM}\u2502{C.RST} {C.YEL}[{i:>2}]{C.RST} {desc}")
    print()
    print(f"  {C.DIM}\u2502{C.RST} {C.R1}[ a]{C.RST} run ALL")
    print(f"  {C.DIM}\u2502{C.RST} {C.R1}[ r]{C.RST} recommended (recon + waf + sens + top vulns)")
    print(f"  {C.DIM}\u2502{C.RST} {C.R1}[ e]{C.RST} EXPLOIT MODE (all modules + verify + extract)")
    print(f"  {C.DIM}\u2502{C.RST} {C.R1}[ g]{C.RST} aggressive mode (adds port scan + backup probes)")
    print(f"  {C.DIM}\u2502{C.RST} {C.R1}[ q]{C.RST} quit")
    print()


def parse_selection(raw, max_n):
    raw = raw.strip().lower()
    if raw in ("q", "quit", "exit"):
        return "quit", False, False
    if raw in ("e", "exploit"):
        return list(range(1, max_n + 1)), True, False
    if raw in ("g", "aggressive"):
        return list(range(1, max_n + 1)), False, True
    if raw in ("a", "all", ""):
        return list(range(1, max_n + 1)), False, False
    if raw in ("r", "rec", "recommended"):
        return [1, 2, 3, 10, 13, 14, 15, 16, 17, 18, 20, 29], False, False
    picks = set()
    for part in raw.replace(",", " ").split():
        try:
            n = int(part)
            if 1 <= n <= max_n:
                picks.add(n)
        except ValueError:
            pass
    return sorted(picks), False, False


def render(key, result):
    section(key)
    if not isinstance(result, dict):
        bullet(str(result))
        return
    if result.get("error"):
        err_line(f"error: {result['error']}")
        return

    if key == "01_basic_recon":
        kv("status", result.get("status"))
        kv("server", result.get("server") or "\u2014")
        kv("powered_by", result.get("powered_by") or "\u2014")
        kv("title", result.get("title") or "\u2014")
        kv("generator", result.get("generator") or "\u2014")
        kv("tech", ", ".join(result.get("tech") or []) or "\u2014", C.CYN)
        kv("length", result.get("length"))
        if result.get("has_robots"):
            warn_line("robots.txt present")
        if result.get("has_sitemap"):
            warn_line("sitemap.xml present")
        if result.get("security_txt"):
            find_line("security.txt present")

    elif key == "02_waf":
        det = result.get("detected") or []
        if det:
            for d in det:
                find_line(d, C.RED)
            for d in result.get("details") or []:
                if d.get("evidence"):
                    bullet(f"{d['waf']} (score {d['score']}): "
                           f"{', '.join(d['evidence'][:3])}")
        else:
            bullet("no WAF signature matched")
        if result.get("blocked_on_probe"):
            warn_line(f"blocked on attack probe (status {result.get('block_status')})")

    elif key in ("03_sensitive", "27_backups"):
        if result.get("found"):
            for f in result["found"]:
                sig = f.get("signature")
                tag = f"  [{sig}]" if sig else ""
                find_line(f"{f['status']}  {f['path']}  "
                          f"({f.get('length', '?')}b){tag}")
            _render_verdicts(result)
        else:
            note = result.get("note")
            if note:
                bullet(note)
            else:
                bullet(f"no matches "
                       f"({result.get('scanned', result.get('tested', '?'))} tested)")

    elif key == "04_dirfuzz":
        if result.get("found"):
            for f in result["found"]:
                find_line(f"{f['status']}  {f['path']}  "
                          f"({f.get('length', '?')}b)")
        else:
            bullet(f"no paths found ({result.get('scanned', '?')} tested)")

    elif key == "05_subdomains":
        kv("domain", result.get("domain"))
        kv("count", result.get("count"))
        for src, n in (result.get("sources") or {}).items():
            bullet(f"{src}: {n}")
        for s in result.get("subdomains", []):
            bullet(s)

    elif key == "06_ports":
        if result.get("note"):
            bullet(result["note"])
            return
        kv("host", result.get("host"))
        kv("scanned", result.get("scanned"))
        for p in result.get("open", []):
            b = f" \u2014 {p['banner']}" if p.get("banner") else ""
            find_line(f"port {p['port']}{b}")
        if result.get("services"):
            kv("services", ", ".join(result["services"]), C.CYN)
        if not result.get("open"):
            bullet("no common ports open")

    elif key == "07_ssl":
        for k in ("tls_version", "cipher", "subject", "issuer",
                  "notBefore", "notAfter", "days_until_expiry", "error"):
            if k in result:
                kv(k, str(result[k]))
        if result.get("san"):
            kv("san", ", ".join(result["san"][:5]))
        if result.get("weak_protocols"):
            warn_line(f"weak protocols: {', '.join(result['weak_protocols'])}")
        weak_c = result.get("weak_ciphers_accepted")
        if weak_c is True:
            cipher_name = result.get("weak_cipher_accepted")
            extra = f" ({cipher_name})" if cipher_name else ""
            warn_line(f"weak ciphers accepted{extra}")
        elif weak_c == "untested":
            bullet("weak cipher probe: untested (OpenSSL 3 rejects cipher string)")

    elif key == "08_dns":
        for rt in ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA",
                   "SRV", "DMARC", "_dmarc", "DKIM_default", "BIMI"):
            v = result.get(rt)
            if v:
                kv(rt, ", ".join(str(x) for x in v[:3]))
        kv("has_spf", result.get("has_spf"))
        kv("has_dmarc", result.get("has_dmarc"))
        if result.get("wildcard_dns"):
            warn_line("wildcard DNS detected")

    elif key == "09_methods":
        for r in result.get("results", []):
            bullet(f"{r['method']} \u2192 {r['status']}")
        if result.get("allow_header"):
            kv("Allow", result["allow_header"])
        for f in result.get("findings", []):
            warn_line(f"[{f.get('severity', '?')}] {f['method']}: {f['issue']}")
        for o in result.get("override_support", []):
            warn_line(f"method override via {o['header']} accepted")

    elif key == "10_headers":
        for k, v in (result.get("present") or {}).items():
            find_line(f"{k}: {v[:60]}")
        for m in result.get("missing", []):
            warn_line(f"missing: {m}")
        for i in result.get("issues", []):
            sev = i.get("severity", "?") if isinstance(i, dict) else ""
            msg = i.get("issue", i) if isinstance(i, dict) else i
            warn_line(f"[{sev}] {msg}")

    elif key == "11_cookies":
        for c in result.get("cookies", []):
            if c.get("issues"):
                warn_line(f"{c['name']}: {', '.join(c['issues'])}")
            else:
                find_line(f"{c['name']}: all flags set")
        if not result.get("cookies"):
            bullet(result.get("note", "no cookies"))

    elif key == "12_cors":
        for f in result.get("findings", []):
            warn_line(f"[{f.get('severity', '?')}] {f['origin']}: {f['issue']}")
        if not result.get("findings"):
            bullet("no CORS misconfig observed")

    elif key in ("13_sqli", "14_sqli_blind", "15_xss", "16_xss_blind",
                 "17_lfi", "18_rce", "19_ssrf", "20_redirect",
                 "21_crlf", "22_ssti", "23_xxe"):
        if result.get("params_tested"):
            kv("params", ", ".join(result["params_tested"][:15]), C.CYN)
        if result.get("endpoints_tested"):
            kv("endpoints", result["endpoints_tested"])
        kv("payloads fired",
           result.get("tested", result.get("delivered", "?")))
        _render_verdicts(result)

    elif key == "24_jwt":
        kv("tokens_found", result.get("tokens_found", 0))
        for a in result.get("analysis", []):
            bullet(f"{a['source']} alg={a['header'].get('alg')}")
            for iss in a.get("issues", []):
                warn_line(f"[{iss.get('severity', '?')}] "
                          f"{iss.get('issue', iss)}")

    elif key == "25_graphql":
        for f in result.get("findings", []):
            find_line(f"endpoint: {f['endpoint']}  "
                      f"({f.get('type_count', '?')} types)")
            if f.get("types"):
                bullet(f"types: {', '.join(f['types'][:10])}")
            if f.get("note"):
                bullet(f.get("note"))
        if not result.get("findings"):
            bullet(f"no GraphQL introspection "
                   f"({result.get('tested', '?')} endpoints tested)")

    elif key == "26_api":
        for e in result.get("endpoints", []):
            find_line(f"{e['status']}  {e['path']}  "
                      f"({e.get('length', '?')}b)")
        if not result.get("endpoints"):
            bullet(f"no API paths found ({result.get('tested', '?')} tested)")

    elif key == "28_host_header":
        for f in result.get("findings", []):
            warn_line(f"[{f.get('severity', '?')}] Host: {f['host']} "
                      f"\u2192 {f['issue']}")
        if not result.get("findings"):
            bullet("no host header injection observed")

    elif key == "29_csrf":
        kv("total_forms", result.get("total_forms"))
        kv("post_forms", result.get("post_forms"))
        kv("post_forms_without_csrf_token",
           result.get("post_forms_without_csrf_token"))
        kv("session_cookie_present", result.get("session_cookie_present"))
        kv("session_with_samesite", result.get("session_with_samesite"))
        kv("paths_checked", result.get("paths_checked"))
        for t in result.get("tokens_present", []):
            find_line(f"token marker: {t}")
        for c in result.get("session_cookies", []):
            tag = (f"SameSite={c['samesite']}" if c["samesite"]
                   else "no SameSite")
            bullet(f"{c['name']}  ({tag}, from {c['path']})")
        for f in result.get("findings", []):
            warn_line(f"[{f.get('severity', '?')}] {f['issue']}")

    elif key == "30_takeover":
        if result.get("findings"):
            for f in result.get("findings", []):
                warn_line(f"{f['service']}: {f['note']}  "
                          f"({f.get('host', '')})")
        else:
            bullet(f"no takeover signature "
                   f"(checked host + "
                   f"{result.get('subdomains_checked', 0)} sub(s))")

    else:
        bullet(str(result)[:500])


def _render_verdicts(result):
    verified = result.get("verified")
    if verified is None:
        for f in result.get("findings") or result.get("found") or []:
            find_line(str(f), C.RED)
        return

    conf = result.get("confirmed_count", 0)
    likely = result.get("likely_count", 0)
    exploit = result.get("exploited_count", 0)

    if conf:
        print(f"  {C.DIM}\u2502{C.RST} {C.BLD}{C.GRN}confirmed: {conf}{C.RST}")
    if likely:
        print(f"  {C.DIM}\u2502{C.RST} {C.BLD}{C.YEL}likely: {likely}{C.RST}")
    if exploit:
        print(f"  {C.DIM}\u2502{C.RST} {C.BLD}{C.RED}exploited: {exploit}{C.RST}")
    if not conf and not likely:
        print(f"  {C.DIM}\u2502{C.RST} {C.DIM}no confirmed findings "
              f"(retest failed){C.RST}")

    for f in verified:
        v = f.get("verification", {})
        verdict = v.get("verdict", "FAILED")
        label = f.get("param") or f.get("path") or f.get("url", "")[:60]
        evidence = v.get("evidence") or v.get("reason", "")
        if verdict == "CONFIRMED":
            verdict_line("CONFIRMED", f"{label}", evidence)
            exp = f.get("exploitation")
            if exp:
                if exp.get("extracted"):
                    for e in exp["extracted"]:
                        label2 = e.get('label', e.get('path', '?'))
                        val = e.get('value', e.get('snippet', ''))
                        verdict_line("EXPLOITED",
                                     f"extracted: {label2} = {val}"[:140])
                if exp.get("command_output"):
                    for c in exp["command_output"]:
                        verdict_line("EXPLOITED",
                                     f"{c['cmd']} \u2192 {c['output'][:100]}")
        elif verdict == "LIKELY":
            verdict_line("LIKELY", f"{label}", evidence)
        else:
            verdict_line("FAILED", f"{label}", evidence)

    wl = result.get("weak_login")
    if wl and wl.get("cracked"):
        for c in wl["cracked"]:
            verdict_line("EXPLOITED",
                         f"login cracked: {c['username']}:{c['password']}",
                         f"{c['url']}  ({c['evidence']})")


async def run_modules(target, picks, bxss_host=None, proxy=None, timeout=10,
                      do_exploit=False, aggressive=False):
    ctx = {
        "target": target,
        "host": host_of(target),
        "scheme": scheme_of(target),
        "params": get_params(target),
        "bxss_host": bxss_host,
        "aggressive": aggressive,
    }
    scope = f"{scheme_of(target)}://{host_of(target)}"
    async with HTTPClient(timeout=timeout, proxy=proxy,
                          auth=ctx.get("auth"),
                          scope_origin=scope) as client:
        needs_crawl = any(MODULES[n - 1][0] in (
            "13_sqli", "14_sqli_blind", "15_xss", "16_xss_blind",
            "17_lfi", "18_rce", "19_ssrf", "20_redirect",
            "21_crlf", "22_ssti"
        ) for n in picks)
        if needs_crawl and "discovery" not in ctx:
            print(f"\n{C.DIM}\u2502{C.RST} {C.R2}\u2192{C.RST} "
                  f"discovering params + endpoints \u2026")
            ctx["discovery"] = await discover(client, target, ctx)
            d = ctx["discovery"]
            info_line(f"crawled {d['pages_crawled']} page(s), "
                      f"found {d['endpoint_count']} endpoint(s), "
                      f"{len(d['all_params'])} unique param(s)")

        if do_exploit:
            print(f"\n  {C.BLD}{C.RED}\u26a0 EXPLOIT MODE \u2014 "
                  f"verification + extraction enabled{C.RST}")
        if aggressive:
            print(f"  {C.BLD}{C.YEL}\u26a0 AGGRESSIVE \u2014 "
                  f"port scan + backup probes enabled{C.RST}")

        for n in picks:
            key, desc, fn = MODULES[n - 1]
            print(f"\n{C.DIM}\u2502{C.RST} {C.R1}\u25c6{C.RST} "
                  f"{C.DIM}running {key} \u2026{C.RST}")
            try:
                result = await fn(client, target, ctx)
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}

            if isinstance(result, dict) and not result.get("error"):
                try:
                    result = await verify_and_maybe_exploit(
                        client, key, result, ctx, do_exploit=do_exploit)
                except Exception as e:
                    result["verify_error"] = str(e)

            render(key, result)

            try:
                await run_hook(key, client, ctx, result)
            except Exception:
                pass

        _print_intel(ctx)


def _print_intel(ctx):
    interesting = {
        "leaked_credentials": "Leaked credentials (config file)",
        "confirmed_sqli": "Confirmed SQLi (extraction ready)",
        "confirmed_lfi": "Confirmed LFI (file read ready)",
        "confirmed_rce": "Confirmed RCE (command exec ready)",
        "open_ports": "Open ports discovered",
        "services": "Services identified",
        "target_subdomains": "Subdomains discovered",
    }
    printed = False
    for key, label in interesting.items():
        val = ctx.get(key)
        if val:
            if not printed:
                section("intel gathered")
                printed = True
            n = len(val) if isinstance(val, list) else 1
            kv(label, f"{n} item(s)")


def prompt_target():
    print()
    raw = input(f"  {C.R1}\u25b8{C.RST} {C.WHT}target{C.RST} "
                f"{C.DIM}(example.com){C.RST}: ").strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw.rstrip("/")


def main():
    missing = startup_check()
    if missing:
        print(f"  {C.RED}\u2717 missing data file(s): "
              f"{', '.join(missing)}{C.RST}")
        print(f"  {C.DIM}  expected under data/{C.RST}")
        return

    render_banner()

    target = prompt_target()
    if not target:
        print(f"  {C.RED}\u2717 no target{C.RST}")
        return

    host = host_of(target)
    print(f"  {C.DIM}\u2502{C.RST} {C.R2}\u2192{C.RST} "
          f"host: {C.WHT}{host}{C.RST}")

    bxss = input(f"  {C.R1}\u25b8{C.RST} {C.WHT}blind-xss callback{C.RST} "
                 f"{C.DIM}(blank to skip){C.RST}: ").strip() or None

    print_menu()
    sel = input(f"  {C.R1}\u25b8{C.RST} {C.WHT}select{C.RST} "
                f"{C.DIM}(1-30, a=all, r=recommended, e=exploit, "
                f"g=aggressive){C.RST}: ").strip()
    picks, do_exploit, aggressive = parse_selection(sel, len(MODULES))
    if picks == "quit":
        print(f"  {C.DIM}bye.{C.RST}")
        return
    if not picks:
        print(f"  {C.RED}\u2717 no valid selection{C.RST}")
        return

    print()
    mode = f"{C.RED}EXPLOIT{C.RST}" if do_exploit else \
           f"{C.YEL}AGGRESSIVE{C.RST}" if aggressive else \
           f"{C.CYN}SCAN{C.RST}"
    info_line(f"mode: {mode}   target: {C.WHT}{host}{C.RST}   "
              f"modules: {len(picks)}")
    asyncio.run(run_modules(target, picks, bxss_host=bxss,
                            do_exploit=do_exploit, aggressive=aggressive))

    print()
    print(f"  {C.R1}\u25c6{C.RST} {C.DIM}done.{C.RST}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C.DIM}interrupted{C.RST}")
        sys.exit(0)
