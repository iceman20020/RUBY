"""cross-module chaining — recon findings become inputs to later scans."""

from urllib.parse import urljoin


async def chain_after_recon(client, ctx, recon_result):
    if not isinstance(recon_result, dict):
        return
    seeds = ctx.setdefault("extra_seeds", [])
    for key in ("found", "endpoints"):
        for item in (recon_result.get(key) or []):
            if isinstance(item, dict) and item.get("path"):
                seeds.append(urljoin(ctx["target"], item["path"]))
    if recon_result.get("subdomains"):
        ctx["discovered_subdomains"] = recon_result["subdomains"]


async def chain_after_waf(client, ctx, waf_result):
    if not isinstance(waf_result, dict):
        return
    ctx["waf_detected"] = waf_result.get("detected") or []
    ctx["waf_blocked"] = bool(waf_result.get("blocked_on_probe"))


async def chain_after_sensitive(client, ctx, sens_result):
    if not isinstance(sens_result, dict):
        return
    leaked = []
    for f in sens_result.get("found") or []:
        path = f.get("path", "")
        snippet = f.get("snippet", "")
        if any(p in path.lower() for p in
               (".env", "config", "wp-config", "settings", "appsettings")):
            cred_markers = ["DB_PASSWORD", "DB_USER", "password", "secret",
                            "key=", "token"]
            if any(m.lower() in snippet.lower() for m in cred_markers):
                leaked.append({"file": path, "snippet": snippet[:200],
                               "note": "config file with credential markers"})
    if leaked:
        ctx["leaked_credentials"] = leaked


async def chain_after_ports(client, ctx, port_result):
    if not isinstance(port_result, dict):
        return
    open_ports = [p["port"] for p in port_result.get("open") or []]
    ctx["open_ports"] = open_ports
    services = []
    if 6379 in open_ports: services.append("redis")
    if 3306 in open_ports: services.append("mysql")
    if 5432 in open_ports: services.append("postgres")
    if 27017 in open_ports: services.append("mongodb")
    if 9200 in open_ports: services.append("elasticsearch")
    if 22 in open_ports: services.append("ssh")
    if 3389 in open_ports: services.append("rdp")
    ctx["services"] = services


async def chain_after_subdomains(client, ctx, sub_result):
    if not isinstance(sub_result, dict):
        return
    ctx["target_subdomains"] = sub_result.get("subdomains") or []


async def chain_after_headers(client, ctx, header_result):
    if not isinstance(header_result, dict):
        return
    ctx["missing_headers"] = header_result.get("missing") or []


async def chain_after_sqli(client, ctx, sqli_result):
    if not isinstance(sqli_result, dict):
        return
    confirmed = [f for f in sqli_result.get("verified") or []
                 if f.get("verification", {}).get("verdict") == "CONFIRMED"]
    if confirmed:
        ctx["confirmed_sqli"] = confirmed


async def chain_after_lfi(client, ctx, lfi_result):
    if not isinstance(lfi_result, dict):
        return
    confirmed = [f for f in lfi_result.get("verified") or []
                 if f.get("verification", {}).get("verdict") == "CONFIRMED"]
    if confirmed:
        ctx["confirmed_lfi"] = confirmed


async def chain_after_rce(client, ctx, rce_result):
    if not isinstance(rce_result, dict):
        return
    confirmed = [f for f in rce_result.get("verified") or []
                 if f.get("verification", {}).get("verdict") == "CONFIRMED"]
    if confirmed:
        ctx["confirmed_rce"] = confirmed


CHAIN_HOOKS = {
    "01_basic_recon": chain_after_recon,
    "02_waf": chain_after_waf,
    "03_sensitive": chain_after_sensitive,
    "05_subdomains": chain_after_subdomains,
    "06_ports": chain_after_ports,
    "10_headers": chain_after_headers,
    "13_sqli": chain_after_sqli,
    "17_lfi": chain_after_lfi,
    "18_rce": chain_after_rce,
}


async def run_hook(module_key, client, ctx, result):
    hook = CHAIN_HOOKS.get(module_key)
    if hook:
        try:
            await hook(client, ctx, result)
        except Exception:
            pass
