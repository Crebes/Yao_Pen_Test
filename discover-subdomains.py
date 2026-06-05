#!/usr/bin/env python3
"""
Subdomain discovery for *.yao.legal
1. Query crt.sh CT logs (passive — no traffic to target)
2. DNS brute-force common subdomains not in CT logs
3. Live HTTP check each — reports status code and server header
4. Writes subdomain_discovery.json for update-targets.py to consume
"""

import json, socket, ssl, urllib.request, urllib.error, re, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN   = "yao.legal"
TIMEOUT  = 8

WORDLIST = [
    "www", "app", "api", "admin", "backoffice", "portal", "dashboard",
    "staging", "stg", "dev", "test", "uat", "demo", "sandbox",
    "wopi", "docs", "mail", "smtp", "vpn", "remote",
    "uk", "aus", "us", "eu", "au", "ca",
    "auth", "login", "sso", "oauth",
    "cdn", "assets", "static", "media",
    "ws", "websocket",
    "grafana", "kibana", "status", "sentry",
    "jenkins", "ci",
    "internal", "intranet",
    "backoffice.staging", "app.staging", "app.stg",
    "backoffice.stg", "api.staging", "api.stg",
    "wopi.staging", "wopi.stg",
    "demo.staging", "demo.stg",
]

# ── crt.sh CT log query ────────────────────────────────────
def query_crtsh(domain, retries=3):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    for attempt in range(1, retries + 1):
        try:
            print(f"  crt.sh query (attempt {attempt}/{retries})...")
            req = urllib.request.Request(url, headers={"User-Agent": "PentestWizard/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
            names = set()
            for entry in data:
                for name in re.split(r"[\n,]", entry.get("name_value", "")):
                    name = name.strip().lstrip("*").lstrip(".")
                    if name.endswith(f".{domain}") or name == domain:
                        names.add(name.lower())
            print(f"  CT logs: {len(names)} names found")
            return names
        except Exception as e:
            print(f"  crt.sh attempt {attempt} failed: {e}")
            if attempt < retries:
                time.sleep(5)
    print("  crt.sh unavailable — using brute-force only")
    return set()

# ── DNS + HTTP checks ──────────────────────────────────────
def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def http_check(host):
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(
                url, method="HEAD",
                headers={"User-Agent": "PentestWizard/1.0 (authorised security test)"}
            )
            kw = {"timeout": TIMEOUT, "context": ctx} if scheme == "https" else {"timeout": TIMEOUT}
            with urllib.request.urlopen(req, **kw) as r:
                return scheme, r.status, r.headers.get("Server", ""), r.url
        except urllib.error.HTTPError as e:
            return scheme, e.code, e.headers.get("Server", ""), url
        except Exception:
            continue
    return None, None, "", ""

def check_host(host):
    ip = resolve(host)
    if not ip:
        return host, None, None, None, "", ""
    scheme, status, server, final_url = http_check(host)
    return host, ip, scheme, status, server, final_url

# ── Mode inference from hostname ───────────────────────────
def infer_mode(host):
    h = host.lower()
    if any(k in h for k in ("stg", "staging", "dev", "demo", "test", "uat", "sandbox")):
        return "staging"
    return "staging"   # user confirmed: run Hydra on everything

def infer_login_path(host):
    return "/auth/login"

# ── Main ───────────────────────────────────────────────────
def main():
    print(f"\n{'='*60}")
    print(f"  Subdomain discovery — *.{DOMAIN}")
    print(f"{'='*60}\n")

    ct_names    = query_crtsh(DOMAIN)
    brute_names = {f"{w}.{DOMAIN}" for w in WORDLIST}
    all_hosts   = sorted(ct_names | brute_names)

    print(f"\n  Total to check: {len(all_hosts)} "
          f"({len(ct_names)} CT + {len(brute_names - ct_names)} brute-force)\n")

    results = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check_host, h): h for h in all_hosts}
        for f in as_completed(futures):
            host, ip, scheme, status, server, final_url = f.result()
            if ip:
                results.append({
                    "host": host, "ip": ip, "scheme": scheme or "?",
                    "status": status, "server": server, "final_url": final_url,
                    "mode": infer_mode(host),
                    "login_path": infer_login_path(host),
                })
                marker = "✔" if status and status < 400 else "⚠" if status else "✘"
                print(f"  [{marker}] {host:<48} {ip:<18} HTTP {status or '?'}  {server}")
                sys.stdout.flush()

    # ── Summary ───────────────────────────────────────────
    live   = [r for r in results if r["status"] and r["status"] < 400]
    err5xx = [r for r in results if r["status"] and r["status"] >= 500]
    err4xx = [r for r in results if r["status"] and 400 <= r["status"] < 500]

    print(f"\n{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")
    print(f"  Resolved & responding : {len(results)}")
    print(f"  Live (2xx/3xx)        : {len(live)}")
    print(f"  4xx                   : {len(err4xx)}")
    print(f"  5xx / offline         : {len(err5xx)}")
    print(f"  DNS failed            : {len(all_hosts) - len(results)}")

    if live:
        print(f"\n  LIVE TARGETS:")
        for r in sorted(live, key=lambda x: x["host"]):
            print(f"    [{r['status']}] https://{r['host']}  {r['server']}")

    if err4xx:
        print(f"\n  4xx (auth/not found — may still be scannable):")
        for r in sorted(err4xx, key=lambda x: x["host"]):
            print(f"    [{r['status']}] https://{r['host']}")

    # Save full results
    out = "subdomain_discovery.json"
    json.dump({"domain": DOMAIN, "results": results}, open(out, "w"), indent=2)
    print(f"\n  Saved: {out}")
    print(f"  Run update-targets.py to merge new hosts into targets.json\n")

if __name__ == "__main__":
    main()
