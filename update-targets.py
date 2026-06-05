#!/usr/bin/env python3
"""
Merges subdomain_discovery.json into targets.json.
- Adds newly discovered live hosts not already in targets.json
- Never removes or modifies existing entries
- Skips hosts that returned 5xx (offline/down)
- Reports what was added
"""

import json, sys, os

SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
TARGETS_FILE   = os.path.join(SCRIPT_DIR, "targets.json")
DISCOVERY_FILE = os.path.join(SCRIPT_DIR, "subdomain_discovery.json")

def main():
    if not os.path.exists(DISCOVERY_FILE):
        print("  subdomain_discovery.json not found — run discover-subdomains.py first")
        sys.exit(1)

    discovery = json.load(open(DISCOVERY_FILE))
    targets   = json.load(open(TARGETS_FILE))

    existing_urls = {t["url"].rstrip("/").lower() for t in targets["targets"]}

    added = []
    skipped_offline = []
    skipped_existing = []

    for r in sorted(discovery["results"], key=lambda x: x["host"]):
        url = f"https://{r['host']}"
        url_lower = url.lower()

        if url_lower in existing_urls:
            skipped_existing.append(r["host"])
            continue

        # Skip hosts that are clearly down
        if r["status"] and r["status"] >= 500:
            skipped_offline.append((r["host"], r["status"]))
            continue

        # Skip if DNS resolved but no HTTP response at all
        if not r["status"]:
            continue

        entry = {
            "url":        url,
            "mode":       r["mode"],
            "login_path": r["login_path"],
            "notes":      f"Auto-discovered — HTTP {r['status']} {r.get('server','')}"
                          f"{' (REVIEW login_path)' if 'api' in r['host'] else ''}"
        }
        targets["targets"].append(entry)
        existing_urls.add(url_lower)
        added.append(entry)

    # Write back
    json.dump(targets, open(TARGETS_FILE, "w"), indent=2)

    print(f"\n  Targets update complete:")
    print(f"  Added   : {len(added)}")
    print(f"  Existing: {len(skipped_existing)}")
    print(f"  Offline : {len(skipped_offline)}")
    print(f"  Total in targets.json: {len(targets['targets'])}")

    if added:
        print(f"\n  New targets added:")
        for e in added:
            print(f"    {e['url']}  [{e['mode']}]  {e['notes']}")

    if skipped_offline:
        print(f"\n  Skipped (offline/5xx):")
        for h, st in skipped_offline:
            print(f"    https://{h}  [{st}]")

    if added:
        print(f"\n  NOTE: Review login_path for any api.* entries before running Hydra.")

if __name__ == "__main__":
    main()
