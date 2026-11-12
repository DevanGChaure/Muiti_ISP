#!/usr/bin/env python3
"""
BGP Hijack Detector — polls multiple routers' BGP tables and compares
them against a known-good baseline for a protected address space.

Detects:
  1. Origin AS mismatch on a known prefix (e.g. equal-length hijack)
  2. Unauthorized more-specific prefixes inside protected space (e.g. /24 hijack)

Watches multiple vantage points, since different routers in the mesh
can disagree about which path is best (see Stage A findings).
"""

import subprocess
import json
import time
import ipaddress
import sys
from datetime import datetime

# ---- Configuration ----
VANTAGE_POINTS = [
    "clab-bgp-multi-isp1",
    "clab-bgp-multi-isp2",
]
POLL_INTERVAL = 3                       # seconds

PROTECTED_SPACE = ipaddress.ip_network("10.10.0.0/16")
BASELINE = {
    "10.10.0.0/16": 65010,              # prefix -> expected origin AS
}
LOG_FILE = "detector/alerts.log"

# Track previous alert state per (router, prefix) so we can also
# announce when a condition clears, not just when it starts.
_active_alerts = set()


def log(msg, alert=False):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {'[ALERT] ' if alert else ''}{msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def get_bgp_table(container):
    try:
        out = subprocess.run(
            ["docker", "exec", container, "vtysh", "-c",
             "show bgp ipv4 unicast json"],
            capture_output=True, text=True, timeout=5
        )
        return json.loads(out.stdout)
    except Exception as e:
        log(f"[{container}] Failed to fetch BGP table: {e}")
        return None


def origin_as(path_entry):
    path = path_entry.get("path", "").strip()
    if not path:
        return None  # locally originated at this router itself
    return int(path.split()[-1])


def best_path(paths):
    for p in paths:
        if p.get("bestpath"):
            return p
    return paths[0] if paths else None


def check(container, table):
    if not table or "routes" not in table:
        return

    routes = table["routes"]
    current_keys = set()

    for prefix, paths in routes.items():
        try:
            net = ipaddress.ip_network(prefix)
        except ValueError:
            continue

        if not net.subnet_of(PROTECTED_SPACE) and net != PROTECTED_SPACE:
            continue

        bp = best_path(paths)
        if bp is None:
            continue

        origin = origin_as(bp)
        key = (container, prefix)

        if prefix in BASELINE:
            expected = BASELINE[prefix]
            if origin != expected:
                current_keys.add(key)
                if key not in _active_alerts:
                    log(f"[{container}] Origin AS mismatch on {prefix}: "
                        f"expected AS{expected}, observed AS{origin}",
                        alert=True)
        else:
            current_keys.add(key)
            if key not in _active_alerts:
                log(f"[{container}] Unauthorized prefix inside "
                    f"{PROTECTED_SPACE}: {prefix} originated by AS{origin}",
                    alert=True)

    # Announce recovery for anything that was alerting and now isn't
    for key in list(_active_alerts):
        if key[0] == container and key not in current_keys:
            log(f"[{key[0]}] Cleared: {key[1]} back to normal")

    _active_alerts.difference_update(
        {k for k in _active_alerts if k[0] == container and k not in current_keys}
    )
    _active_alerts.update(current_keys)


def main():
    log(f"Detector started — watching {VANTAGE_POINTS} for {PROTECTED_SPACE}")
    log(f"Baseline: {BASELINE}")
    try:
        while True:
            for container in VANTAGE_POINTS:
                table = get_bgp_table(container)
                check(container, table)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        log("Detector stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
