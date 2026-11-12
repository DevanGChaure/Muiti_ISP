#!/usr/bin/env python3
"""
Automated response: pushes/removes an inbound BGP filter on a router
to reject illegitimate announcements for the protected prefix space
from a specific neighbor (the direction the attack arrives from).
"""

import subprocess
import sys

APPLY_CONFIG = """configure terminal
ip prefix-list PROTECT-ENT seq 5 permit 10.10.0.0/16 le 24
route-map FILTER-HIJACK deny 10
match ip address prefix-list PROTECT-ENT
exit
route-map FILTER-HIJACK permit 20
exit
router bgp {own_as}
neighbor {neighbor_ip} route-map FILTER-HIJACK in
end
clear bgp ipv4 unicast {neighbor_ip} in
"""

REMOVE_CONFIG = """configure terminal
router bgp {own_as}
no neighbor {neighbor_ip} route-map FILTER-HIJACK in
end
clear bgp ipv4 unicast {neighbor_ip} in
"""

TARGETS = {
    "clab-bgp-multi-isp1": (65001, "10.0.2.2", 65002),
    "clab-bgp-multi-isp2": (65002, "10.0.3.2", 65099),
}


def run_vtysh_script(container, script_text):
    result = subprocess.run(
        ["docker", "exec", "-i", container, "vtysh"],
        input=script_text, capture_output=True, text=True
    )
    print(result.stdout)
    if result.stderr.strip():
        print("[stderr]", result.stderr)


def apply_filter(container):
    own_as, neighbor_ip, _ = TARGETS[container]
    run_vtysh_script(container, APPLY_CONFIG.format(own_as=own_as, neighbor_ip=neighbor_ip))
    print(f"[response] Filter applied on {container} (neighbor {neighbor_ip})")


def remove_filter(container):
    own_as, neighbor_ip, _ = TARGETS[container]
    run_vtysh_script(container, REMOVE_CONFIG.format(own_as=own_as, neighbor_ip=neighbor_ip))
    print(f"[response] Filter removed on {container} (neighbor {neighbor_ip})")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("apply", "remove"):
        print("Usage: respond.py <apply|remove> <container>")
        sys.exit(1)
    action, container = sys.argv[1], sys.argv[2]
    if container not in TARGETS:
        print(f"Unknown target: {container}")
        sys.exit(1)
    (apply_filter if action == "apply" else remove_filter)(container)
