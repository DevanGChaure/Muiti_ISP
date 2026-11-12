# Secure Multi-ISP Enterprise Network with BGP Hijack Detection, Network IDS & Automated Incident Response

## Overview

This project builds a realistic, multi-Autonomous-System network using real BGP routing software (FRRouting) inside Docker containers, orchestrated with Containerlab. It demonstrates:

1. Normal BGP routing and redundancy across two upstream ISPs
2. A working enterprise LAN with a **custom-built DHCP server in C++**
3. Multiple real, measurable **BGP hijack attacks**
4. A **Python-based detection system** that identifies hijacks in real time
5. An **automated incident response system** that applies BGP filters to block the attack and restore legitimate traffic

The goal is to show, end to end, how a routing-layer attack works, how it affects real traffic, and how it can be detected and mitigated automatically — not just in theory, but with a fully working, reproducible lab.

---

## Topology

| Router | AS | Role |
|---|---|---|
| ISP1 | 65001 | Transit provider |
| ISP2 | 65002 | Transit provider (also peers with the attacker) |
| Enterprise | 65010 | Dual-homed owner of `10.10.0.0/16` |
| Attacker | 65099 | Hijacker, connected only through ISP2 |
| Client | 65201 | Stand-in for "the Internet," generates real traffic |

### Addressing

| Link | Subnet |
|---|---|
| ISP1 ↔ Enterprise | 10.0.0.0/30 |
| ISP2 ↔ Enterprise | 10.0.1.0/30 |
| ISP1 ↔ ISP2 | 10.0.2.0/30 |
| ISP2 ↔ Attacker | 10.0.3.0/30 |
| ISP1 ↔ Client | 10.0.4.0/30 |

| Device | Address |
|---|---|
| Enterprise loopback | 10.10.0.1/16 |
| Client loopback | 198.51.100.1/24 |
| Enterprise LAN gateway (eth3) | 10.10.0.254/24 |
| dhcp-server | 10.10.0.2/24 |
| client1 / client2 | DHCP-leased from 10.10.0.100–120 |

---

## Prerequisites

- Docker
- [Containerlab](https://containerlab.dev/)
- Python 3
- A Linux host (tested on Kali Linux)

---

## Setup

### 1. Recreate the LAN bridge (required after every host reboot)

```bash
sudo ip link add name br-ent-lan type bridge 2>/dev/null
sudo ip link set br-ent-lan up
```

### 2. Build the custom DHCP server image

```bash
docker build -t enterprise-dhcp:latest dhcp-server/
```

### 3. Deploy the lab

```bash
cd ~/secure-enterprise-network
sudo containerlab deploy -t topology/bgp-multi.clab.yml
```

Wait ~20–30 seconds for BGP to converge.

### 4. Lease the LAN clients

```bash
docker exec -it clab-bgp-multi-client1 udhcpc -i eth1 -f -v -n -t 5 -T 3
docker exec -it clab-bgp-multi-client2 udhcpc -i eth1 -f -v -n -t 5 -T 3
```

### 5. Add a convenience shell helper

```bash
R() { docker exec -u 0 clab-bgp-multi-$1 "${@:2}"; }
```

---

## Verifying Normal Operation

```bash
R isp1 vtysh -c "show bgp summary"
R isp1 vtysh -c "show bgp ipv4 unicast 10.10.0.0/16"
R client ping -I 198.51.100.1 -c 3 10.10.0.1
```

Expected: all BGP sessions Established, Enterprise's prefix visible with the correct AS path, and the ping succeeding with `ttl=63`.

---

## Attacks

Controlled via `attack.sh`:

```bash
./attack.sh none          # withdraw everything, clean baseline
./attack.sh equal         # Stage A: /16 equal-length hijack
./attack.sh specific      # Stage B: /24 blackhole hijack
./attack.sh impersonate   # Stage C: /24 impersonation hijack
./attack.sh status        # show current attacker advertisements
```

### Stage A — Equal-length hijack (`/16`)
Announces the same prefix Enterprise owns. Outcome depends on BGP tiebreakers (AS path length, arrival order) — **non-deterministic**, demonstrated to win or lose depending on session timing.

### Stage B — More-specific blackhole (`/24`)
Announces a smaller, more specific prefix inside Enterprise's space. Wins on every router unconditionally via longest-prefix-match. Traffic is silently discarded (`ip route ... blackhole`) — **deterministic denial of service**.

### Stage C — More-specific impersonation (`/24`)
Same prefix-length trick as Stage B, but the attacker assigns an address inside the stolen range to its own loopback, causing its kernel to answer traffic as if it were the real destination — **deterministic interception**, with the only forensic trace being a one-hop TTL difference (62 vs. the baseline 63).

---

## Detection

```bash
python3 detector/detector.py
```

Polls BGP tables on ISP1 and ISP2 every 3 seconds and checks:
1. Whether the origin AS of the known `10.10.0.0/16` prefix has changed
2. Whether any new, unauthorized prefix has appeared inside that address space

Alerts are printed and logged to `detector/alerts.log`.

---

## Automated Incident Response

```bash
python3 detector/respond.py apply clab-bgp-multi-isp1
python3 detector/respond.py remove clab-bgp-multi-isp1
```

Applies (or removes) an inbound BGP route-map on the specified router, rejecting any announcement for `10.10.0.0/16` or more specific prefixes arriving from the attacker's direction. This restores legitimate routing and traffic flow even while the attack is still active.

---

## Running the Full Demo

```bash
./demo.sh
```

Walks through: baseline verification → DHCP lease demonstration → attack launch → traffic impact → detection → automated response → recovery confirmation, pausing between each step.

---

## Key Findings

- **Equal-length hijacks are a race condition**, not a reliable attack — their success depends on BGP session convergence timing, not configuration.
- **More-specific hijacks are deterministic and always succeed** at the routing layer, regardless of AS path length, due to longest-prefix-match being evaluated before any other BGP comparison.
- **A detector that only checks the known prefix's origin is blind to more-specific hijacks** — the `/24` in Stage B/C never changes the `/16`'s origin, so detection logic must also watch for entirely new, unauthorized prefixes.
- **TTL is a cheap, passive forensic signal** — an impersonation attack is otherwise packet-perfect, but the extra hop through the attacker's network is visible in every reply's TTL.
- **BGP filtering restores legitimate routing without needing to stop the attacker** — the response blocks the lie at the listening router, not at the source.

---

## Syllabus Mapping

| Topic | Where demonstrated |
|---|---|
| OSI/TCP-IP models | Full verification ladder: link, network, transport, application |
| CIDR, subnetting | `/30` point-to-point links, `/16` and `/24` prefixes |
| Routing in the Internet (BGP) | Core of the entire project |
| TCP three-way handshake | BGP sessions over TCP/179 |
| ICMP, ARP | Ping testing, address resolution on the LAN |
| DHCP | Custom C++ DHCP server, full DORA exchange |
| Network IDS concepts | Detection script, packet captures |

---

## Author

Built by Devang, B.Tech CSE, MIT-WPU, as a networking and cybersecurity project combining BGP routing, systems programming, and automated defense.
