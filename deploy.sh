#!/bin/bash
sudo ip link add name br-ent-lan type bridge 2>/dev/null
sudo ip link set br-ent-lan up
sudo containerlab deploy -t topology/bgp-multi.clab.yml
