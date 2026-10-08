#!/bin/sh
ip addr add 10.10.0.2/24 dev eth1 2>/dev/null
exec /app/dhcp_server
