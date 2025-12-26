#!/bin/bash
#
# Lumier Dynamics - Status Check Script
# Quick overview of system health
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check() {
    if $1 &>/dev/null; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
    fi
}

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                  LUMIER DYNAMICS - STATUS                     ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Services
echo -e "${BLUE}Services:${NC}"
check "systemctl is-active --quiet lumierproxy" "Lumier Proxy Service"
check "systemctl is-active --quiet dnsmasq" "DHCP Server (dnsmasq)"
echo ""

# Ports
echo -e "${BLUE}Ports:${NC}"
check "ss -tlnp | grep -q ':8080'" "Dashboard (8080)"
check "ss -tlnp | grep -q ':8888'" "Proxy (8888)"
check "ss -ulnp | grep -q ':67'" "DHCP (67)"
echo ""

# Network
echo -e "${BLUE}Network:${NC}"
AP_IFACE=$(grep "^interface=" /etc/dnsmasq.d/lumier-ap.conf 2>/dev/null | cut -d= -f2)
if [ -n "$AP_IFACE" ]; then
    check "ip addr show $AP_IFACE 2>/dev/null | grep -q '10.10.10.1'" "AP Interface ($AP_IFACE)"
else
    echo -e "${YELLOW}?${NC} AP Interface (not configured)"
fi
check "ping -c 1 -W 2 10.10.10.2" "AP Reachable (10.10.10.2)"
check "cat /proc/sys/net/ipv4/ip_forward | grep -q 1" "IP Forwarding"
check "iptables -t nat -L POSTROUTING -n | grep -q MASQUERADE" "NAT Rules"
echo ""

# DHCP Leases
echo -e "${BLUE}DHCP Leases:${NC}"
if [ -f /var/lib/misc/dnsmasq.leases ]; then
    LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
    echo "  Active leases: $LEASE_COUNT"
    if [ "$LEASE_COUNT" -gt 0 ]; then
        echo ""
        echo "  Recent devices:"
        tail -5 /var/lib/misc/dnsmasq.leases | while read line; do
            IP=$(echo "$line" | awk '{print $3}')
            MAC=$(echo "$line" | awk '{print $2}')
            NAME=$(echo "$line" | awk '{print $4}')
            echo "    $IP - $MAC ($NAME)"
        done
    fi
else
    echo "  No lease file found"
fi
echo ""

# Quick links
SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "${BLUE}Quick Links:${NC}"
echo "  Dashboard: http://$SERVER_IP:8080"
echo "  Logs:      sudo journalctl -u lumierproxy -f"
echo ""

# Recent errors
echo -e "${BLUE}Recent Errors (last 5):${NC}"
journalctl -u lumierproxy --since "1 hour ago" -p err --no-pager -q 2>/dev/null | tail -5 || echo "  None"
echo ""
