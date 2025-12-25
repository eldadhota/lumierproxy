#!/bin/bash
#
# LumierProxy Access Point Status Script
# Shows the current state of the AP network
#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DHCP_LEASE_FILE="/var/lib/lumier/dnsmasq.leases"

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }
print_ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
print_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
print_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
print_info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

# Load config
if [[ -f /etc/lumier/ap-config.env ]]; then
    source /etc/lumier/ap-config.env
else
    AP_INTERFACE="eth0"
    WAN_INTERFACE="wlan0"
    AP_GATEWAY="10.10.10.1"
fi

echo ""
echo "========================================"
echo "   LumierProxy AP Status"
echo "========================================"

# Check AP interface
print_header "Network Interfaces"

if ip link show "$AP_INTERFACE" &>/dev/null; then
    if ip addr show "$AP_INTERFACE" | grep -q "$AP_GATEWAY"; then
        print_ok "AP Interface ($AP_INTERFACE): UP with $AP_GATEWAY"
    else
        print_warn "AP Interface ($AP_INTERFACE): UP but no IP configured"
    fi
else
    print_fail "AP Interface ($AP_INTERFACE): NOT FOUND"
fi

if ip link show "$WAN_INTERFACE" &>/dev/null; then
    WAN_IP=$(ip addr show "$WAN_INTERFACE" | grep "inet " | awk '{print $2}' | head -1)
    if [[ -n "$WAN_IP" ]]; then
        print_ok "WAN Interface ($WAN_INTERFACE): $WAN_IP"
    else
        print_warn "WAN Interface ($WAN_INTERFACE): UP but no IP"
    fi
else
    print_fail "WAN Interface ($WAN_INTERFACE): NOT FOUND"
fi

# Check dnsmasq
print_header "DHCP Server (dnsmasq)"

if pgrep -f "dnsmasq.*dnsmasq-ap.conf" &>/dev/null; then
    print_ok "dnsmasq is running"
else
    print_fail "dnsmasq is NOT running"
fi

if [[ -f /etc/lumier/dnsmasq-ap.conf ]]; then
    print_ok "Config exists: /etc/lumier/dnsmasq-ap.conf"
else
    print_fail "Config missing: /etc/lumier/dnsmasq-ap.conf"
fi

# Check connected devices
print_header "Connected Devices (DHCP Leases)"

if [[ -f "$DHCP_LEASE_FILE" ]]; then
    DEVICE_COUNT=$(wc -l < "$DHCP_LEASE_FILE" 2>/dev/null || echo "0")
    if [[ "$DEVICE_COUNT" -gt 0 ]]; then
        print_ok "$DEVICE_COUNT device(s) connected:"
        echo ""
        printf "  %-20s %-18s %-15s\n" "HOSTNAME" "MAC" "IP"
        printf "  %-20s %-18s %-15s\n" "--------" "---" "--"
        while read -r timestamp mac ip hostname clientid; do
            printf "  %-20s %-18s %-15s\n" "${hostname:-unknown}" "$mac" "$ip"
        done < "$DHCP_LEASE_FILE"
    else
        print_info "No devices connected"
    fi
else
    print_warn "Lease file not found: $DHCP_LEASE_FILE"
fi

# Check iptables
print_header "Firewall (iptables)"

if iptables -L LUMIER_FORWARD &>/dev/null; then
    print_ok "LUMIER_FORWARD chain exists"
else
    print_fail "LUMIER_FORWARD chain missing"
fi

if iptables -L LUMIER_INPUT &>/dev/null; then
    print_ok "LUMIER_INPUT chain exists"
else
    print_fail "LUMIER_INPUT chain missing"
fi

if iptables -t nat -L LUMIER_NAT &>/dev/null; then
    print_ok "LUMIER_NAT chain exists"
else
    print_fail "LUMIER_NAT chain missing"
fi

# Check IP forwarding
if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
    print_ok "IP forwarding enabled"
else
    print_fail "IP forwarding disabled"
fi

# Check proxy redirect
print_header "Proxy Redirect Rules"

if iptables -t nat -L LUMIER_NAT -n 2>/dev/null | grep -q "REDIRECT.*8888"; then
    print_ok "HTTP/HTTPS redirected to port 8888"
else
    print_fail "Redirect rules not found"
fi

# Check systemd service
print_header "Systemd Service"

if systemctl is-enabled lumier-ap.service &>/dev/null; then
    print_ok "lumier-ap.service enabled"
else
    print_warn "lumier-ap.service not enabled"
fi

if systemctl is-active lumier-ap.service &>/dev/null; then
    print_ok "lumier-ap.service active"
else
    print_warn "lumier-ap.service not active"
fi

# Check proxy server
print_header "LumierProxy Server"

if pgrep -f "lumierproxy\|main.go" &>/dev/null || lsof -i :8888 &>/dev/null 2>&1; then
    print_ok "Proxy server running on port 8888"
else
    print_warn "Proxy server not detected on port 8888"
fi

if lsof -i :8080 &>/dev/null 2>&1; then
    print_ok "Dashboard running on port 8080"
else
    print_warn "Dashboard not detected on port 8080"
fi

echo ""
echo "========================================"
echo ""
