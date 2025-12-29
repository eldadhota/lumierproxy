#!/bin/bash
#
# Lumier Dynamics - Uninstall Script
# Removes services and network configuration (preserves data)
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║              LUMIER DYNAMICS - UNINSTALL                      ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./uninstall.sh"
    exit 1
fi

echo -e "${YELLOW}WARNING: This will:${NC}"
echo "  - Stop and disable the Lumier service"
echo "  - Remove dnsmasq configuration"
echo "  - Remove network configuration"
echo ""
echo -e "${GREEN}Data will be preserved:${NC}"
echo "  - /opt/lumierproxy/device_data.json"
echo ""
read -p "Continue with uninstall? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Stopping services..."
systemctl stop lumierproxy 2>/dev/null || true
systemctl disable lumierproxy 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true

echo "Removing systemd service..."
rm -f /etc/systemd/system/lumierproxy.service
systemctl daemon-reload

echo "Removing network configuration..."
rm -f /etc/dnsmasq.d/lumier-ap.conf
rm -f /etc/netplan/99-lumier-ap.yaml 2>/dev/null || true

# Remove interface config from /etc/network/interfaces if present
if [ -f /etc/network/interfaces ]; then
    sed -i '/# Lumier AP Network/,/^$/d' /etc/network/interfaces 2>/dev/null || true
fi

echo "Removing iptables rules..."
AP_NETWORK="10.10.10.0/24"
iptables -t nat -D POSTROUTING -s $AP_NETWORK -j MASQUERADE 2>/dev/null || true

# Get USB interface and remove rules
AP_IFACE=$(ip link show | grep -oP 'enx[a-f0-9]+' | head -1)
if [ -n "$AP_IFACE" ]; then
    iptables -D FORWARD -i "$AP_IFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
fi

# Save cleaned iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

echo ""
echo -e "${GREEN}Uninstall complete!${NC}"
echo ""
echo "The following was preserved:"
echo "  - /opt/lumierproxy/ directory (with device data)"
echo "  - Installed packages (dnsmasq, iptables-persistent)"
echo ""
echo "To fully remove, run:"
echo "  sudo rm -rf /opt/lumierproxy"
echo "  sudo apt remove dnsmasq iptables-persistent"
echo ""
