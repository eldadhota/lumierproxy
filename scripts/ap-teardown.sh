#!/bin/bash
#
# LumierProxy Access Point Teardown Script
# Removes all AP network configuration and restores original state
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root (use sudo)"
        exit 1
    fi
}

load_config() {
    if [[ -f /etc/lumier/ap-config.env ]]; then
        source /etc/lumier/ap-config.env
        print_status "Loaded config from /etc/lumier/ap-config.env"
    else
        print_warning "No config found, using defaults"
        AP_INTERFACE="eth0"
    fi
}

stop_dnsmasq() {
    print_status "Stopping dnsmasq..."
    pkill -f "dnsmasq.*dnsmasq-ap.conf" 2>/dev/null || true
    print_success "dnsmasq stopped"
}

remove_iptables() {
    print_status "Removing iptables rules..."

    # Remove jumps to our chains
    iptables -D INPUT -j LUMIER_INPUT 2>/dev/null || true
    iptables -D FORWARD -j LUMIER_FORWARD 2>/dev/null || true
    iptables -t nat -D PREROUTING -j LUMIER_NAT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -j LUMIER_NAT 2>/dev/null || true

    # Flush and delete our chains
    iptables -F LUMIER_INPUT 2>/dev/null || true
    iptables -X LUMIER_INPUT 2>/dev/null || true
    iptables -F LUMIER_FORWARD 2>/dev/null || true
    iptables -X LUMIER_FORWARD 2>/dev/null || true
    iptables -t nat -F LUMIER_NAT 2>/dev/null || true
    iptables -t nat -X LUMIER_NAT 2>/dev/null || true

    # Save clean rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

    print_success "iptables rules removed"
}

remove_interface_config() {
    print_status "Removing interface configuration..."
    if [[ -n "$AP_INTERFACE" ]]; then
        ip addr flush dev "$AP_INTERFACE" 2>/dev/null || true
    fi
    print_success "Interface configuration removed"
}

disable_service() {
    print_status "Disabling systemd service..."
    systemctl stop lumier-ap.service 2>/dev/null || true
    systemctl disable lumier-ap.service 2>/dev/null || true
    rm -f /etc/systemd/system/lumier-ap.service
    systemctl daemon-reload
    print_success "Systemd service removed"
}

cleanup_files() {
    print_status "Cleaning up files..."
    rm -f /etc/lumier/dnsmasq-ap.conf
    rm -f /etc/lumier/ap-config.env
    rm -f /var/run/lumier-dnsmasq.pid
    rm -f /etc/sysctl.d/99-lumier-forward.conf
    print_success "Files cleaned up"
}

main() {
    echo ""
    echo "========================================"
    echo "   LumierProxy AP Teardown Script"
    echo "========================================"
    echo ""

    check_root
    load_config
    stop_dnsmasq
    remove_iptables
    remove_interface_config
    disable_service
    cleanup_files

    echo ""
    print_success "AP network configuration removed"
    echo ""
    echo "Your original proxy server is still intact and running."
    echo "The UniFi AP will no longer receive DHCP from this server."
    echo ""
}

main "$@"
