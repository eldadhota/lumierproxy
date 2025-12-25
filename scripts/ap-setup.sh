#!/bin/bash
#
# LumierProxy Access Point Setup Script
# This script configures your PC as a gateway for the UniFi AP
#
# Network: 10.10.10.0/24 (isolated from your office 192.168.50.x network)
# Gateway: 10.10.10.1 (your PC, on TP-Link UE300 adapter)
# DHCP:    10.10.10.100 - 10.10.10.200
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - EDIT THESE IF NEEDED
AP_INTERFACE="${AP_INTERFACE:-eth0}"       # TP-Link UE300 interface (connected to UniFi AP)
WAN_INTERFACE="${WAN_INTERFACE:-wlan0}"    # Your internet connection interface
AP_GATEWAY="10.10.10.1"                    # Gateway IP for AP network
AP_NETMASK="255.255.255.0"
AP_NETWORK="10.10.10.0/24"
DHCP_START="10.10.10.100"
DHCP_END="10.10.10.200"
PROXY_PORT="8888"
DHCP_LEASE_FILE="/var/lib/lumier/dnsmasq.leases"
DNSMASQ_CONFIG="/etc/lumier/dnsmasq-ap.conf"
LUMIER_DIR="/etc/lumier"

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_interfaces() {
    print_status "Detecting network interfaces..."
    echo ""
    echo "Available interfaces:"
    ip -br link show | grep -v "^lo"
    echo ""

    # Try to auto-detect TP-Link UE300 (usually shows as enx... or eth...)
    local tp_link=$(ip link show | grep -E "enx|eth" | grep -v "NO-CARRIER" | head -1 | awk -F': ' '{print $2}')
    if [[ -n "$tp_link" ]]; then
        print_status "Detected possible TP-Link adapter: $tp_link"
    fi

    echo ""
    read -p "Enter the TP-Link UE300 interface name (AP network) [$AP_INTERFACE]: " input
    AP_INTERFACE="${input:-$AP_INTERFACE}"

    read -p "Enter your internet/WAN interface name [$WAN_INTERFACE]: " input
    WAN_INTERFACE="${input:-$WAN_INTERFACE}"

    # Validate interfaces exist
    if ! ip link show "$AP_INTERFACE" &>/dev/null; then
        print_error "Interface $AP_INTERFACE does not exist!"
        exit 1
    fi
    if ! ip link show "$WAN_INTERFACE" &>/dev/null; then
        print_error "Interface $WAN_INTERFACE does not exist!"
        exit 1
    fi

    print_success "Using AP interface: $AP_INTERFACE"
    print_success "Using WAN interface: $WAN_INTERFACE"
}

install_dependencies() {
    print_status "Installing required packages..."
    apt-get update -qq
    apt-get install -y -qq dnsmasq iptables-persistent

    # Stop and disable system dnsmasq (we'll run our own instance)
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true

    print_success "Dependencies installed"
}

create_directories() {
    print_status "Creating directories..."
    mkdir -p "$LUMIER_DIR"
    mkdir -p "$(dirname $DHCP_LEASE_FILE)"
    touch "$DHCP_LEASE_FILE"
    print_success "Directories created"
}

configure_interface() {
    print_status "Configuring $AP_INTERFACE with IP $AP_GATEWAY..."

    # Remove any existing IP
    ip addr flush dev "$AP_INTERFACE" 2>/dev/null || true

    # Set static IP
    ip addr add "$AP_GATEWAY/24" dev "$AP_INTERFACE"
    ip link set "$AP_INTERFACE" up

    print_success "Interface configured"
}

create_dnsmasq_config() {
    print_status "Creating dnsmasq configuration..."

    cat > "$DNSMASQ_CONFIG" << EOF
# LumierProxy AP DHCP Configuration
# Generated: $(date)

# Interface to listen on
interface=$AP_INTERFACE

# Don't use /etc/resolv.conf
no-resolv

# Upstream DNS servers
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1

# DHCP range and lease time
dhcp-range=$DHCP_START,$DHCP_END,$AP_NETMASK,12h

# Gateway (this PC)
dhcp-option=3,$AP_GATEWAY

# DNS server (this PC, will forward to upstream)
dhcp-option=6,$AP_GATEWAY

# Lease file (monitored by LumierProxy for device detection)
dhcp-leasefile=$DHCP_LEASE_FILE

# Log DHCP requests
log-dhcp

# Don't read /etc/hosts
no-hosts

# Bind only to specified interface
bind-interfaces

# Don't forward short names
domain-needed

# Don't forward addresses in non-routed spaces
bogus-priv
EOF

    print_success "dnsmasq configuration created at $DNSMASQ_CONFIG"
}

configure_iptables() {
    print_status "Configuring iptables (STRICT MODE - no traffic leaks)..."

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-lumier-forward.conf

    # Clear existing rules for our chains
    iptables -t nat -F LUMIER_NAT 2>/dev/null || true
    iptables -t nat -X LUMIER_NAT 2>/dev/null || true
    iptables -F LUMIER_FORWARD 2>/dev/null || true
    iptables -X LUMIER_FORWARD 2>/dev/null || true
    iptables -F LUMIER_INPUT 2>/dev/null || true
    iptables -X LUMIER_INPUT 2>/dev/null || true

    # Create our chains
    iptables -t nat -N LUMIER_NAT
    iptables -N LUMIER_FORWARD
    iptables -N LUMIER_INPUT

    # === NAT TABLE ===
    # Redirect HTTP traffic to transparent proxy
    iptables -t nat -A LUMIER_NAT -i "$AP_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port $PROXY_PORT

    # Redirect HTTPS traffic to transparent proxy
    iptables -t nat -A LUMIER_NAT -i "$AP_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port $PROXY_PORT

    # NAT for traffic going to internet (after proxy processing)
    iptables -t nat -A LUMIER_NAT -o "$WAN_INTERFACE" -j MASQUERADE

    # Insert our NAT chain into PREROUTING and POSTROUTING
    iptables -t nat -I PREROUTING -j LUMIER_NAT
    iptables -t nat -I POSTROUTING -j LUMIER_NAT

    # === FILTER TABLE - INPUT ===
    # Allow DHCP requests from AP clients
    iptables -A LUMIER_INPUT -i "$AP_INTERFACE" -p udp --dport 67 -j ACCEPT

    # Allow DNS requests from AP clients
    iptables -A LUMIER_INPUT -i "$AP_INTERFACE" -p udp --dport 53 -j ACCEPT
    iptables -A LUMIER_INPUT -i "$AP_INTERFACE" -p tcp --dport 53 -j ACCEPT

    # Allow proxy connections from AP clients
    iptables -A LUMIER_INPUT -i "$AP_INTERFACE" -p tcp --dport $PROXY_PORT -j ACCEPT

    # Allow established connections
    iptables -A LUMIER_INPUT -i "$AP_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # DROP everything else from AP clients (prevents direct access attempts)
    iptables -A LUMIER_INPUT -i "$AP_INTERFACE" -j DROP

    # Insert our INPUT chain
    iptables -I INPUT -j LUMIER_INPUT

    # === FILTER TABLE - FORWARD ===
    # CRITICAL: Only allow forwarding from proxy server, not direct from clients
    # Allow established connections (responses to proxy requests)
    iptables -A LUMIER_FORWARD -i "$WAN_INTERFACE" -o "$AP_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow traffic from proxy (local) to internet
    iptables -A LUMIER_FORWARD -i "$AP_INTERFACE" -o "$WAN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # DROP all other forwarding (prevents clients from bypassing proxy)
    iptables -A LUMIER_FORWARD -i "$AP_INTERFACE" -j DROP

    # Insert our FORWARD chain
    iptables -I FORWARD -j LUMIER_FORWARD

    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4

    print_success "iptables configured (STRICT MODE - all traffic must go through proxy)"
}

start_dnsmasq() {
    print_status "Starting dnsmasq for DHCP..."

    # Kill any existing dnsmasq for our config
    pkill -f "dnsmasq.*dnsmasq-ap.conf" 2>/dev/null || true
    sleep 1

    # Start dnsmasq with our config
    dnsmasq --conf-file="$DNSMASQ_CONFIG" --pid-file=/var/run/lumier-dnsmasq.pid

    print_success "dnsmasq started"
}

create_systemd_service() {
    print_status "Creating systemd service for AP network..."

    cat > /etc/systemd/system/lumier-ap.service << EOF
[Unit]
Description=LumierProxy Access Point Network
After=network.target
Before=lumierproxy.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'ip addr add $AP_GATEWAY/24 dev $AP_INTERFACE 2>/dev/null || true; ip link set $AP_INTERFACE up; dnsmasq --conf-file=$DNSMASQ_CONFIG --pid-file=/var/run/lumier-dnsmasq.pid'
ExecStop=/bin/bash -c 'pkill -f "dnsmasq.*dnsmasq-ap.conf" || true; ip addr flush dev $AP_INTERFACE || true'

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable lumier-ap.service

    print_success "Systemd service created and enabled"
}

save_config() {
    print_status "Saving configuration..."

    cat > "$LUMIER_DIR/ap-config.env" << EOF
# LumierProxy AP Configuration
# Generated: $(date)
AP_INTERFACE=$AP_INTERFACE
WAN_INTERFACE=$WAN_INTERFACE
AP_GATEWAY=$AP_GATEWAY
AP_NETWORK=$AP_NETWORK
DHCP_START=$DHCP_START
DHCP_END=$DHCP_END
PROXY_PORT=$PROXY_PORT
DHCP_LEASE_FILE=$DHCP_LEASE_FILE
EOF

    print_success "Configuration saved to $LUMIER_DIR/ap-config.env"
}

show_status() {
    echo ""
    echo "========================================"
    echo "       AP NETWORK SETUP COMPLETE"
    echo "========================================"
    echo ""
    echo "Network Configuration:"
    echo "  AP Interface:    $AP_INTERFACE"
    echo "  WAN Interface:   $WAN_INTERFACE"
    echo "  Gateway IP:      $AP_GATEWAY"
    echo "  DHCP Range:      $DHCP_START - $DHCP_END"
    echo "  Proxy Port:      $PROXY_PORT"
    echo ""
    echo "Files Created:"
    echo "  DHCP Config:     $DNSMASQ_CONFIG"
    echo "  DHCP Leases:     $DHCP_LEASE_FILE"
    echo "  Saved Config:    $LUMIER_DIR/ap-config.env"
    echo ""
    echo "Security:"
    echo "  - All HTTP/HTTPS traffic redirected to proxy"
    echo "  - Direct internet access BLOCKED"
    echo "  - Only DHCP, DNS, and proxy traffic allowed"
    echo ""
    echo "Next Steps:"
    echo "  1. Connect UniFi AP to $AP_INTERFACE via PoE injector"
    echo "  2. Configure UniFi AP:"
    echo "     - SSID: AP-Prox"
    echo "     - Password: Drnda123"
    echo "     - AP IP: 10.10.10.2 (static)"
    echo "     - Gateway: 10.10.10.1"
    echo "  3. Start LumierProxy server"
    echo "  4. Connect a device to test"
    echo ""
}

# Main
main() {
    echo ""
    echo "========================================"
    echo "   LumierProxy AP Setup Script"
    echo "========================================"
    echo ""

    check_root
    detect_interfaces
    install_dependencies
    create_directories
    configure_interface
    create_dnsmasq_config
    configure_iptables
    start_dnsmasq
    create_systemd_service
    save_config
    show_status
}

# Run main function
main "$@"
