#!/bin/bash
#
# Lumier Dynamics - Network Setup Script
# This script configures the USB ethernet adapter and DHCP for the Access Point network
#
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ ⚠️  SECURITY WARNING - DEPRECATED SCRIPT                                    │
# │                                                                             │
# │ This script enables NAT and IP forwarding, which allows devices to bypass  │
# │ the proxy and access the internet directly. For a secure setup that        │
# │ FORCES all traffic through the proxy, use:                                 │
# │                                                                             │
# │   sudo ./scripts/ap-setup.sh                                               │
# │                                                                             │
# │ Only use this script if you specifically need NAT/direct internet access.  │
# └─────────────────────────────────────────────────────────────────────────────┘
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default configuration
AP_NETWORK="10.10.10.0/24"
AP_GATEWAY="10.10.10.1"
AP_NETMASK="255.255.255.0"
DHCP_RANGE_START="10.10.10.100"
DHCP_RANGE_END="10.10.10.200"
DHCP_LEASE_TIME="12h"

# Print functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
prompt() { echo -e "${CYAN}[?]${NC} $1"; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo ./setup-network.sh)"
    fi
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              LUMIER DYNAMICS - NETWORK SETUP                  ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print security warning
print_security_warning() {
    echo -e "${YELLOW}"
    echo "┌───────────────────────────────────────────────────────────────┐"
    echo "│ ⚠️  WARNING: This script enables NAT/IP forwarding            │"
    echo "│                                                               │"
    echo "│ Devices can BYPASS the proxy and access internet directly.   │"
    echo "│ For a secure setup that forces proxy usage, use instead:     │"
    echo "│                                                               │"
    echo "│   sudo ./scripts/ap-setup.sh                                 │"
    echo "│                                                               │"
    echo "└───────────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
    echo ""
    read -p "Continue anyway? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted. Use ./scripts/ap-setup.sh for secure setup."
        exit 0
    fi
}

# Detect USB ethernet adapter
detect_usb_adapter() {
    info "Detecting USB ethernet adapters..."

    # List all network interfaces
    echo ""
    echo "Available network interfaces:"
    echo "─────────────────────────────"

    # Find likely USB ethernet adapters (usually enx* or eth1+)
    USB_ADAPTERS=()
    while IFS= read -r line; do
        iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        # Skip loopback and common primary interfaces
        if [[ "$iface" != "lo" ]] && [[ "$iface" != "" ]]; then
            # Get MAC and state
            mac=$(ip link show "$iface" 2>/dev/null | grep -oP 'link/ether \K[^ ]+' || echo "N/A")
            state=$(ip link show "$iface" 2>/dev/null | grep -oP 'state \K\w+' || echo "UNKNOWN")

            # Check if it looks like a USB adapter
            if [[ "$iface" == enx* ]] || [[ "$iface" == eth1 ]] || [[ "$iface" == usb* ]]; then
                USB_ADAPTERS+=("$iface")
                echo -e "  ${GREEN}*${NC} $iface (MAC: $mac, State: $state) ${GREEN}[LIKELY USB ADAPTER]${NC}"
            else
                echo "    $iface (MAC: $mac, State: $state)"
            fi
        fi
    done < <(ip link show | grep "^[0-9]")

    echo ""

    # If only one USB adapter found, suggest it
    if [ ${#USB_ADAPTERS[@]} -eq 1 ]; then
        SUGGESTED_IFACE="${USB_ADAPTERS[0]}"
        info "Detected USB adapter: $SUGGESTED_IFACE"
    elif [ ${#USB_ADAPTERS[@]} -gt 1 ]; then
        warn "Multiple USB adapters detected. Please select one."
        SUGGESTED_IFACE="${USB_ADAPTERS[0]}"
    else
        warn "No USB adapter auto-detected. Please enter the interface name manually."
        SUGGESTED_IFACE=""
    fi
}

# Get user configuration
get_configuration() {
    prompt "Enter the USB ethernet interface name"
    if [ -n "$SUGGESTED_IFACE" ]; then
        read -p "  [$SUGGESTED_IFACE]: " USB_INTERFACE
        USB_INTERFACE=${USB_INTERFACE:-$SUGGESTED_IFACE}
    else
        read -p "  : " USB_INTERFACE
    fi

    if [ -z "$USB_INTERFACE" ]; then
        error "Interface name is required"
    fi

    # Verify interface exists
    if ! ip link show "$USB_INTERFACE" &> /dev/null; then
        error "Interface '$USB_INTERFACE' does not exist"
    fi

    echo ""
    info "Network Configuration:"
    echo "  Interface:   $USB_INTERFACE"
    echo "  Gateway IP:  $AP_GATEWAY"
    echo "  Network:     $AP_NETWORK"
    echo "  DHCP Range:  $DHCP_RANGE_START - $DHCP_RANGE_END"
    echo ""

    read -p "Proceed with this configuration? (Y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
}

# Configure static IP on interface
configure_interface() {
    info "Configuring interface $USB_INTERFACE..."

    # Bring interface down first
    ip link set "$USB_INTERFACE" down 2>/dev/null || true

    # Remove any existing IP
    ip addr flush dev "$USB_INTERFACE" 2>/dev/null || true

    # Set static IP
    ip addr add "$AP_GATEWAY/24" dev "$USB_INTERFACE"
    ip link set "$USB_INTERFACE" up

    # Wait for interface to come up
    sleep 2

    # Verify
    if ip addr show "$USB_INTERFACE" | grep -q "$AP_GATEWAY"; then
        success "Interface configured with IP $AP_GATEWAY"
    else
        error "Failed to configure interface"
    fi
}

# Make interface configuration persistent
persist_interface() {
    info "Making interface configuration persistent..."

    # Check if using netplan (Ubuntu 18.04+)
    if [ -d /etc/netplan ]; then
        cat > /etc/netplan/99-lumier-ap.yaml << EOF
network:
  version: 2
  ethernets:
    $USB_INTERFACE:
      addresses:
        - $AP_GATEWAY/24
      dhcp4: no
EOF
        chmod 600 /etc/netplan/99-lumier-ap.yaml
        netplan apply 2>/dev/null || warn "Netplan apply failed, but config saved"
        success "Netplan configuration created"

    # Check if using ifupdown (Debian/older Ubuntu)
    elif [ -f /etc/network/interfaces ]; then
        if ! grep -q "$USB_INTERFACE" /etc/network/interfaces; then
            cat >> /etc/network/interfaces << EOF

# Lumier AP Network
auto $USB_INTERFACE
iface $USB_INTERFACE inet static
    address $AP_GATEWAY
    netmask $AP_NETMASK
EOF
            success "Added to /etc/network/interfaces"
        else
            warn "Interface already in /etc/network/interfaces, skipping"
        fi
    else
        warn "Could not determine network configuration system"
        warn "You may need to manually persist the interface configuration"
    fi
}

# Configure dnsmasq for DHCP
configure_dhcp() {
    info "Configuring DHCP server (dnsmasq)..."

    # Create dnsmasq config for AP
    cat > /etc/dnsmasq.d/lumier-ap.conf << EOF
# Lumier Dynamics AP Network Configuration
# Generated by setup-network.sh

# Interface to listen on
interface=$USB_INTERFACE

# Don't use /etc/resolv.conf
no-resolv

# Upstream DNS (Google DNS)
server=8.8.8.8
server=8.8.4.4

# DHCP Configuration
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$AP_NETMASK,$DHCP_LEASE_TIME

# Gateway
dhcp-option=3,$AP_GATEWAY

# DNS Server (this server)
dhcp-option=6,$AP_GATEWAY

# WPAD for automatic proxy configuration
dhcp-option=252,http://$AP_GATEWAY:8080/wpad.dat

# Domain
domain=lumier.local

# Log DHCP queries (helpful for debugging)
log-dhcp

# Don't listen on other interfaces
except-interface=lo
bind-interfaces

# Static assignments can be added here:
# dhcp-host=aa:bb:cc:dd:ee:ff,10.10.10.50,device-name
EOF

    success "DHCP configuration created"

    # Restart dnsmasq
    systemctl restart dnsmasq
    systemctl enable dnsmasq

    # Verify dnsmasq is running
    sleep 2
    if systemctl is-active --quiet dnsmasq; then
        success "DHCP server started"
    else
        error "DHCP server failed to start. Check: journalctl -u dnsmasq"
    fi
}

# Configure iptables for NAT
configure_iptables() {
    info "Configuring iptables for NAT..."

    # Get the main internet-facing interface
    MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

    if [ -z "$MAIN_IFACE" ]; then
        warn "Could not detect main interface. Using eth0 as fallback."
        MAIN_IFACE="eth0"
    fi

    info "Main interface detected: $MAIN_IFACE"

    # Flush existing NAT rules for AP network
    iptables -t nat -D POSTROUTING -s $AP_NETWORK -o "$MAIN_IFACE" -j MASQUERADE 2>/dev/null || true

    # Add NAT rule
    iptables -t nat -A POSTROUTING -s $AP_NETWORK -o "$MAIN_IFACE" -j MASQUERADE

    # Allow forwarding
    iptables -D FORWARD -i "$USB_INTERFACE" -o "$MAIN_IFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$MAIN_IFACE" -o "$USB_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    iptables -A FORWARD -i "$USB_INTERFACE" -o "$MAIN_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$MAIN_IFACE" -o "$USB_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Save iptables rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4

    # For Debian/Ubuntu with iptables-persistent
    if [ -d /etc/iptables ] && command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    fi

    success "NAT configured"
}

# Enable IP forwarding
enable_forwarding() {
    info "Enabling IP forwarding..."

    echo 1 > /proc/sys/net/ipv4/ip_forward

    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    sysctl -p > /dev/null 2>&1

    success "IP forwarding enabled"
}

# Test connectivity
test_connectivity() {
    info "Testing network connectivity..."

    echo ""
    echo "Network Status:"
    echo "───────────────"
    echo ""

    # Interface status
    echo "Interface $USB_INTERFACE:"
    ip addr show "$USB_INTERFACE" | grep "inet " | awk '{print "  IP: " $2}'
    echo ""

    # DHCP status
    echo "DHCP Server:"
    if systemctl is-active --quiet dnsmasq; then
        echo -e "  Status: ${GREEN}Running${NC}"
    else
        echo -e "  Status: ${RED}Not Running${NC}"
    fi
    echo ""

    # Check for connected devices
    LEASES=$(cat /var/lib/lumier/dnsmasq.leases 2>/dev/null | wc -l)
    echo "DHCP Leases: $LEASES active"
    echo ""

    # NAT status
    echo "NAT Rules:"
    iptables -t nat -L POSTROUTING -n | grep -q "MASQUERADE" && echo -e "  Status: ${GREEN}Configured${NC}" || echo -e "  Status: ${RED}Missing${NC}"
    echo ""
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              NETWORK SETUP COMPLETE!                          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Network Configuration Summary:"
    echo "─────────────────────────────"
    echo "  Interface:     $USB_INTERFACE"
    echo "  Server IP:     $AP_GATEWAY"
    echo "  Network:       $AP_NETWORK"
    echo "  DHCP Range:    $DHCP_RANGE_START - $DHCP_RANGE_END"
    echo ""
    echo "Next Steps:"
    echo "───────────"
    echo "  1. Connect ethernet cable from USB adapter to UniFi AP (via PoE)"
    echo "  2. Configure the UniFi AP:"
    echo "     - IP: 10.10.10.2"
    echo "     - Gateway: 10.10.10.1"
    echo "     - SSID: LumierProxy"
    echo "  3. Start the Lumier service:"
    echo "     sudo systemctl start lumierproxy"
    echo ""
    echo "To verify AP connection after setup:"
    echo "  ping 10.10.10.2"
    echo ""
}

# Fix rules mode (for troubleshooting)
fix_rules() {
    info "Reapplying network rules..."
    configure_interface
    configure_iptables
    enable_forwarding
    systemctl restart dnsmasq
    success "Rules reapplied"
    test_connectivity
}

# Main function
main() {
    print_banner
    check_root
    print_security_warning

    # Check for --fix-rules mode
    if [ "$1" == "--fix-rules" ]; then
        # Need to get interface from existing config
        if [ -f /etc/dnsmasq.d/lumier-ap.conf ]; then
            USB_INTERFACE=$(grep "^interface=" /etc/dnsmasq.d/lumier-ap.conf | cut -d= -f2)
            if [ -n "$USB_INTERFACE" ]; then
                fix_rules
                exit 0
            fi
        fi
        error "No existing configuration found. Run setup first."
    fi

    detect_usb_adapter
    get_configuration
    echo ""
    configure_interface
    persist_interface
    configure_dhcp
    configure_iptables
    enable_forwarding
    test_connectivity
    print_summary
}

# Run main
main "$@"
