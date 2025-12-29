#!/bin/bash
#
# Lumier Dynamics - Installation Script
# This script installs all required dependencies and sets up the proxy service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/lumierproxy"
SERVICE_NAME="lumierproxy"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Print functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo ./install.sh)"
    fi
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              LUMIER DYNAMICS - INSTALLATION                   ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Cannot detect OS. This script requires Ubuntu/Debian."
    fi

    info "Detected OS: $OS $VER"

    if [[ "$OS" != *"Ubuntu"* ]] && [[ "$OS" != *"Debian"* ]]; then
        warn "This script is designed for Ubuntu/Debian. Proceeding anyway..."
    fi
}

# Install dependencies
install_dependencies() {
    info "Updating package lists..."
    apt-get update -qq

    info "Installing required packages..."
    apt-get install -y -qq \
        dnsmasq \
        iptables-persistent \
        net-tools \
        curl \
        jq \
        > /dev/null

    success "Dependencies installed"
}

# Stop dnsmasq default service (we'll configure it ourselves)
configure_dnsmasq() {
    info "Configuring dnsmasq..."

    # Stop default dnsmasq if running
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true

    # Create config directory
    mkdir -p /etc/dnsmasq.d

    # Disable default config
    if [ -f /etc/dnsmasq.conf ]; then
        sed -i 's/^[^#]/#&/' /etc/dnsmasq.conf 2>/dev/null || true
        echo "conf-dir=/etc/dnsmasq.d/,*.conf" >> /etc/dnsmasq.conf
    fi

    success "dnsmasq configured"
}

# Create installation directory
create_install_dir() {
    info "Creating installation directory..."

    mkdir -p "$INSTALL_DIR"

    # Copy files if we're not already in install dir
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PARENT_DIR="$(dirname "$SCRIPT_DIR")"

    if [ "$PARENT_DIR" != "$INSTALL_DIR" ]; then
        if [ -f "$PARENT_DIR/lumierproxy" ]; then
            cp "$PARENT_DIR/lumierproxy" "$INSTALL_DIR/"
            success "Binary copied to $INSTALL_DIR"
        elif [ -f "$PARENT_DIR/main.go" ]; then
            warn "Binary not found. You'll need to build it:"
            echo "  cd $PARENT_DIR && go build -o lumierproxy ."
            echo "  cp lumierproxy $INSTALL_DIR/"
        fi

        # Copy deploy scripts
        mkdir -p "$INSTALL_DIR/deploy"
        cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/deploy/" 2>/dev/null || true

        # Copy other needed files
        cp "$PARENT_DIR/scripts"/* "$INSTALL_DIR/scripts/" 2>/dev/null || true
    fi

    success "Installation directory ready"
}

# Create systemd service
create_service() {
    info "Creating systemd service..."

    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Lumier Dynamics Proxy Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lumierproxy
ExecStart=/opt/lumierproxy/lumierproxy
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=false
ProtectSystem=false
PrivateTmp=true

# Environment
Environment=LUMIER_DATA_DIR=/opt/lumierproxy

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    success "Systemd service created"
}

# Configure firewall
configure_firewall() {
    info "Configuring firewall..."

    # Check if ufw is active
    if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
        ufw allow 8080/tcp comment "Lumier Dashboard"
        ufw allow 8888/tcp comment "Lumier Proxy"
        ufw allow 67/udp comment "DHCP Server"
        ufw allow 68/udp comment "DHCP Client"
        success "UFW rules added"
    else
        info "UFW not active, skipping firewall configuration"
    fi
}

# Enable IP forwarding
enable_ip_forwarding() {
    info "Enabling IP forwarding..."

    # Enable now
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Make persistent
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    sysctl -p > /dev/null 2>&1

    success "IP forwarding enabled"
}

# Print next steps
print_next_steps() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                 INSTALLATION COMPLETE!                        ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo ""
    echo "  1. Connect the TP-Link UE300 USB adapter to the server"
    echo ""
    echo "  2. Run the network setup script:"
    echo -e "     ${YELLOW}sudo $INSTALL_DIR/deploy/setup-network.sh${NC}"
    echo ""
    echo "  3. Connect and configure the UniFi AP"
    echo ""
    echo "  4. Start the service:"
    echo -e "     ${YELLOW}sudo systemctl start lumierproxy${NC}"
    echo -e "     ${YELLOW}sudo systemctl enable lumierproxy${NC}"
    echo ""
    echo "  5. Access the dashboard:"
    echo -e "     ${YELLOW}http://YOUR_SERVER_IP:8080${NC}"
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  View logs:     sudo journalctl -u lumierproxy -f"
    echo "  Check status:  sudo systemctl status lumierproxy"
    echo "  Restart:       sudo systemctl restart lumierproxy"
    echo ""
    echo -e "See ${YELLOW}$INSTALL_DIR/deploy/DEPLOYMENT_GUIDE.md${NC} for full documentation."
    echo ""
}

# Main installation flow
main() {
    print_banner
    check_root
    detect_os

    # Check for auto mode (skip confirmation)
    AUTO_MODE=false
    if [ "$1" == "--auto" ] || [ "$1" == "-y" ]; then
        AUTO_MODE=true
    fi

    if [ "$AUTO_MODE" = false ]; then
        echo ""
        read -p "This will install Lumier Dynamics. Continue? (y/N) " -n 1 -r
        echo ""

        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Installation cancelled."
            exit 0
        fi
    fi

    echo ""
    install_dependencies
    configure_dnsmasq
    create_install_dir
    create_service
    configure_firewall
    enable_ip_forwarding

    if [ "$AUTO_MODE" = false ]; then
        print_next_steps
    else
        success "Installation complete (auto mode)"
    fi
}

# Run main
main "$@"
