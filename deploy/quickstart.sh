#!/bin/bash
#
# Lumier Dynamics - Quick Start Script
# One-command setup after hardware is connected
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║              LUMIER DYNAMICS - QUICK START                    ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo ./quickstart.sh${NC}"
    exit 1
fi

echo "This script will:"
echo "  1. Install required packages"
echo "  2. Configure network for Access Point"
echo "  3. Set up and start the Lumier service"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo -e "${BLUE}Step 1/4: Installing dependencies...${NC}"
"$SCRIPT_DIR/install.sh" --auto 2>/dev/null || "$SCRIPT_DIR/install.sh"

echo ""
echo -e "${BLUE}Step 2/4: Configuring network...${NC}"
"$SCRIPT_DIR/setup-network.sh"

echo ""
echo -e "${BLUE}Step 3/4: Building binary (if needed)...${NC}"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
if [ ! -f /opt/lumierproxy/lumierproxy ]; then
    if [ -f "$PARENT_DIR/main.go" ]; then
        echo "Building Lumier binary..."
        cd "$PARENT_DIR"
        if command -v go &> /dev/null; then
            go build -o lumierproxy .
            cp lumierproxy /opt/lumierproxy/
            echo -e "${GREEN}Binary built successfully${NC}"
        else
            echo -e "${YELLOW}Go not installed. Please build manually:${NC}"
            echo "  cd $PARENT_DIR && go build -o lumierproxy ."
            echo "  sudo cp lumierproxy /opt/lumierproxy/"
        fi
    fi
fi

echo ""
echo -e "${BLUE}Step 4/4: Starting service...${NC}"
if [ -f /opt/lumierproxy/lumierproxy ]; then
    systemctl daemon-reload
    systemctl start lumierproxy
    systemctl enable lumierproxy
    sleep 2
    if systemctl is-active --quiet lumierproxy; then
        echo -e "${GREEN}Service started successfully!${NC}"
    else
        echo -e "${RED}Service failed to start. Check: journalctl -u lumierproxy${NC}"
    fi
else
    echo -e "${YELLOW}Binary not found at /opt/lumierproxy/lumierproxy${NC}"
    echo "Please build and copy the binary first."
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                    QUICK START COMPLETE                       ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "Next steps:"
echo "  1. Configure UniFi AP with IP 10.10.10.2, Gateway 10.10.10.1"
echo "  2. Set up WiFi SSID 'LumierProxy' on the AP"
echo ""
echo -e "Dashboard: ${YELLOW}http://$SERVER_IP:8080${NC}"
echo ""
echo "Run '$SCRIPT_DIR/status.sh' to check system status"
echo ""
