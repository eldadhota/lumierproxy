#!/bin/bash
# ===========================================
# Lumier Dynamics - Linux/Ubuntu Launcher
# ===========================================
# This script sets up everything needed and
# launches the proxy server on a fresh system.
# ===========================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}==========================================${NC}"
echo -e "${CYAN}  Lumier Dynamics Proxy Launcher v3.0${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

# Get script directory and change to it
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
echo -e "Working directory: ${CYAN}$SCRIPT_DIR${NC}"
echo ""

# ===========================================
# Function: Check and install Go
# ===========================================
ensure_go_installed() {
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version)
        echo -e "${GREEN}Go is installed:${NC} $GO_VERSION"
        return 0
    fi

    echo -e "${YELLOW}Go is not installed on this system.${NC}"
    echo ""

    # Check if we can use apt (Debian/Ubuntu)
    if command -v apt-get &> /dev/null; then
        echo -e "${YELLOW}Installing Go via apt...${NC}"
        echo "This may require sudo password."
        echo ""

        # Check if running as root
        if [ "$EUID" -eq 0 ]; then
            apt-get update
            apt-get install -y golang-go
        else
            sudo apt-get update
            sudo apt-get install -y golang-go
        fi

        # Verify installation
        if command -v go &> /dev/null; then
            echo ""
            echo -e "${GREEN}Go installed successfully:${NC} $(go version)"
            return 0
        fi
    fi

    # Check if we can use dnf (Fedora/RHEL)
    if command -v dnf &> /dev/null; then
        echo -e "${YELLOW}Installing Go via dnf...${NC}"
        if [ "$EUID" -eq 0 ]; then
            dnf install -y golang
        else
            sudo dnf install -y golang
        fi

        if command -v go &> /dev/null; then
            echo -e "${GREEN}Go installed successfully:${NC} $(go version)"
            return 0
        fi
    fi

    # Check if we can use pacman (Arch)
    if command -v pacman &> /dev/null; then
        echo -e "${YELLOW}Installing Go via pacman...${NC}"
        if [ "$EUID" -eq 0 ]; then
            pacman -S --noconfirm go
        else
            sudo pacman -S --noconfirm go
        fi

        if command -v go &> /dev/null; then
            echo -e "${GREEN}Go installed successfully:${NC} $(go version)"
            return 0
        fi
    fi

    # Manual installation fallback
    echo ""
    echo -e "${RED}Could not auto-install Go.${NC}"
    echo ""
    echo "Please install Go manually:"
    echo "  - Download from: https://go.dev/dl/"
    echo "  - Or follow: https://go.dev/doc/install"
    echo ""
    echo "After installing Go, run this script again."
    exit 1
}

# ===========================================
# Function: Ensure Go module is initialized
# ===========================================
ensure_go_module() {
    if [ ! -f "go.mod" ]; then
        echo ""
        echo -e "${YELLOW}go.mod not found, initializing module...${NC}"
        go mod init lumier-dynamics
    fi

    # Check if dependencies are downloaded
    if [ ! -f "go.sum" ] || ! grep -q "golang.org/x/net" go.sum 2>/dev/null; then
        echo -e "${YELLOW}Fetching Go dependencies...${NC}"
        go mod tidy
    fi
}

# ===========================================
# Function: Ensure proxies.txt exists
# ===========================================
ensure_proxies_file() {
    if [ -f "proxies.txt" ]; then
        PROXY_COUNT=$(grep -v '^#' proxies.txt | grep -v '^$' | wc -l)
        echo -e "${GREEN}Found proxies.txt${NC} ($PROXY_COUNT proxies configured)"
        return 0
    fi

    echo ""
    echo -e "${YELLOW}proxies.txt not found, creating template...${NC}"

    cat > proxies.txt << 'EOF'
# Lumier Dynamics - Upstream Proxy Configuration
# ==============================================
# Add one SOCKS5 proxy per line in this format:
# host:port:username:password
#
# Example (Bright Data):
# brd.superproxy.io:22228:brd-customer-XXXXX-zone-isp-ip-1.2.3.4:yourpassword
#
# Add your proxies below:
EOF

    echo ""
    echo -e "${GREEN}Created proxies.txt template.${NC}"
    echo ""
    echo -e "${YELLOW}Please edit proxies.txt and add your upstream proxies.${NC}"
    echo "Then run this script again."
    echo ""
    echo "To edit: nano proxies.txt"
    echo ""
    exit 0
}

# ===========================================
# Function: Configure firewall
# ===========================================
configure_firewall() {
    # Check if ufw is available and active
    if command -v ufw &> /dev/null; then
        UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1 || echo "inactive")
        if [[ "$UFW_STATUS" == *"active"* ]]; then
            echo ""
            echo -e "${YELLOW}Configuring firewall (ufw)...${NC}"

            # Check if rules already exist
            if ! sudo ufw status | grep -q "8080/tcp"; then
                sudo ufw allow 8080/tcp comment 'Lumier Dashboard' >/dev/null 2>&1 || true
                echo "  - Allowed port 8080 (Dashboard)"
            fi
            if ! sudo ufw status | grep -q "8888/tcp"; then
                sudo ufw allow 8888/tcp comment 'Lumier Proxy' >/dev/null 2>&1 || true
                echo "  - Allowed port 8888 (Proxy)"
            fi
        fi
    fi

    # Check if firewalld is available (RHEL/Fedora)
    if command -v firewall-cmd &> /dev/null; then
        if systemctl is-active --quiet firewalld; then
            echo ""
            echo -e "${YELLOW}Configuring firewall (firewalld)...${NC}"
            sudo firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true
            sudo firewall-cmd --permanent --add-port=8888/tcp >/dev/null 2>&1 || true
            sudo firewall-cmd --reload >/dev/null 2>&1 || true
            echo "  - Allowed ports 8080 and 8888"
        fi
    fi
}

# ===========================================
# Function: Get server IP address
# ===========================================
get_server_ip() {
    # Try to get the primary IP address
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -z "$IP" ]; then
        IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
    fi
    if [ -z "$IP" ]; then
        IP="localhost"
    fi
    echo "$IP"
}

# ===========================================
# MAIN SCRIPT
# ===========================================

# Step 1: Ensure Go is installed
ensure_go_installed

# Step 2: Ensure Go module is set up
ensure_go_module

# Step 3: Ensure proxies.txt exists
ensure_proxies_file

# Step 4: Configure firewall (optional, won't fail if not available)
configure_firewall 2>/dev/null || true

# Step 5: Build the application
echo ""
echo -e "${YELLOW}Building Lumier Dynamics...${NC}"

if go build -o lumierproxy main.go; then
    echo -e "${GREEN}Build successful!${NC}"
else
    echo -e "${RED}Build failed. Please check for errors above.${NC}"
    exit 1
fi

# Step 6: Display startup information
SERVER_IP=$(get_server_ip)
echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}  Ready to Start!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://$SERVER_IP:8080${NC}"
echo -e "  Proxy Port: ${CYAN}8888${NC}"
echo -e "  Login:      ${CYAN}admin / admin123${NC}"
echo ""
echo -e "${YELLOW}Phone Setup:${NC}"
echo "  1. Open WiFi Settings > Modify Network"
echo "  2. Set Proxy to Manual"
echo "  3. Hostname: $SERVER_IP"
echo "  4. Port: 8888"
echo ""
echo -e "${CYAN}Starting Lumier Dynamics...${NC}"
echo "Press Ctrl+C to stop the server"
echo ""
echo "==========================================="
echo ""

# Step 7: Run the server
./lumierproxy

# Cleanup message
echo ""
echo -e "${YELLOW}Server stopped.${NC}"
