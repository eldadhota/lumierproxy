#!/bin/bash
# Lumier Dynamics Proxy Server - Launch Script for Ubuntu/Linux
# This script builds and runs the proxy server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Lumier Dynamics Proxy Server v3.0${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed.${NC}"
    echo "Please install Go first: https://go.dev/doc/install"
    echo "Or run: sudo apt install golang-go"
    exit 1
fi

echo -e "${YELLOW}Building the proxy server...${NC}"
go build -o lumierproxy .

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    echo ""
    echo -e "${YELLOW}Starting Lumier Dynamics...${NC}"
    echo "Press Ctrl+C to stop the server"
    echo ""
    ./lumierproxy
else
    echo -e "${RED}Build failed. Please check for errors.${NC}"
    exit 1
fi
