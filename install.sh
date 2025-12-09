#!/bin/bash

# Lumier Dynamics - Pure Go Proxy Installation Script
# No external dependencies - pure Go implementation

set -e

echo "=========================================="
echo "🌐 Lumier Dynamics - Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
apt-get update

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go..."
    apt-get install -y golang-go
else
    echo "✅ Go already installed: $(go version)"
fi

# Install git if not present  
if ! command -v git &> /dev/null; then
    echo "📦 Installing git..."
    apt-get install -y git
fi

# Create installation directory
echo "📁 Creating installation directory..."
mkdir -p /opt/lumier-dynamics
cd /opt/lumier-dynamics

# Copy files
echo "📋 Installing Lumier Dynamics..."
if [ -f "$PWD/../main.go" ]; then
    cp ../main.go .
    cp ../proxies.txt .
    cp ../go.mod .
else
    echo "Warning: Running from current directory"
    # Files should already be here
fi

# Build the application
echo "🔨 Building application..."
go mod download
go build -o lumier-proxy main.go

# Create systemd service
echo "⚙️  Creating systemd service..."
cat > /etc/systemd/system/lumier-dynamics.service << 'EOF'
[Unit]
Description=Lumier Dynamics HTTP/HTTPS Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lumier-dynamics
ExecStart=/opt/lumier-dynamics/lumier-proxy
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Configure firewall (if ufw is installed)
if command -v ufw &> /dev/null; then
    echo "🔥 Configuring firewall..."
    ufw allow 8080/tcp comment 'Lumier Dashboard'
    ufw allow 8888/tcp comment 'Lumier Proxy Port'
    echo "Firewall rules added"
fi

echo ""
echo "=========================================="
echo "✅ Installation Complete!"
echo "=========================================="
echo ""
echo "📝 Next Steps:"
echo ""
echo "1. Edit proxy pool:"
echo "   nano /opt/lumier-dynamics/proxies.txt"
echo "   Add your Bright Data proxies (format: host:port:username:password)"
echo ""
echo "2. Start the service:"
echo "   systemctl start lumier-dynamics"
echo ""
echo "3. Enable on boot:"
echo "   systemctl enable lumier-dynamics"
echo ""
echo "4. Check status:"
echo "   systemctl status lumier-dynamics"
echo ""
echo "5. View logs:"
echo "   journalctl -u lumier-dynamics -f"
echo ""
echo "6. Access dashboard:"
echo "   http://YOUR_SERVER_IP:8080"
echo ""
echo "📱 Phone Setup:"
echo "   1. Go to Wi-Fi Settings"
echo "   2. Modify Network → Manual Proxy"
echo "   3. Hostname: YOUR_SERVER_IP"
echo "   4. Port: 8888"
echo ""
echo "📁 Data Files:"
echo "   - proxies.txt: Your upstream proxy pool"
echo "   - device_data.json: Device names, groups, settings (auto-created)"
echo ""
echo "🆕 New Features in v2.0:"
echo "   - Edit device names (click on device name)"
echo "   - Search and filter devices"
echo "   - Group devices by location/team"
echo "   - Bulk proxy changes"
echo "   - Pagination (20 devices per page)"
echo "   - Persistent settings (survives restarts)"
echo "   - Export device list"
echo ""
echo "=========================================="
