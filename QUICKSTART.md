# Lumier Dynamics Proxy Server - Quick Start Guide

## What is Lumier Dynamics?

Lumier Dynamics is an enterprise proxy management system that allows you to:
- Route device traffic through upstream SOCKS5 proxies
- Monitor and manage connected devices via a web dashboard
- Organize devices into groups
- Track proxy health and traffic analytics

---

## Requirements

- **Linux** (Ubuntu 20.04+ recommended) or **Windows**
- **Go 1.20+** installed ([Download Go](https://go.dev/doc/install))
- A list of SOCKS5 proxies in `proxies.txt`

---

## Quick Start (5 minutes)

### Step 1: Add Your Proxies

Edit `proxies.txt` and add your SOCKS5 proxies (one per line):
```
host:port:username:password
host:port:username:password
```

### Step 2: Run the Server

**On Linux/Ubuntu:**
```bash
chmod +x start.sh
./start.sh
```

**On Windows:**
Double-click `run_proxy.bat` or run in PowerShell:
```powershell
.\run_proxy.ps1
```

### Step 3: Access the Dashboard

Open your browser and go to:
```
http://YOUR_SERVER_IP:8080
```

**Default login:**
- Username: `admin`
- Password: `admin123`

> **Important:** Change the default password immediately in Settings!

### Step 4: Connect Your Devices

On each phone/device, configure Wi-Fi proxy settings:
- **Proxy Host:** Your server's IP address
- **Proxy Port:** `8888`
- **Type:** HTTP

---

## Running as a Service (Auto-Start on Boot)

To keep the server running 24/7 and auto-restart on crashes:

### Ubuntu/Linux (systemd)

1. Build the binary:
   ```bash
   go build -o lumierproxy main.go
   ```

2. Copy files to /opt:
   ```bash
   sudo mkdir -p /opt/lumierproxy
   sudo cp lumierproxy proxies.txt device_data.json /opt/lumierproxy/
   ```

3. Install the service:
   ```bash
   sudo cp lumierproxy.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable lumierproxy
   sudo systemctl start lumierproxy
   ```

4. Check status:
   ```bash
   sudo systemctl status lumierproxy
   ```

5. View logs:
   ```bash
   sudo journalctl -u lumierproxy -f
   ```

---

## Dashboard Features

| Page | Description |
|------|-------------|
| **Devices** | View all connected devices, change proxies, edit device info |
| **Health** | Monitor proxy success rates and performance |
| **Analytics** | View traffic history and trends |
| **Settings** | Change password, manage device groups |

---

## Ports Used

| Port | Purpose |
|------|---------|
| `8888` | Proxy server (devices connect here) |
| `8080` | Dashboard web interface |

---

## Troubleshooting

### "No upstream proxies loaded"
- Check that `proxies.txt` exists and has valid proxy entries
- Format: `host:port:username:password`

### Devices not connecting
- Ensure firewall allows ports 8888 and 8080
- Verify the device proxy settings match your server IP

### Dashboard not loading
- Check if the server is running: `sudo systemctl status lumierproxy`
- Verify port 8080 is not blocked

---

## File Structure

```
lumierproxy/
├── main.go              # Main application source
├── proxies.txt          # Your SOCKS5 proxy list
├── device_data.json     # Persistent data (auto-created)
├── start.sh             # Linux launch script
├── run_proxy.bat        # Windows launch script
├── lumierproxy.service  # systemd service file
└── QUICKSTART.md        # This guide
```

---

## Support

For issues and feature requests, visit:
https://github.com/eldadhota/lumierproxy/issues
