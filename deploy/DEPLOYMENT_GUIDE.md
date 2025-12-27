# Lumier Dynamics - Deployment Guide

## Migration: Android App → Access Point System

This guide walks you through migrating from the Android proxy app system to the new WiFi Access Point system with dashboard control.

---

## Table of Contents

1. [Overview](#overview)
2. [Hardware Requirements](#hardware-requirements)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Step-by-Step Deployment](#step-by-step-deployment)
5. [Verifying the Setup](#verifying-the-setup)
6. [Migrating Devices](#migrating-devices)
7. [Troubleshooting](#troubleshooting)
8. [Quick Reference Card](#quick-reference-card)

---

## Overview

### Old System (Android App)
- Each Android device has the Lumier app installed
- App configures proxy settings manually
- Devices connect to any WiFi network

### New System (Access Point)
- UniFi UAP-LR creates a dedicated WiFi network
- Devices connect to this WiFi and are automatically proxied
- No app needed - all traffic goes through proxy
- Dashboard approval required for new devices
- Windows client available for PC users to use approved device proxies

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        PROXY SERVER                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │ Main NIC    │    │ USB Ethernet│    │ Lumier      │          │
│  │ (Internet)  │    │ (10.10.10.1)│    │ Proxy :8888 │          │
│  │ eth0/ens33  │    │ eth1/enx*   │    │ Dashboard   │          │
│  └──────┬──────┘    └──────┬──────┘    │ :8080       │          │
│         │                  │           └─────────────┘          │
│         │                  │                                     │
│    To Internet        To UniFi AP                                │
└─────────┼──────────────────┼────────────────────────────────────┘
          │                  │
          ▼                  ▼
    ┌─────────┐        ┌─────────────┐
    │ Router/ │        │ UniFi       │
    │ Internet│        │ UAP-LR      │
    └─────────┘        │ (10.10.10.2)│
                       └──────┬──────┘
                              │
                    ┌─────────┴─────────┐
                    │   WiFi Network    │
                    │  "LumierProxy"    │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌────────┐      ┌────────┐      ┌────────┐
         │ Phone 1│      │ Phone 2│      │ Laptop │
         │10.10.10│      │10.10.10│      │10.10.10│
         │  .100  │      │  .101  │      │  .102  │
         └────────┘      └────────┘      └────────┘
```

---

## Hardware Requirements

| Item | Model | Purpose |
|------|-------|---------|
| Proxy Server | Ubuntu/Debian Linux (VM or Physical) | Runs Lumier proxy |
| USB Ethernet Adapter | TP-Link UE300 | Connects server to AP |
| Access Point | UniFi UAP-LR | Creates WiFi network |
| Ethernet Cable | Cat5e/Cat6 | Connects adapter to AP |
| PoE Injector | UniFi PoE (included with AP) | Powers the AP |

---

## Pre-Deployment Checklist

Run through this checklist BEFORE deployment day:

### Server Preparation
- [ ] Server has Ubuntu 20.04+ or Debian 11+ installed
- [ ] Server has at least 2GB RAM, 10GB disk space
- [ ] Server has internet connectivity
- [ ] You have root/sudo access to the server
- [ ] Note server's main IP address: `______________`

### Hardware Preparation
- [ ] TP-Link UE300 adapter in hand
- [ ] UniFi UAP-LR in hand
- [ ] PoE injector for UAP-LR
- [ ] Ethernet cable (at least 2m)
- [ ] UniFi AP is factory reset (hold reset 10+ seconds)

### Network Information
- [ ] Current proxy server IP: `______________`
- [ ] Dashboard port: `8080`
- [ ] Proxy port: `8888`
- [ ] AP Network will be: `10.10.10.0/24`
- [ ] AP Gateway will be: `10.10.10.1`
- [ ] AP DHCP range: `10.10.10.100-200`

### Credentials
- [ ] Dashboard admin password: `______________`
- [ ] WiFi password for AP: `______________`
- [ ] UniFi Controller credentials (if using): `______________`

---

## Step-by-Step Deployment

### Phase 1: Prepare the Server (Do this BEFORE going to office)

**Time: 15 minutes**

1. **SSH into your server:**
   ```bash
   ssh user@your-server-ip
   ```

2. **Download/update Lumier:**
   ```bash
   cd /opt/lumierproxy  # or wherever you have it
   git pull origin claude/add-remote-access-point-YvGsu
   ```

3. **Build the binary:**
   ```bash
   go build -o lumierproxy .
   ```

4. **Run the installation script:**
   ```bash
   sudo ./deploy/install.sh
   ```
   This will:
   - Install required packages (dnsmasq, iptables-persistent)
   - Set up the systemd service
   - Create necessary directories

5. **Verify the service is ready:**
   ```bash
   sudo systemctl status lumierproxy
   ```

---

### Phase 2: Connect Hardware (At the office)

**Time: 10 minutes**

1. **Plug in the TP-Link UE300 adapter:**
   - Insert into a USB 3.0 port on the server
   - Wait 10 seconds for it to be recognized

2. **Identify the new network interface:**
   ```bash
   ip link show
   ```
   Look for a new interface like `enx*` or `eth1`

   Note the interface name: `______________`

3. **Connect the ethernet cable:**
   - One end to the TP-Link adapter
   - Other end to the PoE injector's "LAN" port

4. **Connect the UniFi AP:**
   - PoE injector's "PoE" port to the AP
   - Plug in the PoE injector to power
   - Wait 2-3 minutes for AP to boot (LED will turn steady white)

---

### Phase 3: Configure the Network

**Time: 5 minutes**

1. **Run the network setup script:**
   ```bash
   sudo ./deploy/setup-network.sh
   ```

   The script will ask for:
   - The USB ethernet interface name (e.g., `enxaabbccddeeff`)

   Note: WiFi settings are configured on the UniFi AP in Phase 4, not here.

2. **Verify network is up:**
   ```bash
   ip addr show  # Should see 10.10.10.1 on USB interface
   ping 10.10.10.2  # Should reach the AP after it gets DHCP
   ```

---

### Phase 4: Configure the UniFi AP

**Time: 10 minutes**

#### Option A: Standalone Mode (Recommended - No Controller)

1. **Connect to the AP's default network:**
   - The AP creates a network like "UniFi" initially
   - Connect a laptop/phone to it

2. **Access AP setup page:**
   - Open browser: `http://192.168.1.20` or use UniFi app
   - Or SSH: `ssh ubnt@192.168.1.20` (password: `ubnt`)

3. **Configure via SSH:**
   ```bash
   ssh ubnt@192.168.1.20
   # Password: ubnt

   # Set static IP
   configure
   set system static-address 10.10.10.2/24
   set system gateway-address 10.10.10.1
   commit

   # Configure wireless
   set wireless.1.ssid LumierProxy
   set wireless.1.security wpapsk
   set wireless.1.wpa.psk YOUR_WIFI_PASSWORD

   # Save and reboot
   save
   reboot
   ```

#### Option B: UniFi Controller

1. Access your UniFi Controller
2. Adopt the AP
3. Configure:
   - Network: `10.10.10.2/24`
   - Gateway: `10.10.10.1`
   - SSID: `LumierProxy`
   - Security: WPA2
   - Password: Your chosen password

---

### Phase 5: Start the Proxy Service

**Time: 2 minutes**

1. **Start the Lumier service:**
   ```bash
   sudo systemctl start lumierproxy
   sudo systemctl enable lumierproxy
   ```

2. **Check it's running:**
   ```bash
   sudo systemctl status lumierproxy
   ```

3. **View logs if needed:**
   ```bash
   sudo journalctl -u lumierproxy -f
   ```

---

### Phase 6: Access the Dashboard

**Time: 2 minutes**

1. **Open browser on any device on the main network:**
   ```
   http://YOUR_SERVER_IP:8080
   ```

2. **Login with your admin credentials**

3. **You should see the dashboard with:**
   - Devices tab (AP devices and pending approvals)
   - Health, Analytics, Activity, Settings tabs

---

## Verifying the Setup

### Connectivity Tests

Run these commands on the server:

```bash
# 1. Check USB adapter is up
ip addr show | grep "10.10.10.1"

# 2. Check DHCP is running
sudo systemctl status dnsmasq

# 3. Check AP is reachable
ping -c 3 10.10.10.2

# 4. Check proxy is listening
ss -tlnp | grep 8888

# 5. Check dashboard is up
curl -I http://localhost:8080
```

### Device Connection Test

1. **Connect a test phone to "LumierProxy" WiFi**
2. **Check it got an IP:**
   - Should be in range 10.10.10.100-200
3. **Check dashboard:**
   - New device should appear as "Pending Approval"
4. **Approve the device:**
   - Click the device, select a proxy, approve
5. **Test browsing:**
   - Open whatismyip.com on the phone
   - Should show your proxy's IP

---

## Migrating Devices

### For Each Android Device:

1. **Disconnect from current WiFi**

2. **Remove the Lumier Android app** (optional, but recommended):
   - Settings → Apps → Lumier → Uninstall
   - This ensures old proxy settings don't interfere

3. **Connect to the new WiFi:**
   - Network name: `LumierProxy`
   - Password: (your configured password)

4. **Wait for dashboard approval:**
   - Device appears as pending in dashboard
   - Click to approve and assign proxy

5. **Verify connection:**
   - Browse to whatismyip.com
   - Confirm it shows the assigned proxy IP

### For PC Users (Windows Client):

1. **Download the Windows client:**
   - Go to `http://YOUR_SERVER:8080/browsers`
   - Click "Download Client (Windows)"

2. **Or build from source:**
   ```bash
   cd client-windows
   GOOS=windows GOARCH=amd64 go build -o lumier-client.exe .
   ```

3. **Run the client:**
   - Double-click `lumier-client.exe`
   - Enter server URL when prompted
   - Enter username for logging
   - Select an approved device to use its proxy

---

## Troubleshooting

### Device Can't Connect to WiFi

1. **Check AP is powered:**
   - LED should be white/blue

2. **Check DHCP is running:**
   ```bash
   sudo systemctl status dnsmasq
   sudo journalctl -u dnsmasq -n 50
   ```

3. **Restart DHCP:**
   ```bash
   sudo systemctl restart dnsmasq
   ```

### Device Connected but No Internet

1. **Check iptables rules:**
   ```bash
   sudo iptables -t nat -L -n
   ```
   Should see MASQUERADE rule

2. **Check IP forwarding:**
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   ```
   Should be `1`

3. **Reapply network rules:**
   ```bash
   sudo ./deploy/setup-network.sh --fix-rules
   ```

### Device Not Appearing in Dashboard

1. **Check device IP:**
   - On device: Settings → WiFi → check IP is 10.10.10.x

2. **Check DHCP leases:**
   ```bash
   cat /var/lib/misc/dnsmasq.leases
   ```

3. **Check proxy logs:**
   ```bash
   sudo journalctl -u lumierproxy -f
   ```

### Dashboard Not Accessible

1. **Check service is running:**
   ```bash
   sudo systemctl status lumierproxy
   ```

2. **Check port is open:**
   ```bash
   ss -tlnp | grep 8080
   ```

3. **Check firewall:**
   ```bash
   sudo ufw status
   sudo ufw allow 8080/tcp
   sudo ufw allow 8888/tcp
   ```

### Proxy Connection Slow

1. **Check proxy health in dashboard:**
   - Go to Health tab
   - Look for degraded/broken proxies

2. **Test upstream proxy directly:**
   ```bash
   curl --socks5-hostname PROXY_HOST:PORT -U user:pass https://api.ipify.org
   ```

---

## Quick Reference Card

Print this and keep it handy:

```
╔═══════════════════════════════════════════════════════════════╗
║                LUMIER QUICK REFERENCE                         ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  NETWORK INFO                                                 ║
║  ─────────────                                                ║
║  WiFi Name:     LumierProxy                                   ║
║  WiFi Password: _____________________                         ║
║  AP IP:         10.10.10.2                                    ║
║  Server IP:     10.10.10.1 (AP network)                       ║
║  Server IP:     _______________ (main network)                ║
║  DHCP Range:    10.10.10.100 - 10.10.10.200                   ║
║                                                               ║
║  DASHBOARD                                                    ║
║  ─────────────                                                ║
║  URL:           http://SERVER_IP:8080                         ║
║  Username:      admin                                         ║
║  Password:      _____________________                         ║
║                                                               ║
║  COMMON COMMANDS                                              ║
║  ─────────────                                                ║
║  Start proxy:   sudo systemctl start lumierproxy              ║
║  Stop proxy:    sudo systemctl stop lumierproxy               ║
║  Restart:       sudo systemctl restart lumierproxy            ║
║  View logs:     sudo journalctl -u lumierproxy -f             ║
║  Check status:  sudo systemctl status lumierproxy             ║
║                                                               ║
║  TROUBLESHOOTING                                              ║
║  ─────────────                                                ║
║  Restart DHCP:  sudo systemctl restart dnsmasq                ║
║  Check leases:  cat /var/lib/misc/dnsmasq.leases              ║
║  Fix network:   sudo ./deploy/setup-network.sh --fix-rules    ║
║  View AP logs:  ssh ubnt@10.10.10.2                           ║
║                                                               ║
║  EMERGENCY CONTACTS                                           ║
║  ─────────────                                                ║
║  ___________________________________________                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## Appendix: File Locations

| File | Location | Purpose |
|------|----------|---------|
| Lumier binary | `/opt/lumierproxy/lumierproxy` | Main proxy server |
| Service file | `/etc/systemd/system/lumierproxy.service` | Systemd unit |
| Device data | `/opt/lumierproxy/device_data.json` | Persistent storage |
| DHCP config | `/etc/dnsmasq.d/lumier-ap.conf` | DHCP for AP network |
| Network config | `/etc/netplan/99-lumier-ap.yaml` | Static IP for USB |
| Logs | `journalctl -u lumierproxy` | Service logs |

---

## Appendix: Rollback Procedure

If something goes wrong and you need to restore service:

1. **Restart services:**
   ```bash
   sudo systemctl restart lumierproxy
   sudo systemctl restart dnsmasq
   ```

2. **Reapply network rules:**
   ```bash
   sudo ./deploy/setup-network.sh --fix-rules
   ```

3. **If USB adapter was disconnected/reconnected:**
   - Re-run `sudo ./deploy/setup-network.sh` to reconfigure

4. **Check connectivity:**
   ```bash
   sudo ./deploy/status.sh
   ```

Note: All devices must connect through the Access Point. There is no fallback to the old Android app system.
