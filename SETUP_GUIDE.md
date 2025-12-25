# LumierProxy Access Point Setup Guide

This guide walks you through setting up LumierProxy with a UniFi UAP-LR access point.

## Overview

```
┌──────────────┐     ┌─────────────────────────────────────┐     ┌──────────────┐
│   Internet   │     │           YOUR PC SERVER            │     │  UniFi AP    │
│    Router    │◄───►│  [WAN Interface]   [TP-Link UE300]  │◄───►│   UAP-LR     │
│ 192.168.50.x │     │                     10.10.10.1      │     │ 10.10.10.2   │
└──────────────┘     │                         │           │     │              │
                     │              LumierProxy Server     │     │ SSID: AP-Prox│
                     │              Port 8888 (proxy)      │     └──────┬───────┘
                     │              Port 8080 (dashboard)  │            │ WiFi
                     └─────────────────────────────────────┘            │
                                                                 ┌──────┴───────┐
                                                                 │   Devices    │
                                                                 │ 10.10.10.x   │
                                                                 └──────────────┘
```

**Key Points:**
- AP network uses `10.10.10.0/24` (separate from your office `192.168.50.x`)
- All device traffic is forced through the proxy
- Direct internet access from AP is **BLOCKED**

---

## Prerequisites Checklist

Before starting, ensure you have:

- [ ] UniFi UAP-LR access point
- [ ] PoE injector (came with the AP)
- [ ] 2 Ethernet cables
- [ ] TP-Link UE300 connected to your PC
- [ ] PC running Linux (Ubuntu/Debian recommended)
- [ ] Root/sudo access on the PC

---

## Quick Setup (5-10 minutes)

### Step 1: Physical Connections

```
[Wall Power] → [PoE Injector POE port] ────────► [UniFi AP]
                      │
               [PoE Injector LAN port]
                      │
                      ▼
              [Ethernet Cable]
                      │
                      ▼
              [TP-Link UE300] ──USB──► [Your PC]
```

1. Plug PoE injector into wall power
2. Connect **POE port** to UniFi AP with ethernet cable
3. Connect **LAN port** to TP-Link UE300 with ethernet cable
4. Plug TP-Link UE300 into your PC's USB port

### Step 2: Find Your Interface Names

```bash
# List all network interfaces
ip link show

# Look for something like:
# - eth0, eth1, enp3s0, enx... (TP-Link will be one of these)
# - wlan0, wlp2s0 (if using WiFi for internet)
```

**Common patterns:**
- TP-Link UE300 often shows as `enx` followed by MAC address (e.g., `enxc025a5123456`)
- Or simply `eth0` or `eth1`

### Step 3: Run Setup Script

```bash
# Navigate to LumierProxy directory
cd /home/user/lumierproxy

# Make script executable
chmod +x scripts/ap-setup.sh

# Run with sudo
sudo ./scripts/ap-setup.sh
```

The script will:
1. Ask for your interface names
2. Install dnsmasq
3. Configure the network
4. Set up firewall rules
5. Start DHCP server

### Step 4: Configure UniFi AP

You have two options:

#### Option A: Factory Reset + Standalone (Easiest)

If this is a fresh or previously-used AP:

1. **Factory reset the AP:** Hold reset button for 10+ seconds until light flashes
2. **Wait 2-3 minutes** for AP to boot
3. **The AP will get IP from your PC's DHCP** (10.10.10.100-200 range)
4. **Find the AP's IP:**
   ```bash
   cat /var/lib/lumier/dnsmasq.leases
   ```
5. **Access AP web interface:** Open browser to `http://10.10.10.x` (the IP from above)
6. **Configure WiFi:**
   - SSID: `AP-Prox`
   - Security: WPA2
   - Password: `Drnda123`
7. **Set static IP for AP:**
   - IP: `10.10.10.2`
   - Subnet: `255.255.255.0`
   - Gateway: `10.10.10.1`
   - DNS: `10.10.10.1`

#### Option B: UniFi Controller (More Features)

```bash
# Install UniFi Controller
sudo apt install openjdk-11-jre-headless -y
wget https://dl.ui.com/unifi/6.5.55/unifi_sysvinit_all.deb
sudo dpkg -i unifi_sysvinit_all.deb
sudo apt install -f -y

# Start controller
sudo systemctl start unifi

# Access at https://localhost:8443 (accept self-signed cert warning)
```

In UniFi Controller:
1. Adopt the AP
2. Go to Settings → WiFi → Create New
3. Set SSID: `AP-Prox`, Password: `Drnda123`
4. Go to Devices → AP → Config → Network
5. Set static IP: `10.10.10.2`, Gateway: `10.10.10.1`

### Step 5: Start LumierProxy

```bash
cd /home/user/lumierproxy
go run main.go
```

Or if you have the compiled binary:
```bash
./lumierproxy
```

### Step 6: Test Connection

1. On your phone/laptop, connect to WiFi `AP-Prox`
2. Enter password: `Drnda123`
3. Device should get IP in range `10.10.10.100-200`
4. Open browser and visit any website
5. Check LumierProxy dashboard at `http://YOUR_SERVER_IP:8080`
6. You should see the device listed!

---

## Verification Commands

```bash
# Check AP network status
sudo ./scripts/ap-status.sh

# View connected devices
cat /var/lib/lumier/dnsmasq.leases

# Check iptables rules
sudo iptables -L -n
sudo iptables -t nat -L -n

# Test if proxy is working (from server)
curl -x http://127.0.0.1:8888 http://httpbin.org/ip
```

---

## Troubleshooting

### AP not getting IP address

```bash
# Check dnsmasq is running
sudo pgrep -f dnsmasq

# Restart dnsmasq
sudo pkill -f "dnsmasq.*dnsmasq-ap.conf"
sudo dnsmasq --conf-file=/etc/lumier/dnsmasq-ap.conf

# Check interface has IP
ip addr show eth0  # replace with your interface
```

### Devices connect but no internet

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
# Should be 1

# Enable if not
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Check iptables NAT
sudo iptables -t nat -L LUMIER_NAT -n
```

### Can't access websites (SSL errors)

This is expected for HTTPS with transparent proxying. The proxy intercepts all traffic.
Make sure LumierProxy server is running on port 8888.

### Device gets IP but can't browse

```bash
# Check proxy is listening
ss -tlnp | grep 8888

# Check DNS is working
nslookup google.com 10.10.10.1

# Test from server
curl http://httpbin.org/ip
```

---

## Rollback / Undo

If something goes wrong:

```bash
# Run teardown script
sudo ./scripts/ap-teardown.sh

# This removes all AP configuration but keeps your proxy intact
```

---

## File Locations

| File | Purpose |
|------|---------|
| `/etc/lumier/dnsmasq-ap.conf` | DHCP server configuration |
| `/etc/lumier/ap-config.env` | Saved interface/IP settings |
| `/var/lib/lumier/dnsmasq.leases` | Connected devices list |
| `/etc/iptables/rules.v4` | Firewall rules |
| `/etc/systemd/system/lumier-ap.service` | Auto-start service |

---

## Security Notes

1. **All traffic forced through proxy** - Devices cannot bypass
2. **Direct forwarding blocked** - iptables DROP policy
3. **WPA2 encryption** - WiFi traffic encrypted
4. **Isolated network** - AP network separate from office network

---

## Daily Operations

### Check status
```bash
sudo ./scripts/ap-status.sh
```

### Restart AP network
```bash
sudo systemctl restart lumier-ap.service
```

### View connected devices
```bash
cat /var/lib/lumier/dnsmasq.leases
```

### Change WiFi password
Reconfigure in UniFi AP web interface or controller.

---

## Support

If you encounter issues:
1. Run `sudo ./scripts/ap-status.sh` and note any FAIL items
2. Check logs: `journalctl -u lumier-ap.service`
3. Verify physical connections
