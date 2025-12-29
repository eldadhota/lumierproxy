# Remote Access Point Implementation Plan

## Overview

Transform the proxy server from an Android app-based system to a **Hardware Access Point (UniFi UAP-LR)** based system where:
- Devices connect to the UniFi AP
- Traffic is transparently proxied through upstream SOCKS5 proxies
- All management is done through the dashboard
- **No traffic can bypass the proxy** (strict iptables rules)

## Hardware Setup

```
┌──────────────┐     ┌─────────────────────────────────────┐     ┌──────────────┐
│   Internet   │     │           YOUR PC SERVER            │     │  UniFi AP    │
│    Router    │◄───►│  [WAN Interface]   [TP-Link UE300]  │◄───►│   UAP-LR     │
│ 192.168.50.x │     │  (wlan0/eth1)        10.10.10.1     │     │ 10.10.10.2   │
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

**Key Changes from Original Plan:**
- Using **UniFi UAP-LR** hardware AP instead of hostapd software AP
- Using **10.10.10.0/24** subnet (isolated from office 192.168.50.x)
- **TP-Link UE300** connects to UniFi AP (not to internet)
- **No hostapd needed** - UniFi handles WiFi

## Network Configuration

- **TP-Link UE300 (eth0)**: LAN interface to UniFi AP → 10.10.10.1
- **WAN Interface**: Your existing internet connection
- **SSID**: AP-Prox
- **Password**: Drnda123
- **UniFi AP IP**: 10.10.10.2 (static)
- **DHCP Range**: 10.10.10.100 - 10.10.10.200

---

## Phase 1: Remove Android App

### 1.1 Delete Android App Directory
- Remove `/android-app/` directory entirely

### 1.2 Remove App API Endpoints
Remove from `main.go`:
- `/api/app/proxies`
- `/api/app/register`
- `/api/app/change-proxy`
- `/api/app/authenticate`
- `/api/app/whoami`
- `/api/app/check-ip`
- `/api/app/validate-password`
- `/api/app/confirm-connection`
- `/api/app/device-settings`

### 1.3 Remove App Handler Functions
- `handleAppProxiesAPI`
- `handleAppRegisterAPI`
- `handleAppChangeProxyAPI`
- `handleAppAuthenticateAPI`
- `handleAppWhoAmI`
- `handleAppCheckIP`
- `handleAppValidatePassword`
- `handleAppConfirmConnection`
- `handleAppDeviceSettings`

### 1.4 Update Documentation
- Update README.md to remove Android app references
- Update QUICKSTART.md

---

## Phase 2: Access Point Network Management

### 2.1 New Data Structures

```go
type APConfig struct {
    Enabled       bool   `json:"enabled"`
    Interface     string `json:"interface"`      // eth0 (TP-Link UE300)
    WANInterface  string `json:"wan_interface"`  // wlan0 or other internet interface
    IPAddress     string `json:"ip_address"`     // 10.10.10.1
    Netmask       string `json:"netmask"`        // 255.255.255.0
    DHCPStart     string `json:"dhcp_start"`     // 10.10.10.100
    DHCPEnd       string `json:"dhcp_end"`       // 10.10.10.200
    ProxyPort     int    `json:"proxy_port"`     // 8888
    LeaseFile     string `json:"lease_file"`     // /var/lib/lumier/dnsmasq.leases
}

type APDevice struct {
    MAC           string    `json:"mac"`
    IP            string    `json:"ip"`
    Hostname      string    `json:"hostname"`
    UpstreamProxy string    `json:"upstream_proxy"`
    ProxyIndex    int       `json:"proxy_index"`
    FirstSeen     time.Time `json:"first_seen"`
    LastSeen      time.Time `json:"last_seen"`
    Status        string    `json:"status"`       // online/offline
    BytesIn       int64     `json:"bytes_in"`
    BytesOut      int64     `json:"bytes_out"`
    RequestCount  int64     `json:"request_count"`
    Group         string    `json:"group"`
    CustomName    string    `json:"custom_name"`
    Notes         string    `json:"notes"`
}
```

### 2.2 Setup Scripts (Already Created)

| Script | Purpose |
|--------|---------|
| `scripts/ap-setup.sh` | Configure network, iptables, dnsmasq |
| `scripts/ap-teardown.sh` | Remove all AP configuration |
| `scripts/ap-status.sh` | Check status of all components |

### 2.3 DHCP Configuration (dnsmasq)

Generated at `/etc/lumier/dnsmasq-ap.conf`:
```
interface=eth0
dhcp-range=10.10.10.100,10.10.10.200,255.255.255.0,12h
dhcp-option=3,10.10.10.1
dhcp-option=6,10.10.10.1
dhcp-leasefile=/var/lib/lumier/dnsmasq.leases
bind-interfaces
server=8.8.8.8
server=8.8.4.4
log-dhcp
```

### 2.4 IPTables Rules (Strict - No Bypass)

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# === CRITICAL: Force all traffic through proxy ===

# Redirect HTTP/HTTPS to transparent proxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8888
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8888

# NAT for outgoing traffic (from proxy to internet)
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

# Allow DHCP, DNS, and proxy traffic
iptables -A INPUT -i eth0 -p udp --dport 67 -j ACCEPT   # DHCP
iptables -A INPUT -i eth0 -p udp --dport 53 -j ACCEPT   # DNS
iptables -A INPUT -i eth0 -p tcp --dport 8888 -j ACCEPT # Proxy

# DROP everything else from AP clients (prevents bypass)
iptables -A INPUT -i eth0 -j DROP
iptables -A FORWARD -i eth0 -j DROP
```

---

## Phase 3: Device Auto-Detection

### 3.1 DHCP Lease Monitoring

Monitor `/var/lib/lumier/dnsmasq.leases` for connected devices:
```
1703456789 aa:bb:cc:dd:ee:ff 10.10.10.101 android-device *
```

Format: `timestamp MAC IP hostname client-id`

### 3.2 Device Detection Loop

```go
func (s *ProxyServer) monitorDHCPLeases() {
    ticker := time.NewTicker(5 * time.Second)
    for range ticker.C {
        s.parseDHCPLeases()
        s.updateDeviceStatus()
    }
}

func (s *ProxyServer) parseDHCPLeases() {
    // Read /var/lib/lumier/dnsmasq.leases
    // Parse each line: timestamp mac ip hostname clientid
    // For each lease:
    //   - If new MAC: create APDevice, assign proxy
    //   - If existing: update IP, mark online
}
```

### 3.3 Auto-Registration Logic

When new device detected:
1. Extract MAC, IP, hostname from lease
2. Check if MAC already exists in APDevices
3. If new: assign next available proxy (round-robin)
4. If existing: update IP and mark online
5. Auto-confirm (no manual step needed - direct connection to AP = trusted)

---

## Phase 4: Transparent Proxy Modifications

### 4.1 Update handleProxy for AP Clients

```go
func handleProxy(w http.ResponseWriter, r *http.Request) {
    clientIP := strings.Split(r.RemoteAddr, ":")[0]

    // Check if client is from AP network (10.10.10.x)
    if server.isAPClient(clientIP) {
        device := server.getAPDeviceByIP(clientIP)
        if device != nil {
            // Update stats
            device.LastSeen = time.Now()
            device.Status = "online"
            atomic.AddInt64(&device.RequestCount, 1)

            // Route through assigned proxy
            if r.Method == http.MethodConnect {
                handleAPHTTPS(w, r, device)
            } else {
                handleAPHTTP(w, r, device)
            }
            return
        }
        // Unknown AP client - block
        http.Error(w, "Device not registered", http.StatusForbidden)
        return
    }

    // Fallback to existing username-based auth for non-AP clients
    // ... existing code ...
}

func (s *ProxyServer) isAPClient(ip string) bool {
    return strings.HasPrefix(ip, "10.10.10.")
}

func (s *ProxyServer) getAPDeviceByIP(ip string) *APDevice {
    s.apMu.RLock()
    defer s.apMu.RUnlock()
    for _, device := range s.apDevices {
        if device.IP == ip && device.Status == "online" {
            return device
        }
    }
    return nil
}
```

### 4.2 Handle Transparent HTTP/HTTPS

For transparent proxy, we receive the original request directly (not CONNECT):
- HTTP: Forward request through SOCKS5 upstream
- HTTPS: Forward TCP connection through SOCKS5 upstream

```go
func handleAPHTTP(w http.ResponseWriter, r *http.Request, device *APDevice) {
    // Get upstream proxy for this device
    proxyStr := device.UpstreamProxy
    // Dial through SOCKS5
    // Forward request
    // Track bytes
}

func handleAPHTTPS(w http.ResponseWriter, r *http.Request, device *APDevice) {
    // Similar to existing handleHTTPS but uses device.UpstreamProxy
}
```

---

## Phase 5: Dashboard Integration

### 5.1 New Dashboard Page: Access Point

**URL**: `/access-point`

**Features**:
- Network status (interface up/down, DHCP running)
- Connected devices count
- Quick stats (total traffic, active devices)
- Configuration display (IP, DHCP range)
- Links to setup scripts

### 5.2 Update Devices Page for AP Devices

**Merge AP devices into existing devices page** with:
- Filter: "AP Devices" / "Legacy Devices" / "All"
- Show MAC address for AP devices
- Show hostname from DHCP
- Assigned proxy per device
- Change proxy dropdown
- Device status (online/offline based on DHCP lease)
- Traffic stats per device
- Group assignment
- Custom naming

### 5.3 New API Endpoints

```
GET  /api/ap/status          - Get AP network status
GET  /api/ap/config          - Get AP configuration
GET  /api/ap/devices         - List AP devices
POST /api/ap/device/proxy    - Change device proxy assignment
POST /api/ap/device/name     - Set custom device name
POST /api/ap/device/group    - Set device group
DELETE /api/ap/device        - Remove/forget a device
```

### 5.4 Update Navigation

Add to dashboard sidebar:
- "Access Point" menu item (shows network status)
- Existing "Devices" page shows both AP and legacy devices

---

## Phase 6: Persistence

### 6.1 Update PersistentData

```go
type PersistentData struct {
    // ... existing fields ...
    APConfig    APConfig              `json:"ap_config"`
    APDevices   map[string]*APDevice  `json:"ap_devices"` // keyed by MAC
}
```

### 6.2 Save/Load AP State

- Save AP device assignments to device_data.json
- Restore on server restart
- Remember proxy assignments by MAC address
- Device goes offline if not in DHCP leases, but assignment preserved

---

## Implementation Checklist

### Scripts (DONE)
- [x] `scripts/ap-setup.sh` - Network setup script
- [x] `scripts/ap-teardown.sh` - Rollback script
- [x] `scripts/ap-status.sh` - Status check script
- [x] `SETUP_GUIDE.md` - Step-by-step documentation

### Code Changes (TODO)
- [ ] Phase 1: Remove Android app code from main.go
- [ ] Phase 2: Add APConfig and APDevice structures
- [ ] Phase 3: Add DHCP lease monitoring
- [ ] Phase 4: Update handleProxy for AP clients
- [ ] Phase 5: Add dashboard pages and API endpoints
- [ ] Phase 6: Update persistence

---

## Prerequisites Checklist

Before deployment:

- [ ] Install dnsmasq: `sudo apt install dnsmasq`
- [ ] Install iptables-persistent: `sudo apt install iptables-persistent`
- [ ] Stop existing dnsmasq: `sudo systemctl stop dnsmasq && sudo systemctl disable dnsmasq`
- [ ] Connect UniFi AP to TP-Link UE300 via PoE injector
- [ ] Configure UniFi AP with SSID: AP-Prox, Password: Drnda123
- [ ] Set UniFi AP static IP: 10.10.10.2, Gateway: 10.10.10.1
- [ ] Run `sudo ./scripts/ap-setup.sh`

---

## Files Summary

### New Files
- `scripts/ap-setup.sh` - Network configuration
- `scripts/ap-teardown.sh` - Rollback
- `scripts/ap-status.sh` - Status check
- `SETUP_GUIDE.md` - Documentation
- `/etc/lumier/dnsmasq-ap.conf` - DHCP config (generated)
- `/etc/lumier/ap-config.env` - Saved settings (generated)
- `/var/lib/lumier/dnsmasq.leases` - Connected devices (runtime)

### Modified Files
- `main.go` - AP device management, transparent proxy, new APIs
- `device_data.json` - New fields for AP config and devices
- `README.md` - Updated documentation

### Deleted Files
- `android-app/` directory (entire)

---

## Security Features

1. **Strict iptables** - All traffic MUST go through proxy, direct bypass blocked
2. **Isolated network** - 10.10.10.0/24 separate from office network
3. **WPA2 encryption** - Configured on UniFi AP
4. **MAC-based tracking** - Devices identified by hardware address
5. **Dashboard auth** - Still required for management

---

## Rollback Plan

If issues occur:
1. Run: `sudo ./scripts/ap-teardown.sh`
2. This removes network config but keeps proxy intact
3. Restore main.go from git if needed: `git checkout main.go`
4. Your original proxy continues working for existing devices
