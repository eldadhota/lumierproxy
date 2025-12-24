# Remote Access Point Implementation Plan

## Overview

Transform the proxy server from an Android app-based system to a **WiFi Access Point (AP)** based system where:
- Devices connect to the AP created by the server
- Traffic is transparently proxied through upstream SOCKS5 proxies
- All management is done through the dashboard

## Network Configuration

```
Internet (WAN)          Server                    Client Devices
     |                    |                            |
     |                    |                            |
[TP-Link UE300] ←→ [eth0] [wlan0] ←→ WiFi AP ←→ [Phone/Laptop/etc]
                          |
                    192.168.50.1
                          |
                    DHCP: 192.168.50.100-200
```

- **eth0**: WAN interface (TP-Link UE300 → Internet)
- **wlan0**: AP interface (WiFi hotspot)
- **SSID**: AP-Prox
- **Password**: Drnda123
- **AP IP**: 192.168.50.1
- **DHCP Range**: 192.168.50.100 - 192.168.50.200

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

## Phase 2: Access Point Management

### 2.1 New Data Structures

```go
type APConfig struct {
    Enabled       bool   `json:"enabled"`
    SSID          string `json:"ssid"`
    Password      string `json:"password"`
    Channel       int    `json:"channel"`
    Interface     string `json:"interface"`      // wlan0
    WANInterface  string `json:"wan_interface"`  // eth0
    IPAddress     string `json:"ip_address"`     // 192.168.50.1
    DHCPStart     string `json:"dhcp_start"`     // 192.168.50.100
    DHCPEnd       string `json:"dhcp_end"`       // 192.168.50.200
    ProxyPort     int    `json:"proxy_port"`     // 8888
}

type APDevice struct {
    MAC           string    `json:"mac"`
    IP            string    `json:"ip"`
    Hostname      string    `json:"hostname"`
    UpstreamProxy string    `json:"upstream_proxy"`
    FirstSeen     time.Time `json:"first_seen"`
    LastSeen      time.Time `json:"last_seen"`
    Status        string    `json:"status"`       // online/offline
    BytesIn       int64     `json:"bytes_in"`
    BytesOut      int64     `json:"bytes_out"`
    RequestCount  int64     `json:"request_count"`
    Group         string    `json:"group"`
    CustomName    string    `json:"custom_name"`
}
```

### 2.2 Configuration File Generation

**hostapd.conf** (generated dynamically):
```
interface=wlan0
driver=nl80211
ssid=AP-Prox
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=Drnda123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

**dnsmasq.conf** (generated dynamically):
```
interface=wlan0
dhcp-range=192.168.50.100,192.168.50.200,255.255.255.0,24h
bind-interfaces
server=8.8.8.8
server=8.8.4.4
log-dhcp
dhcp-leasefile=/tmp/dnsmasq.leases
```

### 2.3 AP Control Functions

```go
func (s *ProxyServer) startAccessPoint() error
func (s *ProxyServer) stopAccessPoint() error
func (s *ProxyServer) restartAccessPoint() error
func (s *ProxyServer) getAPStatus() (bool, error)
func (s *ProxyServer) configureIPTables() error
func (s *ProxyServer) clearIPTables() error
```

### 2.4 IPTables Rules for Transparent Proxy

```bash
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# NAT for internet access
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Redirect HTTP/HTTPS through transparent proxy
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8888
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8888

# Allow forwarding
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

---

## Phase 3: Device Auto-Detection

### 3.1 DHCP Lease Monitoring

Monitor `/tmp/dnsmasq.leases` for connected devices:
```
1703456789 aa:bb:cc:dd:ee:ff 192.168.50.101 android-device *
```

Format: `timestamp MAC IP hostname client-id`

### 3.2 Device Detection Loop

```go
func (s *ProxyServer) monitorDHCPLeases() {
    // Run every 5 seconds
    // Parse /tmp/dnsmasq.leases
    // Detect new devices → auto-register with next available proxy
    // Detect disconnected devices → mark as offline
}
```

### 3.3 Auto-Registration Logic

When new device detected:
1. Extract MAC, IP, hostname from lease
2. Check if MAC already exists in devices
3. If new: assign next available proxy (round-robin)
4. If existing: update IP and mark online
5. Auto-confirm session (no manual step needed)

---

## Phase 4: Transparent Proxy Modifications

### 4.1 Update handleProxy for Transparent Mode

Current flow requires `Proxy-Authorization` header. New flow:
1. Get client IP from connection
2. Look up device by IP (from AP DHCP range)
3. Get assigned proxy for that device
4. Route traffic through upstream proxy

```go
func handleProxy(w http.ResponseWriter, r *http.Request) {
    clientIP := getClientIP(r)

    // Check if from AP network (192.168.50.x)
    if isAPClient(clientIP) {
        device := server.getAPDeviceByIP(clientIP)
        if device != nil {
            // Route through assigned proxy
            handleTransparentProxy(w, r, device)
            return
        }
    }

    // Fallback to existing username-based auth
    // ... existing code ...
}
```

### 4.2 Handle Transparent HTTPS (CONNECT Tunnel)

For HTTPS, the proxy sees the original destination in the CONNECT request.
Transparent proxying of HTTPS requires either:
- **Option A**: SSL bump (decrypt/re-encrypt) - complex, requires CA
- **Option B**: TCP-level forwarding - simpler, no decryption

**Recommended: Option B** - Forward TCP connections directly through SOCKS5 upstream.

---

## Phase 5: Dashboard Integration

### 5.1 New Dashboard Page: Access Point

**URL**: `/access-point`

**Features**:
- Start/Stop AP toggle
- Connection status indicator
- SSID/Password display (with edit option)
- Channel selection
- Interface status (wlan0, eth0)

### 5.2 New Dashboard Page: Connected Devices

**URL**: `/ap-devices`

**Features**:
- List all connected devices (MAC, IP, hostname)
- Assigned proxy per device
- Change proxy dropdown
- Device status (online/offline)
- Traffic stats per device
- Group assignment
- Custom naming

### 5.3 New API Endpoints

```
GET  /api/ap/status          - Get AP running status
POST /api/ap/start           - Start access point
POST /api/ap/stop            - Stop access point
POST /api/ap/restart         - Restart access point
GET  /api/ap/config          - Get AP configuration
POST /api/ap/config          - Update AP configuration
GET  /api/ap/devices         - List connected devices
POST /api/ap/device/proxy    - Change device proxy assignment
POST /api/ap/device/name     - Set custom device name
POST /api/ap/device/group    - Set device group
```

### 5.4 Update Navigation

Add to dashboard sidebar:
- "Access Point" menu item
- "AP Devices" submenu

---

## Phase 6: Persistence

### 6.1 Update PersistentData

```go
type PersistentData struct {
    // ... existing fields ...
    APConfig    APConfig             `json:"ap_config"`
    APDevices   map[string]*APDevice `json:"ap_devices"` // keyed by MAC
}
```

### 6.2 Save/Load AP State

- Save AP device assignments to device_data.json
- Restore on server restart
- Remember proxy assignments by MAC address

---

## Implementation Order

1. **Phase 1**: Remove Android app (30 min)
   - Delete directory
   - Remove API endpoints and handlers
   - Clean up references

2. **Phase 2**: AP Management Core (2-3 hours)
   - Add data structures
   - Implement config file generation
   - Implement start/stop AP functions
   - IPTables management

3. **Phase 3**: Device Detection (1-2 hours)
   - DHCP lease monitoring
   - Auto-registration logic
   - Device status tracking

4. **Phase 4**: Transparent Proxy (1-2 hours)
   - Modify handleProxy for AP clients
   - IP-based device lookup
   - Traffic routing

5. **Phase 5**: Dashboard UI (2-3 hours)
   - Access Point page
   - Connected Devices page
   - API endpoints
   - Navigation updates

6. **Phase 6**: Testing & Polish (1 hour)
   - End-to-end testing
   - Error handling
   - Documentation

---

## Prerequisites Checklist

Before running the new system:

- [ ] Install hostapd: `sudo apt install hostapd`
- [ ] Install dnsmasq: `sudo apt install dnsmasq`
- [ ] Stop existing hostapd/dnsmasq: `sudo systemctl stop hostapd dnsmasq`
- [ ] Disable existing services: `sudo systemctl disable hostapd dnsmasq`
- [ ] Verify wlan0 exists: `ip link show wlan0`
- [ ] Verify eth0 exists: `ip link show eth0`
- [ ] Ensure wlan0 supports AP mode: `iw list | grep -A10 "Supported interface modes"`

---

## Files to Create/Modify

### New Files
- `/etc/lumier/hostapd.conf` (generated)
- `/etc/lumier/dnsmasq.conf` (generated)

### Modified Files
- `main.go` - Major changes (AP management, transparent proxy, new APIs)
- `device_data.json` - New fields for AP config and devices
- `README.md` - Updated documentation
- `QUICKSTART.md` - Updated quick start

### Deleted Files
- `android-app/` directory (entire)

---

## Security Considerations

1. **WPA2 encryption** for WiFi (not WEP)
2. **Isolated AP network** (192.168.50.0/24)
3. **No direct client-to-client** communication on AP
4. **Dashboard auth** still required for management
5. **MAC-based** device identification (can be spoofed, but acceptable for this use case)

---

## Rollback Plan

If issues occur:
1. Stop the proxy server
2. Run: `sudo systemctl start hostapd dnsmasq` (restore original services)
3. Clear iptables: `sudo iptables -F && sudo iptables -t nat -F`
4. Restore from git: `git checkout main.go`
