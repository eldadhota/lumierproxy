# Lumier Dynamics - Enterprise Proxy Management System

A comprehensive HTTP/HTTPS proxy server with device management, upstream SOCKS5 proxy routing, and a web dashboard for administration.

## Features

- **Multi-device proxy management** - Route multiple Android devices through different upstream SOCKS5 proxies
- **Web Dashboard** - Real-time device monitoring, proxy health, traffic analytics
- **Android App** - Easy device registration and proxy selection
- **Supervisor Management** - Multiple supervisor accounts with audit logging
- **Rollout Mode** - Lock device settings for end-user deployment
- **IP Geolocation** - Check which proxy IP a device is using
- **Persistent Storage** - Device configs survive server restarts

## Quick Start

### Windows
```powershell
# Double-click run_proxy.ps1 or run in PowerShell:
.\run_proxy.ps1
```

### Linux (Ubuntu/Debian)
```bash
# Make executable and run:
chmod +x run_proxy.sh
./run_proxy.sh
```

### Access Points
- **Dashboard**: http://YOUR_SERVER_IP:8080
- **Proxy Port**: 8888 (configure on Android devices)
- **Default Login**: admin / admin123

---

## Access Point (AP) Mode - Recommended Setup

The recommended deployment method uses a WiFi Access Point for automatic device management:

### Setup Steps

1. **Run the AP setup script** (Linux):
   ```bash
   sudo ./scripts/ap-setup.sh
   ```

2. **Start the LumierProxy service**:
   ```bash
   ./lumierproxy
   # Or as a service:
   sudo systemctl start lumierproxy
   ```

3. **Connect devices to the WiFi network** (SSID: `LumierProxy`)

4. **Approve devices in the dashboard**:
   - Open http://YOUR_SERVER_IP:8080
   - Go to Devices tab
   - Click "Approve" on pending devices
   - Assign proxies to approved devices

5. **Verify traffic routing**:
   - Approved devices get internet only through assigned proxy
   - Unapproved devices are blocked

### Why AP Mode?

- **No per-device configuration** - Devices auto-configure via WPAD/PAC
- **Prevent bypass** - Devices cannot access internet directly
- **Easy management** - Approve/assign proxies from dashboard
- **MAC-based tracking** - Even with IP changes, devices are tracked

For detailed AP deployment, see `SETUP_GUIDE.md`.

---

## Server Setup

### Prerequisites
- Go 1.19 or later
- Network access to upstream SOCKS5 proxies

### Configuration Files

#### proxies.txt
Add your upstream SOCKS5 proxies (one per line):
```
host:port:username:password
```
Example:
```
brd.superproxy.io:22228:brd-customer-xxx-ip-1.2.3.4:password123
brd.superproxy.io:22228:brd-customer-xxx-ip-5.6.7.8:password456
```

#### Environment Variables (Optional)
| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | 0.0.0.0 | Interface to bind to |
| `PROXY_PORT` | 8888 | HTTP proxy port for devices |
| `DASHBOARD_PORT` | 8080 | Web dashboard port |
| `REQUIRE_REGISTRATION` | true | Block unregistered devices |
| `ALLOW_IP_FALLBACK` | false | Match devices by IP if no username |

### Running as a Service (Linux)

```bash
# Install as systemd service
sudo ./install.sh

# Control the service
sudo systemctl start lumier-dynamics
sudo systemctl stop lumier-dynamics
sudo systemctl status lumier-dynamics

# View logs
sudo journalctl -u lumier-dynamics -f
```

---

## Dashboard Guide

### Devices Page
- View all registered devices with status indicators
- **Green**: Active (seen in last 5 minutes)
- **Gray**: Offline
- Click device name to edit
- Change proxy assignment per device
- Filter by group, search by name/username

### Proxy Health Page
- Monitor upstream proxy status
- View success/failure rates
- Check response times

### Analytics Page
- Traffic statistics over time
- Peak device counts
- Error rates

### Settings Page

#### Change Password
Update your dashboard login password.

#### Device Groups
Create groups to organize devices (e.g., by location, team).

#### Proxy Management
- Add/remove upstream SOCKS5 proxies
- Bulk import proxies (paste multiple lines)

#### Supervisor Management
Manage passwords for the Android app:

**Admin Password** (for Register Device button):
- Default: `Drnda123`
- Used when registering new devices

**Supervisor Passwords** (for Change Proxy button):
- Each supervisor has a name and password
- Changes are logged with supervisor name for audit
- Default supervisors: Mirko, Ana, Marko, Ivan

### Monitoring Page
- Real-time CPU/memory usage
- Network traffic statistics
- Live server logs

---

## Android App Setup

### Installation
1. Build the APK from `android-app/` directory using Android Studio
2. Install on Android device
3. Grant necessary permissions

### Configuration

1. **Server IP**: Enter your server's IP address
2. **Server Port**: Usually 8081 (API port, not proxy port)
3. **Username**: Unique identifier for this device
4. **Proxy**: Select from available upstream proxies

### Buttons

| Button | Password Required | Description |
|--------|-------------------|-------------|
| **Refresh** | No | Fetch available proxies from server |
| **Connect** | No | Test connection to server |
| **Register Device (Admin)** | Admin password | Register new device with server |
| **Change Proxy (Supervisor)** | Supervisor password | Change proxy for existing device |
| **Check IP** | No | Show current public IP and which proxy it belongs to |

### Rollout Mode

When "Rollout Setup" is checked during registration:
- All settings are locked (IP, port, username, proxy)
- Only Connect and Check IP buttons work
- Supervisors can temporarily unlock to make changes
- Prevents end-users from modifying device configuration

### Android WiFi Proxy Settings

After registering in the app:
1. Go to **Settings > WiFi**
2. Long-press your network > **Modify network**
3. Enable **Advanced options**
4. Set **Proxy** to **Manual**
5. **Hostname**: Your server IP
6. **Port**: 8888
7. Save

---

## API Endpoints

### App Endpoints (No Auth)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/app/proxies` | GET | List available proxies |
| `/api/app/register` | POST | Register new device |
| `/api/app/change-proxy` | POST | Change device's proxy |
| `/api/app/whoami` | GET | Get current public IP |
| `/api/app/check-ip` | POST | Check if IP matches a proxy |
| `/api/app/validate-password` | POST | Validate admin/supervisor password |

### Dashboard Endpoints (Auth Required)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices |
| `/api/proxies` | GET | List all proxies |
| `/api/change-proxy` | POST | Change device proxy |
| `/api/supervisors` | GET | List supervisors |
| `/api/add-supervisor` | POST | Add supervisor |
| `/api/update-supervisor` | POST | Update supervisor |
| `/api/delete-supervisor` | POST | Delete supervisor |
| `/api/admin-password` | POST | Update admin password |

---

## Troubleshooting

### Dashboard not accessible
1. Check firewall: `sudo ufw allow 8080/tcp`
2. Verify server is running: `netstat -tlnp | grep 8080`
3. Ensure binding to all interfaces (BIND_ADDR=0.0.0.0)

### Devices can't connect through proxy
1. Check firewall: `sudo ufw allow 8888/tcp`
2. Verify proxy port: `netstat -tlnp | grep 8888`
3. Test upstream proxy connectivity from server

### Android app can't reach server
1. Ensure phone and server on same network
2. Test: `http://SERVER_IP:8080` in phone browser
3. Check if server IP is correct in app settings

### Check IP shows wrong IP
1. Verify the device is using WiFi proxy (not mobile data)
2. Check that the correct proxy is selected
3. Ensure upstream proxy is working

### Password validation fails
1. Check server connectivity
2. Verify password in Dashboard > Settings > Supervisor Management
3. Fallback passwords work if server is unreachable

---

## File Structure

```
lumierproxy/
├── main.go              # Entry point and API handlers
├── server.go            # Type definitions, ProxyServer struct
├── auth.go              # Authentication, sessions
├── persistence.go       # Data save/load, pruning
├── proxy.go             # Proxy handling, SOCKS5, health monitoring
├── dhcp.go              # DHCP monitoring, AP traffic handling
├── logging.go           # Log and activity tracking
├── routes.go            # Route registration
├── utils.go             # Helper functions
├── embed.go             # Dashboard asset embedding
├── dashboard/           # Embedded dashboard assets
│   ├── pages/           # HTML pages (10 files)
│   ├── assets/          # CSS and JS files
│   └── partials/        # Shared HTML components
├── proxies.txt          # Upstream proxy list
├── device_data.json     # Persistent device/settings data
├── go.mod               # Go module definition
├── run_proxy.ps1        # Windows launcher
├── run_proxy.sh         # Linux launcher
├── deploy/              # Deployment scripts
│   ├── install.sh       # Linux service installer
│   └── quickstart.sh    # Quick setup script
├── scripts/             # AP setup scripts
│   ├── ap-setup.sh      # Access Point setup
│   └── ap-teardown.sh   # AP teardown
└── android-app/         # Android application source
```

---

## Security Notes

- Change default dashboard password immediately after first login
- Use strong passwords for admin and supervisors
- Keep `REQUIRE_REGISTRATION=true` in production
- Consider running behind a reverse proxy with HTTPS
- Supervisor passwords are stored in `device_data.json`

---

## Version History

### v3.0 (Current)
- Supervisor management in dashboard
- Server-side password validation
- Improved proxy selection dialog
- Rollout mode field locking
- Audit logging for proxy changes

### v2.0
- Device groups and search
- Traffic analytics
- Proxy health monitoring
- Export functionality

### v1.0
- Basic proxy routing
- Device registration
- Web dashboard
