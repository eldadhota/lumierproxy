package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	log.Println("===========================================")
	log.Println("🌐 Lumier Dynamics - Pure Go Proxy Server")
	log.Println("    Enterprise Edition v3.0")
	log.Println("===========================================")

	bindAddr := strings.TrimSpace(os.Getenv("BIND_ADDR"))
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	proxyPort := parseEnvInt("PROXY_PORT", 8888)
	dashPort := parseEnvInt("DASHBOARD_PORT", 8080)
	allowIPFallback := parseEnvBool("ALLOW_IP_FALLBACK", false)
	authRequired := parseEnvBool("AUTH_REQUIRED", false)
	requireRegister := parseEnvBool("REQUIRE_REGISTER", true) // Default: require app registration

	server = &ProxyServer{
		proxyPool:       loadProxyPool(),
		proxyHealth:     make(map[int]*ProxyHealth),
		proxyPort:       proxyPort,
		dashPort:        dashPort,
		bindAddr:        bindAddr,
		allowIPFallback: allowIPFallback,
		authRequired:    authRequired,
		requireRegister: requireRegister,
		dataFile:        "device_data.json",
		sessions:        make(map[string]*Session),
		startTime:         time.Now(),
		logBuffer:         make([]LogEntry, 0, 1000),
		deviceActivity:    make(map[string][]DeviceActivity),
		deviceConnections: make(map[string][]DeviceConnection),
		// Access Point initialization
		apDevices: make(map[string]*APDevice),
		apIPToMAC: make(map[string]string),
		// Rate limiting
		loginAttempts: make(map[string]*loginAttemptInfo),
		apConfig: APConfig{
			Enabled:      true,
			Interface:    "eth0",
			WANInterface: "wlan0",
			IPAddress:    "10.10.10.1",
			Netmask:      "255.255.255.0",
			DHCPStart:    "10.10.10.100",
			DHCPEnd:      "10.10.10.200",
			LeaseFile:    "/var/lib/lumier/dnsmasq.leases",
		},
		browserProfiles: make(map[string]*BrowserProfile),
		persistentData: PersistentData{
			DeviceConfigs:   make(map[string]DeviceConfig),
			Groups:          []string{"Default", "Floor 1", "Floor 2", "Team A", "Team B"},
			Users:           []UserCredentials{},
			TrafficHistory:  []TrafficSnapshot{},
			ProxyHealthData: make(map[int]*ProxyHealth),
			APDevices:       make(map[string]*APDevice),
			SystemSettings: SystemSettings{
				SessionTimeout:       2, // 2 hours default WiFi session timeout
				TrafficRetentionDays: 7,
				DeviceTimeoutMinutes: 30,
			},
		},
	}

	server.loadPersistentData()
	server.initializeProxyHealth()
	server.restoreAPDevices() // Restore AP devices from persistent data

	if len(server.persistentData.Users) == 0 {
		server.createDefaultAdmin()
	}

	if len(server.proxyPool) == 0 {
		log.Println("WARNING: No upstream proxies loaded!")
	} else {
		log.Printf("Loaded %d upstream proxies\n", len(server.proxyPool))
	}

	// Load embedded dashboard content
	initEmbeddedContent()

	go autoSaveData()
	go collectTrafficSnapshots()
	go cleanupExpiredSessions()
	go proxyHealthChecker()
	go cpuMonitor()
	go pruneStaleDevices()
	go server.monitorDHCPLeases() // Monitor for AP device connections
	go startDashboard()

	serverIP := getServerIP()
	log.Printf("Proxy server starting on port %d\n", server.proxyPort)
	log.Printf("Dashboard: http://%s:%d\n", serverIP, server.dashPort)
	log.Println("Default login: admin / admin123")
	log.Printf("Access Point: Devices on 10.10.10.x network will be proxied\n")

	// Use http.Server with timeouts for security (prevents slow loris attacks)
	proxyServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", server.bindAddr, server.proxyPort),
		Handler:           http.HandlerFunc(handleProxy),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// Note: WriteTimeout not set for proxy to allow long downloads
	}
	if err := proxyServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// ============================================================================
// API HANDLERS
// ============================================================================

func handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting: check for lockout
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	server.loginMu.Lock()
	attempt, exists := server.loginAttempts[clientIP]
	if exists && time.Now().Before(attempt.LockedUntil) {
		server.loginMu.Unlock()
		remaining := time.Until(attempt.LockedUntil).Round(time.Second)
		http.Error(w, fmt.Sprintf("Too many failed attempts. Try again in %s", remaining), http.StatusTooManyRequests)
		return
	}
	server.loginMu.Unlock()

	var req loginRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !server.validateCredentials(req.Username, req.Password) {
		// Record failed attempt
		server.loginMu.Lock()
		if server.loginAttempts[clientIP] == nil {
			server.loginAttempts[clientIP] = &loginAttemptInfo{}
		}
		attempt := server.loginAttempts[clientIP]
		attempt.Count++
		attempt.LastAttempt = time.Now()

		// Lock out after 5 failed attempts for 5 minutes
		if attempt.Count >= 5 {
			attempt.LockedUntil = time.Now().Add(5 * time.Minute)
			server.addLog("warning", fmt.Sprintf("IP %s locked out due to %d failed login attempts", clientIP, attempt.Count))
		}
		server.loginMu.Unlock()

		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Clear failed attempts on successful login
	server.loginMu.Lock()
	delete(server.loginAttempts, clientIP)
	server.loginMu.Unlock()

	token := server.createSession(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   server.persistentData.SystemSettings.SecureCookies,
		MaxAge:   server.persistentData.SystemSettings.SessionTimeout * 3600,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "username": req.Username})
}

func handleLogoutAPI(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil {
		server.sessionMu.Lock()
		delete(server.sessions, cookie.Value)
		server.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		Secure:   server.persistentData.SystemSettings.SecureCookies,
	})
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleSessionCheckAPI(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}
	session, valid := server.validateSession(cookie.Value)
	if !valid {
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"valid": true, "username": session.Username})
}

func handleChangePasswordAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, _ := r.Cookie("session_token")
	session, _ := server.validateSession(cookie.Value)
	var req changePasswordRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !server.validateCredentials(session.Username, req.OldPassword) {
		http.Error(w, "current password is incorrect", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	for i, user := range server.persistentData.Users {
		if user.Username == session.Username {
			newSalt := generateSalt()
			server.persistentData.Users[i].Salt = newSalt
			server.persistentData.Users[i].PasswordHash = hashPassword(req.NewPassword, newSalt)
			break
		}
	}
	server.persistMu.Unlock()
	go server.savePersistentData()
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	// Stats from AP devices only
	server.apMu.RLock()
	activeCount, totalRequests, totalErrors, totalBytesIn, totalBytesOut := 0, int64(0), int64(0), int64(0), int64(0)
	for _, d := range server.apDevices {
		if d.Confirmed && time.Since(d.LastSeen) < 5*time.Minute {
			activeCount++
		}
		totalRequests += d.RequestCount
		totalErrors += d.ErrorCount
		totalBytesIn += d.BytesIn
		totalBytesOut += d.BytesOut
	}
	totalDevices := len(server.apDevices)
	server.apMu.RUnlock()

	server.healthMu.RLock()
	healthyProxies := 0
	for _, h := range server.proxyHealth {
		if h.Status == "healthy" || h.Status == "unknown" {
			healthyProxies++
		}
	}
	server.healthMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_devices":   totalDevices,
		"active_devices":  activeCount,
		"total_proxies":   len(server.proxyPool),
		"healthy_proxies": healthyProxies,
		"total_requests":  totalRequests,
		"total_errors":    totalErrors,
		"total_bytes_in":  totalBytesIn,
		"total_bytes_out": totalBytesOut,
	})
}

func handleServerIPAPI(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(getServerIP()))
}

func handleProxiesAPI(w http.ResponseWriter, r *http.Request) {
	server.poolMu.Lock()
	defer server.poolMu.Unlock()
	proxies := make([]ProxyInfo, 0)
	for i, line := range server.proxyPool {
		parts := strings.Split(line, ":")
		if len(parts) >= 4 {
			proxies = append(proxies, ProxyInfo{
				Index:      i,
				Host:       parts[0],
				Port:       parts[1],
				User:       parts[2],
				Pass:       parts[3],
				Full:       line,
				CustomName: server.getProxyName(i),
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proxies)
}


// handleAccessPointPage serves the Access Point management page
func handleAccessPointPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write(accessPointPageHTML)
}

// handleAPStatusAPI returns the current AP network status
func handleAPStatusAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	server.apMu.RLock()
	totalDevices := len(server.apDevices)
	onlineDevices := 0
	confirmedDevices := 0
	pendingDevices := 0
	for _, device := range server.apDevices {
		if device.Status == "online" {
			onlineDevices++
		}
		if device.Confirmed {
			confirmedDevices++
		} else {
			pendingDevices++
		}
	}
	server.apMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":           server.apConfig.Enabled,
		"interface":         server.apConfig.Interface,
		"ip_address":        server.apConfig.IPAddress,
		"dhcp_range":        fmt.Sprintf("%s - %s", server.apConfig.DHCPStart, server.apConfig.DHCPEnd),
		"total_devices":     totalDevices,
		"online_devices":    onlineDevices,
		"confirmed_devices": confirmedDevices,
		"pending_devices":   pendingDevices,
	})
}

// handleAPDevicesAPI returns list of all AP devices
func handleAPDevicesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	server.apMu.RLock()
	devices := make([]*APDevice, 0, len(server.apDevices))
	for _, device := range server.apDevices {
		devices = append(devices, device)
	}
	server.apMu.RUnlock()

	// Sort by FirstSeen (newest first)
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].FirstSeen.After(devices[j].FirstSeen)
	})

	// Add proxy names
	type DeviceWithProxyName struct {
		*APDevice
		ProxyName string `json:"proxy_name"`
	}

	result := make([]DeviceWithProxyName, len(devices))
	for i, device := range devices {
		result[i] = DeviceWithProxyName{
			APDevice:  device,
			ProxyName: server.getProxyName(device.ProxyIndex),
		}
	}

	json.NewEncoder(w).Encode(result)
}

// handleAPDeviceConfirmAPI confirms (approves) or unconfirms an AP device
func handleAPDeviceConfirmAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MAC        string `json:"mac"`
		Confirmed  bool   `json:"confirmed"`
		CustomName string `json:"custom_name"`
		ProxyIndex int    `json:"proxy_index"`
		Group      string `json:"group"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mac := strings.ToLower(req.MAC)

	server.apMu.Lock()
	device, exists := server.apDevices[mac]
	if !exists {
		server.apMu.Unlock()
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	device.Confirmed = req.Confirmed
	if req.Confirmed {
		device.ConfirmedAt = time.Now()
		device.ConfirmedBy = "admin" // Could get from session

		// Set custom name if provided
		if req.CustomName != "" {
			device.CustomName = req.CustomName
		}

		// Set group if provided
		if req.Group != "" {
			device.Group = req.Group
		}

		// Assign proxy if provided (during approval)
		if req.ProxyIndex >= 0 {
			server.poolMu.Lock()
			if req.ProxyIndex < len(server.proxyPool) {
				device.ProxyIndex = req.ProxyIndex
				device.UpstreamProxy = server.proxyPool[req.ProxyIndex]
			}
			server.poolMu.Unlock()
		}

		displayName := device.CustomName
		if displayName == "" {
			displayName = device.Hostname
		}
		server.addLog("info", fmt.Sprintf("[AP] Device approved: %s (%s) assigned to proxy #%d", displayName, device.MAC, device.ProxyIndex+1))
	} else {
		server.addLog("info", fmt.Sprintf("[AP] Device access revoked: %s (%s)", device.Hostname, device.MAC))
	}
	server.apMu.Unlock()

	// Save to persistent data
	server.persistMu.Lock()
	if server.persistentData.APDevices == nil {
		server.persistentData.APDevices = make(map[string]*APDevice)
	}
	server.persistentData.APDevices[mac] = device
	server.persistMu.Unlock()

	// Save immediately
	server.savePersistentData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"confirmed": device.Confirmed,
	})
}

// handleAPDeviceProxyAPI changes the proxy assignment for an AP device
func handleAPDeviceProxyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MAC        string `json:"mac"`
		ProxyIndex int    `json:"proxy_index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mac := strings.ToLower(req.MAC)

	server.poolMu.Lock()
	if req.ProxyIndex < 0 || req.ProxyIndex >= len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "Invalid proxy index", http.StatusBadRequest)
		return
	}
	proxyStr := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	server.apMu.Lock()
	device, exists := server.apDevices[mac]
	if !exists {
		server.apMu.Unlock()
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	oldProxy := device.ProxyIndex
	device.ProxyIndex = req.ProxyIndex
	device.UpstreamProxy = proxyStr
	server.apMu.Unlock()

	// Save to persistent data
	server.persistMu.Lock()
	server.persistentData.APDevices[mac] = device
	server.persistMu.Unlock()

	server.addLog("info", fmt.Sprintf("[AP] Proxy changed for %s (%s): %s -> %s",
		device.Hostname, device.MAC,
		server.getProxyName(oldProxy),
		server.getProxyName(req.ProxyIndex)))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"proxy_index": req.ProxyIndex,
		"proxy_name":  server.getProxyName(req.ProxyIndex),
	})
}

// handleAPDeviceUpdateAPI updates device name, group, or notes
func handleAPDeviceUpdateAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MAC        string `json:"mac"`
		CustomName string `json:"custom_name"`
		Group      string `json:"group"`
		Notes      string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mac := strings.ToLower(req.MAC)

	server.apMu.Lock()
	device, exists := server.apDevices[mac]
	if !exists {
		server.apMu.Unlock()
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	device.CustomName = req.CustomName
	device.Group = req.Group
	device.Notes = req.Notes
	server.apMu.Unlock()

	// Save to persistent data
	server.persistMu.Lock()
	server.persistentData.APDevices[mac] = device
	server.persistMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// handleAPDeviceDeleteAPI removes an AP device from the system
func handleAPDeviceDeleteAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MAC string `json:"mac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mac := strings.ToLower(req.MAC)

	server.apMu.Lock()
	device, exists := server.apDevices[mac]
	if !exists {
		server.apMu.Unlock()
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	delete(server.apDevices, mac)
	server.apMu.Unlock()

	// Remove from persistent data
	server.persistMu.Lock()
	delete(server.persistentData.APDevices, mac)
	server.persistMu.Unlock()

	server.addLog("info", fmt.Sprintf("[AP] Device removed: %s (%s)", device.Hostname, device.MAC))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// ============================================================================
// BROWSER PROFILES API HANDLERS
// ============================================================================

// handleBrowserProfilesAPI returns all browser profiles
func handleBrowserProfilesAPI(w http.ResponseWriter, r *http.Request) {
	server.browserMu.RLock()
	profiles := make([]*BrowserProfile, 0, len(server.browserProfiles))
	for _, p := range server.browserProfiles {
		// Add proxy name
		p.ProxyName = server.getProxyName(p.ProxyIndex)
		profiles = append(profiles, p)
	}
	server.browserMu.RUnlock()

	// Sort by name
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	// Count sessions today
	sessionsToday := 0
	today := time.Now().Truncate(24 * time.Hour)
	server.persistMu.RLock()
	totalSessions := len(server.persistentData.BrowserSessions)
	for _, s := range server.persistentData.BrowserSessions {
		if s.StartedAt.After(today) {
			sessionsToday++
		}
	}
	server.persistMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"profiles":       profiles,
		"total_sessions": totalSessions,
		"sessions_today": sessionsToday,
	})
}

// handleCreateBrowserProfileAPI creates a new browser profile
func handleCreateBrowserProfileAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name       string `json:"name"`
		ProxyIndex int    `json:"proxy_index"`
		Color      string `json:"color"`
		Notes      string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Generate unique ID
	id := fmt.Sprintf("bp-%d", time.Now().UnixNano())

	// Get proxy string from pool
	var upstreamProxy string
	server.poolMu.Lock()
	if req.ProxyIndex >= 0 && req.ProxyIndex < len(server.proxyPool) {
		upstreamProxy = server.proxyPool[req.ProxyIndex]
	}
	server.poolMu.Unlock()

	profile := &BrowserProfile{
		ID:            id,
		Name:          req.Name,
		ProxyIndex:    req.ProxyIndex,
		UpstreamProxy: upstreamProxy,
		Color:         req.Color,
		Notes:         req.Notes,
		CreatedAt:     time.Now(),
		CreatedBy:     "admin",
	}

	server.browserMu.Lock()
	server.browserProfiles[id] = profile
	server.browserMu.Unlock()

	// Save to persistent data
	server.persistMu.Lock()
	if server.persistentData.BrowserProfiles == nil {
		server.persistentData.BrowserProfiles = make(map[string]*BrowserProfile)
	}
	server.persistentData.BrowserProfiles[id] = profile
	server.persistMu.Unlock()

	server.savePersistentData()
	server.addLog("info", fmt.Sprintf("[Browser] Profile created: %s", profile.Name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"profile": profile,
	})
}

// handleUpdateBrowserProfileAPI updates a browser profile
func handleUpdateBrowserProfileAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		ProxyIndex int    `json:"proxy_index"`
		Color      string `json:"color"`
		Notes      string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	server.browserMu.Lock()
	profile, exists := server.browserProfiles[req.ID]
	if !exists {
		server.browserMu.Unlock()
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	if req.Name != "" {
		profile.Name = req.Name
	}
	if req.ProxyIndex >= 0 {
		profile.ProxyIndex = req.ProxyIndex
		server.poolMu.Lock()
		if req.ProxyIndex < len(server.proxyPool) {
			profile.UpstreamProxy = server.proxyPool[req.ProxyIndex]
		}
		server.poolMu.Unlock()
	}
	if req.Color != "" {
		profile.Color = req.Color
	}
	profile.Notes = req.Notes
	server.browserMu.Unlock()

	// Save to persistent data
	server.persistMu.Lock()
	if server.persistentData.BrowserProfiles == nil {
		server.persistentData.BrowserProfiles = make(map[string]*BrowserProfile)
	}
	server.persistentData.BrowserProfiles[req.ID] = profile
	server.persistMu.Unlock()

	server.savePersistentData()
	server.addLog("info", fmt.Sprintf("[Browser] Profile updated: %s", profile.Name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"profile": profile,
	})
}

// handleDeleteBrowserProfileAPI deletes a browser profile
func handleDeleteBrowserProfileAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	server.browserMu.Lock()
	profile, exists := server.browserProfiles[req.ID]
	if !exists {
		server.browserMu.Unlock()
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	name := profile.Name
	delete(server.browserProfiles, req.ID)
	server.browserMu.Unlock()

	// Remove from persistent data
	server.persistMu.Lock()
	delete(server.persistentData.BrowserProfiles, req.ID)
	server.persistMu.Unlock()

	server.savePersistentData()
	server.addLog("info", fmt.Sprintf("[Browser] Profile deleted: %s", name))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// handleBrowserSessionAPI logs a browser session start/stop or returns session list
func handleBrowserSessionAPI(w http.ResponseWriter, r *http.Request) {
	// GET - return list of sessions
	if r.Method == http.MethodGet {
		limit := 20
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}

		server.persistMu.RLock()
		sessions := server.persistentData.BrowserSessions
		server.persistMu.RUnlock()

		// Get profile names for each session
		server.browserMu.RLock()
		type SessionWithName struct {
			BrowserSession
			ProfileName string `json:"profile_name"`
		}
		result := make([]SessionWithName, 0)
		// Return in reverse order (newest first)
		start := len(sessions) - limit
		if start < 0 {
			start = 0
		}
		for i := len(sessions) - 1; i >= start; i-- {
			s := sessions[i]
			name := s.ProfileID
			if p, ok := server.browserProfiles[s.ProfileID]; ok {
				name = p.Name
			}
			result = append(result, SessionWithName{
				BrowserSession: s,
				ProfileName:    name,
			})
		}
		server.browserMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request - support both JSON and form data
	var profileID, action, username string
	var duration int64

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		r.ParseForm()
		profileID = r.FormValue("profile_id")
		action = r.FormValue("action")
		username = r.FormValue("username")
		if d := r.FormValue("duration"); d != "" {
			duration, _ = strconv.ParseInt(d, 10, 64)
		}
	} else {
		var req struct {
			ProfileID string `json:"profile_id"`
			Action    string `json:"action"`
			Username  string `json:"username"`
			Duration  int64  `json:"duration"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		profileID = req.ProfileID
		action = req.Action
		username = req.Username
		duration = req.Duration
	}

	server.browserMu.Lock()
	profile, exists := server.browserProfiles[profileID]
	if !exists {
		server.browserMu.Unlock()
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	if action == "start" {
		profile.LastUsedAt = time.Now()
		profile.LastUsedBy = username
		profile.SessionCount++

		// Log session start
		session := BrowserSession{
			ID:        fmt.Sprintf("bs-%d", time.Now().UnixNano()),
			ProfileID: profileID,
			Username:  username,
			StartedAt: time.Now(),
		}

		server.persistMu.Lock()
		server.persistentData.BrowserSessions = append(server.persistentData.BrowserSessions, session)
		// Keep only last 500 sessions
		if len(server.persistentData.BrowserSessions) > 500 {
			server.persistentData.BrowserSessions = server.persistentData.BrowserSessions[len(server.persistentData.BrowserSessions)-500:]
		}
		server.persistMu.Unlock()

		server.addLog("info", fmt.Sprintf("[Browser] Session started: %s by %s", profile.Name, username))
	} else if action == "stop" {
		// Update last session with duration if available
		if duration > 0 {
			server.persistMu.Lock()
			for i := len(server.persistentData.BrowserSessions) - 1; i >= 0; i-- {
				s := &server.persistentData.BrowserSessions[i]
				if s.ProfileID == profileID && s.Username == username && s.Duration == 0 {
					s.EndedAt = time.Now()
					s.Duration = duration
					break
				}
			}
			server.persistMu.Unlock()
		}
		server.addLog("info", fmt.Sprintf("[Browser] Session ended: %s by %s (duration: %ds)", profile.Name, username, duration))
	}
	server.browserMu.Unlock()

	// Update persistent data
	server.persistMu.Lock()
	if server.persistentData.BrowserProfiles == nil {
		server.persistentData.BrowserProfiles = make(map[string]*BrowserProfile)
	}
	server.persistentData.BrowserProfiles[profileID] = profile
	server.persistMu.Unlock()

	server.savePersistentData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// handleClientDownload serves the Windows client executable or instructions
func handleClientDownload(w http.ResponseWriter, r *http.Request) {
	// Check if pre-built Windows client exists
	clientPath := "lumier-client.exe"
	if _, err := os.Stat(clientPath); err == nil {
		// Serve the executable
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=lumier-client.exe")
		http.ServeFile(w, r, clientPath)
		return
	}

	// Otherwise, serve instructions/bootstrap script
	w.Header().Set("Content-Type", "text/plain")
	instructions := `# Lumier Browser Profile Client - Setup Instructions

## Option 1: Download Pre-built Client

If your administrator has compiled the client, download it from:
` + fmt.Sprintf("%s/lumier-client.exe", r.Host) + `

## Option 2: Build from Source (Requires Go)

1. Install Go: https://go.dev/dl/
2. Download the client source code from your administrator
3. Build for Windows:
   go build -o lumier-client.exe .
4. Run lumier-client.exe

## Option 3: Use PowerShell Script

Save this as "lumier-launcher.ps1" and run with PowerShell:

$ServerURL = "` + "http://" + r.Host + `"
$ProfilesURL = "$ServerURL/api/browser-profiles"

# Fetch profiles
$response = Invoke-RestMethod -Uri $ProfilesURL
$profiles = $response.profiles

if ($profiles.Count -eq 0) {
    Write-Host "No profiles found on server"
    exit
}

Write-Host "Available Profiles:"
for ($i = 0; $i -lt $profiles.Count; $i++) {
    Write-Host "  [$($i+1)] $($profiles[$i].name) - $($profiles[$i].proxy_name)"
}

$choice = Read-Host "Select profile number"
$idx = [int]$choice - 1
$profile = $profiles[$idx]

# Launch Firefox with proxy
$proxyParts = $profile.upstream_proxy -split ":"
$proxyHost = $proxyParts[0]
$proxyPort = $proxyParts[1]

# Create Firefox profile directory
$profileDir = "$env:APPDATA\LumierClient\profiles\$($profile.id)"
New-Item -ItemType Directory -Force -Path $profileDir | Out-Null

# Write Firefox preferences
$prefs = @"
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "$proxyHost");
user_pref("network.proxy.socks_port", $proxyPort);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("media.peerconnection.enabled", false);
"@
$prefs | Out-File "$profileDir\user.js" -Encoding ascii

# Find Firefox
$firefox = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
if (-not (Test-Path $firefox)) {
    $firefox = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
}

Write-Host "Launching Firefox with profile: $($profile.name)"
& $firefox -profile $profileDir -no-remote

Write-Host "Session ended"

---

For best results, use the compiled Go client (lumier-client.exe).
Contact your administrator for the pre-built executable.
`
	fmt.Fprint(w, instructions)
}

// handleBrowserProfilesPage serves the browser profiles management page
func handleBrowserProfilesPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write(browserProfilesPageHTML)
}

// ============================================================================
// CLIENT API HANDLERS (No auth required - for Windows client app)

// handleClientProfilesAPI returns approved devices for the Windows client (no auth)
func handleClientProfilesAPI(w http.ResponseWriter, r *http.Request) {
	devices := make([]ClientDevice, 0)

	// Get AP devices (confirmed only)
	server.apMu.RLock()
	for _, d := range server.apDevices {
		if d.Confirmed && d.UpstreamProxy != "" {
			name := d.CustomName
			if name == "" {
				name = d.Hostname
			}
			if name == "" {
				name = d.MAC
			}
			devices = append(devices, ClientDevice{
				ID:            d.MAC,
				Name:          name,
				ProxyIndex:    d.ProxyIndex,
				ProxyName:     server.getProxyName(d.ProxyIndex),
				UpstreamProxy: d.UpstreamProxy,
				Group:         d.Group,
				DeviceType:    "ap",
			})
		}
	}
	server.apMu.RUnlock()

	// Sort by name
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].Name < devices[j].Name
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"devices": devices,
	})
}

// handleClientSessionAPI logs sessions from the Windows client (no auth)
func handleClientSessionAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	deviceID := r.FormValue("device_id")
	deviceName := r.FormValue("device_name")
	proxyName := r.FormValue("proxy_name")
	action := r.FormValue("action")
	username := r.FormValue("username")
	duration, _ := strconv.ParseInt(r.FormValue("duration"), 10, 64)

	if deviceID == "" || username == "" {
		http.Error(w, "device_id and username required", http.StatusBadRequest)
		return
	}

	if action == "start" {
		session := BrowserSession{
			ID:         fmt.Sprintf("bs-%d", time.Now().UnixNano()),
			ProfileID:  deviceID, // Using ProfileID field to store device ID
			DeviceName: deviceName,
			ProxyName:  proxyName,
			Username:   username,
			StartedAt:  time.Now(),
		}

		server.persistMu.Lock()
		server.persistentData.BrowserSessions = append(server.persistentData.BrowserSessions, session)
		if len(server.persistentData.BrowserSessions) > 500 {
			server.persistentData.BrowserSessions = server.persistentData.BrowserSessions[len(server.persistentData.BrowserSessions)-500:]
		}
		server.persistMu.Unlock()

		server.addLog("info", fmt.Sprintf("[Browser Client] %s started session with device '%s' (proxy: %s)", username, deviceName, proxyName))
	} else if action == "stop" {
		if duration > 0 {
			server.persistMu.Lock()
			for i := len(server.persistentData.BrowserSessions) - 1; i >= 0; i-- {
				s := &server.persistentData.BrowserSessions[i]
				if s.ProfileID == deviceID && s.Username == username && s.Duration == 0 {
					s.EndedAt = time.Now()
					s.Duration = duration
					break
				}
			}
			server.persistMu.Unlock()
		}
		server.addLog("info", fmt.Sprintf("[Browser Client] %s ended session with device '%s' (duration: %ds)", username, deviceName, duration))
	}

	server.savePersistentData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// handleBulkImportProxiesAPI imports multiple proxies at once
func handleBulkImportProxiesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Proxies string `json:"proxies"` // Newline-separated proxy strings
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Proxies == "" {
		http.Error(w, "invalid request - provide 'proxies' field with newline-separated proxy strings", http.StatusBadRequest)
		return
	}

	lines := strings.Split(req.Proxies, "\n")
	added := 0
	skipped := 0
	errors := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Validate proxy format (host:port:user:pass)
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			errors = append(errors, fmt.Sprintf("Invalid format: %s", line[:min(50, len(line))]))
			skipped++
			continue
		}

		// Check if proxy already exists
		server.poolMu.Lock()
		exists := false
		for _, existing := range server.proxyPool {
			if existing == line {
				exists = true
				break
			}
		}

		if exists {
			server.poolMu.Unlock()
			skipped++
			continue
		}

		server.proxyPool = append(server.proxyPool, line)
		newIndex := len(server.proxyPool) - 1
		server.poolMu.Unlock()

		// Initialize health tracking
		server.healthMu.Lock()
		server.proxyHealth[newIndex] = &ProxyHealth{
			Index:         newIndex,
			ProxyString:   line,
			IPAddress:     extractProxyIP(line),
			Status:        "unknown",
			UniqueDevices: make(map[string]bool),
		}
		server.healthMu.Unlock()

		added++
	}

	// Save to proxies.txt
	if added > 0 {
		server.poolMu.Lock()
		content := strings.Join(server.proxyPool, "\n")
		server.poolMu.Unlock()
		os.WriteFile("proxies.txt", []byte(content), 0644)
		server.addLog("info", fmt.Sprintf("Bulk imported %d proxies", added))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"added":   added,
		"skipped": skipped,
		"errors":  errors,
		"message": fmt.Sprintf("Added %d proxies, skipped %d", added, skipped),
	})
}

func handleProxyHealthAPI(w http.ResponseWriter, r *http.Request) {
	server.healthMu.RLock()
	healthData := make([]*ProxyHealth, 0)
	for _, h := range server.proxyHealth {
		healthData = append(healthData, h)
	}
	server.healthMu.RUnlock()
	sort.Slice(healthData, func(i, j int) bool { return healthData[i].Index < healthData[j].Index })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthData)
}

// handleDiagnosticsAPI returns diagnostic data for proxy usage and device health
func handleDiagnosticsAPI(w http.ResponseWriter, r *http.Request) {
	// Collect proxy diagnostics
	server.healthMu.RLock()
	proxyDiagnostics := make([]map[string]interface{}, 0)
	var totalRequests, totalSuccess, totalFailure int64

	for _, h := range server.proxyHealth {
		proxyName := server.getProxyName(h.Index)

		// Determine issue type based on success rate
		issueType := "none"
		issueDetails := ""

		if h.TotalRequests > 10 {
			if h.SuccessRate < 50 {
				issueType = "broken"
				issueDetails = fmt.Sprintf("Very low success rate: %.1f%%. Last error: %s", h.SuccessRate, h.LastError)
			} else if h.SuccessRate < 80 {
				issueType = "degraded"
				issueDetails = fmt.Sprintf("Degraded success rate: %.1f%%", h.SuccessRate)
			}
		}

		totalRequests += h.TotalRequests
		totalSuccess += h.SuccessCount
		totalFailure += h.FailureCount

		proxyDiagnostics = append(proxyDiagnostics, map[string]interface{}{
			"index":             h.Index,
			"name":              proxyName,
			"ip_address":        h.IPAddress,
			"total_requests":    h.TotalRequests,
			"success_count":     h.SuccessCount,
			"failure_count":     h.FailureCount,
			"success_rate":      h.SuccessRate,
			"status":            h.Status,
			"issue_type":        issueType,
			"issue_details":     issueDetails,
			"last_error":        h.LastError,
			"bytes_in":          h.BytesIn,
			"bytes_out":         h.BytesOut,
			"active_devices":    h.ActiveDevices,
			"device_count":      h.DeviceCount,
		})
	}
	server.healthMu.RUnlock()

	// Sort by index
	sort.Slice(proxyDiagnostics, func(i, j int) bool {
		return proxyDiagnostics[i]["index"].(int) < proxyDiagnostics[j]["index"].(int)
	})

	// Collect device health summary from AP devices
	server.apMu.RLock()
	var activeDevices, inactiveDevices, errorDevices int
	var totalDeviceRequests, totalDeviceErrors int64
	deviceHealthSummary := make([]map[string]interface{}, 0)

	for _, device := range server.apDevices {
		if !device.Confirmed {
			continue // Skip unconfirmed devices
		}
		isActive := time.Since(device.LastSeen) < 5*time.Minute
		if isActive {
			activeDevices++
		} else {
			inactiveDevices++
		}
		if device.ErrorCount > 0 {
			errorDevices++
		}
		totalDeviceRequests += device.RequestCount
		totalDeviceErrors += device.ErrorCount

		// Get proxy name for this device
		proxyName := server.getProxyName(device.ProxyIndex)

		// Calculate device error rate
		var errorRate float64
		if device.RequestCount > 0 {
			errorRate = float64(device.ErrorCount) / float64(device.RequestCount) * 100
		}

		name := device.CustomName
		if name == "" {
			name = device.Hostname
		}

		deviceHealthSummary = append(deviceHealthSummary, map[string]interface{}{
			"mac":           device.MAC,
			"name":          name,
			"ip":            device.IP,
			"proxy_name":    proxyName,
			"request_count": device.RequestCount,
			"error_count":   device.ErrorCount,
			"error_rate":    errorRate,
			"bytes_in":      device.BytesIn,
			"bytes_out":     device.BytesOut,
			"last_seen":     device.LastSeen,
			"is_active":     isActive,
			"last_error":    device.LastError,
		})
	}
	server.apMu.RUnlock()

	// Sort devices by request count (most active first)
	sort.Slice(deviceHealthSummary, func(i, j int) bool {
		return deviceHealthSummary[i]["request_count"].(int64) > deviceHealthSummary[j]["request_count"].(int64)
	})

	// Calculate rates
	overallSuccessRate := float64(0)
	if totalRequests > 0 {
		overallSuccessRate = float64(totalSuccess) / float64(totalRequests) * 100
	}
	deviceErrorRate := float64(0)
	if totalDeviceRequests > 0 {
		deviceErrorRate = float64(totalDeviceErrors) / float64(totalDeviceRequests) * 100
	}

	// Count issue types
	var brokenCount, degradedCount, healthyCount int
	for _, p := range proxyDiagnostics {
		switch p["issue_type"].(string) {
		case "broken":
			brokenCount++
		case "degraded":
			degradedCount++
		default:
			healthyCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"proxies":              proxyDiagnostics,
		"devices":              deviceHealthSummary,
		"summary": map[string]interface{}{
			"total_proxies":        len(proxyDiagnostics),
			"healthy_proxies":      healthyCount,
			"degraded_proxies":     degradedCount,
			"broken_proxies":       brokenCount,
			"total_requests":       totalRequests,
			"total_success":        totalSuccess,
			"total_failure":        totalFailure,
			"overall_success_rate": overallSuccessRate,
			"active_devices":       activeDevices,
			"inactive_devices":     inactiveDevices,
			"error_devices":        errorDevices,
			"device_error_rate":    deviceErrorRate,
		},
	})
}

func handleTrafficHistoryAPI(w http.ResponseWriter, r *http.Request) {
	server.persistMu.RLock()
	history := server.persistentData.TrafficHistory
	server.persistMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func handleGroupsAPI(w http.ResponseWriter, r *http.Request) {
	server.persistMu.RLock()
	groups := server.persistentData.Groups
	server.persistMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

func handleAddGroupAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req addGroupRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.GroupName == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	exists := false
	for _, g := range server.persistentData.Groups {
		if g == req.GroupName {
			exists = true
			break
		}
	}
	if !exists {
		server.persistentData.Groups = append(server.persistentData.Groups, req.GroupName)
	}
	server.persistMu.Unlock()
	go server.savePersistentData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "added": !exists})
}

func handleDeleteGroupAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deleteGroupRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.GroupName == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Prevent deleting the "Default" group
	if req.GroupName == "Default" {
		http.Error(w, "cannot delete Default group", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	deleted := false
	newGroups := make([]string, 0)
	for _, g := range server.persistentData.Groups {
		if g == req.GroupName {
			deleted = true
		} else {
			newGroups = append(newGroups, g)
		}
	}
	server.persistentData.Groups = newGroups
	// Move devices from deleted group to Default
	for key, config := range server.persistentData.DeviceConfigs {
		if config.Group == req.GroupName {
			config.Group = "Default"
			server.persistentData.DeviceConfigs[key] = config
		}
	}
	server.persistMu.Unlock()
	// Also update in-memory AP devices
	server.apMu.Lock()
	for _, device := range server.apDevices {
		if device.Group == req.GroupName {
			device.Group = "Default"
		}
	}
	server.apMu.Unlock()
	go server.savePersistentData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "deleted": deleted})
}

func handleAddProxyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req addProxyRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.ProxyString == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Validate proxy format (host:port:user:pass)
	parts := strings.Split(req.ProxyString, ":")
	if len(parts) < 4 {
		http.Error(w, "invalid proxy format. Use: host:port:username:password", http.StatusBadRequest)
		return
	}
	// Check if proxy already exists
	server.poolMu.Lock()
	for _, p := range server.proxyPool {
		if p == req.ProxyString {
			server.poolMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "added": false, "message": "Proxy already exists"})
			return
		}
	}
	server.proxyPool = append(server.proxyPool, req.ProxyString)
	newIndex := len(server.proxyPool) - 1
	server.poolMu.Unlock()
	// Initialize health for new proxy
	server.healthMu.Lock()
	server.proxyHealth[newIndex] = &ProxyHealth{
		Index:         newIndex,
		ProxyString:   req.ProxyString,
		IPAddress:     extractProxyIP(req.ProxyString),
		Status:        "unknown",
		UniqueDevices: make(map[string]bool),
	}
	server.healthMu.Unlock()
	// Save to proxies.txt
	go saveProxyPool()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "added": true, "index": newIndex})
}

func handleDeleteProxyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deleteProxyRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.poolMu.Lock()
	if req.ProxyIndex < 0 || req.ProxyIndex >= len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "invalid proxy index", http.StatusBadRequest)
		return
	}
	// Check if any AP devices are using this proxy
	deletedProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	server.apMu.RLock()
	devicesUsingProxy := 0
	for _, device := range server.apDevices {
		if device.UpstreamProxy == deletedProxy {
			devicesUsingProxy++
		}
	}
	server.apMu.RUnlock()

	if devicesUsingProxy > 0 {
		http.Error(w, fmt.Sprintf("Cannot delete: %d device(s) are using this proxy. Reassign them first.", devicesUsingProxy), http.StatusBadRequest)
		return
	}

	// Remove proxy from pool
	server.poolMu.Lock()
	server.proxyPool = append(server.proxyPool[:req.ProxyIndex], server.proxyPool[req.ProxyIndex+1:]...)
	server.poolMu.Unlock()

	// Remove health data and reindex
	server.healthMu.Lock()
	delete(server.proxyHealth, req.ProxyIndex)
	// Reindex remaining proxies
	newHealth := make(map[int]*ProxyHealth)
	for i, proxy := range server.proxyPool {
		for _, h := range server.proxyHealth {
			if h.ProxyString == proxy {
				h.Index = i
				newHealth[i] = h
				break
			}
		}
	}
	server.proxyHealth = newHealth
	server.healthMu.Unlock()

	// Update device configs that had higher proxy indices
	server.persistMu.Lock()
	for key, config := range server.persistentData.DeviceConfigs {
		if config.ProxyIndex > req.ProxyIndex {
			config.ProxyIndex--
			server.persistentData.DeviceConfigs[key] = config
		}
	}
	server.persistMu.Unlock()

	go saveProxyPool()
	go server.savePersistentData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "deleted": true})
}

func handleExportAPI(w http.ResponseWriter, r *http.Request) {
	server.apMu.RLock()
	devices := make([]*APDevice, 0)
	for _, d := range server.apDevices {
		devices = append(devices, d)
	}
	server.apMu.RUnlock()
	server.healthMu.RLock()
	healthData := make([]*ProxyHealth, 0)
	for _, h := range server.proxyHealth {
		healthData = append(healthData, h)
	}
	server.healthMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=lumier_export.json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"exported_at":  time.Now().Format(time.RFC3339),
		"devices":      devices,
		"proxy_health": healthData,
	})
}

// ============================================================================
// HTML PAGE HANDLERS AND TEMPLATES
// ============================================================================

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil {
		if _, valid := server.validateSession(cookie.Value); valid {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(loginPageHTML))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardPageHTML))
}

func handleHealthPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(healthPageHTML))
}

func handleDiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(diagnosticsPageHTML))
}

func handleAnalyticsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(analyticsPageHTML))
}

func handleActivityPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(activityPageHTML))
}

func handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(settingsPageHTML))
}

func handleMonitoringPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(monitoringPageHTML))
}

func handleSystemStatsAPI(w http.ResponseWriter, r *http.Request) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	server.cpuMu.RLock()
	cpuUsage := server.cpuUsage
	server.cpuMu.RUnlock()

	server.apMu.RLock()
	var totalBytesIn, totalBytesOut, totalRequests int64
	activeDevices := 0
	for _, d := range server.apDevices {
		totalBytesIn += d.BytesIn
		totalBytesOut += d.BytesOut
		totalRequests += d.RequestCount
		if d.Confirmed && time.Since(d.LastSeen) < 5*time.Minute {
			activeDevices++
		}
	}
	totalDevices := len(server.apDevices)
	server.apMu.RUnlock()

	uptime := time.Since(server.startTime)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cpu_usage":        cpuUsage,
		"memory_used":      memStats.Alloc,
		"memory_total":     memStats.Sys,
		"memory_heap":      memStats.HeapAlloc,
		"goroutines":       runtime.NumGoroutine(),
		"uptime_seconds":   int64(uptime.Seconds()),
		"uptime_formatted": formatUptime(uptime),
		"total_bytes_in":   totalBytesIn,
		"total_bytes_out":  totalBytesOut,
		"total_requests":   totalRequests,
		"total_devices":    totalDevices,
		"active_devices":   activeDevices,
		"total_proxies":    len(server.proxyPool),
	})
}

func handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	// Support filtering by device, category, and level
	query := r.URL.Query()
	deviceIP := query.Get("device_ip")
	category := query.Get("category")
	level := query.Get("level")
	limitStr := query.Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	allLogs := server.getLogs(1000) // Get more logs for filtering

	// Filter logs
	var filtered []LogEntry
	for _, log := range allLogs {
		if deviceIP != "" && log.DeviceIP != deviceIP {
			continue
		}
		if category != "" && log.Category != category {
			continue
		}
		if level != "" && log.Level != level {
			continue
		}
		filtered = append(filtered, log)
	}

	// Apply limit after filtering
	if len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered)
}

// handleDeviceActivityAPI returns activity log for a specific device
func handleDeviceActivityAPI(w http.ResponseWriter, r *http.Request) {
	deviceIP := r.URL.Query().Get("device_ip")
	if deviceIP == "" {
		http.Error(w, "device_ip parameter required", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	activities := server.getDeviceActivity(deviceIP, limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activities)
}

// handleActivityLogAPI returns a comprehensive activity log with filtering
func handleActivityLogAPI(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filterCategory := query.Get("category")
	filterLevel := query.Get("level")
	filterDevice := query.Get("device")
	registeredOnly := query.Get("registered_only") == "true"
	limitStr := query.Get("limit")
	limit := 200
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Get all logs (up to 1000)
	allLogs := server.getLogs(1000)

	// Build a set of registered device IPs/MACs for filtering
	registeredDevices := make(map[string]bool)
	if registeredOnly {
		server.apMu.RLock()
		for _, device := range server.apDevices {
			if device.Confirmed {
				registeredDevices[device.MAC] = true
				registeredDevices[device.IP] = true
			}
		}
		server.apMu.RUnlock()
	}

	// Build response with filtering
	var result []map[string]interface{}
	for _, log := range allLogs {
		// Apply filters
		if filterCategory != "" && log.Category != filterCategory {
			continue
		}
		if filterLevel != "" && log.Level != filterLevel {
			continue
		}
		if filterDevice != "" {
			if log.DeviceIP != filterDevice && log.Username != filterDevice && log.DeviceName != filterDevice {
				continue
			}
		}
		// Filter unregistered devices
		if registeredOnly && log.DeviceIP != "" {
			if !registeredDevices[log.DeviceIP] && !registeredDevices[log.Username] {
				continue
			}
		}

		entry := map[string]interface{}{
			"timestamp":   log.Timestamp,
			"level":       log.Level,
			"message":     log.Message,
			"category":    log.Category,
			"device_ip":   log.DeviceIP,
			"device_name": log.DeviceName,
			"username":    log.Username,
		}
		result = append(result, entry)
	}

	// Apply limit
	if len(result) > limit {
		result = result[len(result)-limit:]
	}

	// Get summary stats
	var errorCount, warnCount, infoCount int
	for _, log := range allLogs {
		switch log.Level {
		case "error":
			errorCount++
		case "warn", "warning":
			warnCount++
		case "info":
			infoCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":        result,
		"total_count": len(allLogs),
		"error_count": errorCount,
		"warn_count":  warnCount,
		"info_count":  infoCount,
		"categories":  []string{"connection", "auth", "proxy", "error", "session", "config"},
	})
}

func handleSupervisorsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	server.persistMu.RLock()
	supervisors := server.persistentData.Supervisors
	adminPassword := server.persistentData.AdminPassword
	server.persistMu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"supervisors":    supervisors,
		"admin_password": adminPassword,
	})
}

func handleAddSupervisorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req Supervisor
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Password == "" {
		http.Error(w, "name and password required", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	// Check if name already exists
	for _, s := range server.persistentData.Supervisors {
		if s.Name == req.Name {
			server.persistMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "message": "Supervisor name already exists"})
			return
		}
	}
	server.persistentData.Supervisors = append(server.persistentData.Supervisors, req)
	server.persistMu.Unlock()
	server.savePersistentData()
	log.Printf("👤 Added supervisor: %s\n", req.Name)
	server.addLog("info", fmt.Sprintf("Added supervisor: %s", req.Name))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleUpdateSupervisorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OldName  string `json:"old_name"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	found := false
	for i, s := range server.persistentData.Supervisors {
		if s.Name == req.OldName {
			server.persistentData.Supervisors[i] = Supervisor{Name: req.Name, Password: req.Password}
			found = true
			break
		}
	}
	server.persistMu.Unlock()
	if !found {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "message": "Supervisor not found"})
		return
	}
	server.savePersistentData()
	log.Printf("👤 Updated supervisor: %s -> %s\n", req.OldName, req.Name)
	server.addLog("info", fmt.Sprintf("Updated supervisor: %s -> %s", req.OldName, req.Name))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleDeleteSupervisorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	found := false
	newList := []Supervisor{}
	for _, s := range server.persistentData.Supervisors {
		if s.Name == req.Name {
			found = true
		} else {
			newList = append(newList, s)
		}
	}
	server.persistentData.Supervisors = newList
	server.persistMu.Unlock()
	if !found {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "message": "Supervisor not found"})
		return
	}
	server.savePersistentData()
	log.Printf("👤 Deleted supervisor: %s\n", req.Name)
	server.addLog("info", fmt.Sprintf("Deleted supervisor: %s", req.Name))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleAdminPasswordAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	server.persistentData.AdminPassword = req.Password
	server.persistMu.Unlock()
	server.savePersistentData()
	log.Printf("🔐 Admin password updated\n")
	server.addLog("info", "Admin password updated")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleUpdateProxyNameAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Index int    `json:"index"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.poolMu.Lock()
	if req.Index < 0 || req.Index >= len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "invalid proxy index", http.StatusBadRequest)
		return
	}
	server.poolMu.Unlock()
	server.persistMu.Lock()
	if server.persistentData.ProxyNames == nil {
		server.persistentData.ProxyNames = make(map[int]string)
	}
	if req.Name == "" {
		delete(server.persistentData.ProxyNames, req.Index)
	} else {
		server.persistentData.ProxyNames[req.Index] = req.Name
	}
	server.persistMu.Unlock()
	server.savePersistentData()
	log.Printf("📝 Proxy %d renamed to: %s\n", req.Index+1, req.Name)
	server.addLog("info", fmt.Sprintf("Proxy %d renamed to: %s", req.Index+1, req.Name))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleReorderProxiesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Order []int `json:"order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.poolMu.Lock()
	if len(req.Order) != len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "invalid order length", http.StatusBadRequest)
		return
	}
	newPool := make([]string, len(server.proxyPool))
	for newIdx, oldIdx := range req.Order {
		if oldIdx < 0 || oldIdx >= len(server.proxyPool) {
			server.poolMu.Unlock()
			http.Error(w, "invalid index in order", http.StatusBadRequest)
			return
		}
		newPool[newIdx] = server.proxyPool[oldIdx]
	}
	server.persistMu.Lock()
	newNames := make(map[int]string)
	for newIdx, oldIdx := range req.Order {
		if name, ok := server.persistentData.ProxyNames[oldIdx]; ok {
			newNames[newIdx] = name
		}
	}
	server.persistentData.ProxyNames = newNames
	server.persistMu.Unlock()
	server.proxyPool = newPool
	server.poolMu.Unlock()
	// Save to proxies.txt
	content := strings.Join(server.proxyPool, "\n")
	os.WriteFile("proxies.txt", []byte(content), 0644)
	server.savePersistentData()
	log.Printf("🔄 Proxies reordered\n")
	server.addLog("info", "Proxies reordered")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleSessionSettingsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		server.persistMu.RLock()
		settings := server.persistentData.SystemSettings
		server.persistMu.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session_timeout_hours": settings.SessionTimeout,
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			SessionTimeout int `json:"session_timeout_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		// Validate timeout (1-48 hours)
		if req.SessionTimeout < 1 {
			req.SessionTimeout = 1
		} else if req.SessionTimeout > 48 {
			req.SessionTimeout = 48
		}

		server.persistMu.Lock()
		server.persistentData.SystemSettings.SessionTimeout = req.SessionTimeout
		server.persistMu.Unlock()

		server.savePersistentData()
		log.Printf("⚙️ Session timeout updated to %d hours\n", req.SessionTimeout)
		server.addLog("info", fmt.Sprintf("Session timeout updated to %d hours", req.SessionTimeout))

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// getScamalyticsScore fetches the fraud score from Scamalytics for an IP
func getScamalyticsScore(ip string) TrustScoreResult {
	// Validate IP format
	if net.ParseIP(ip) == nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "invalid IP"}
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Follow redirects
		},
	}

	// Fetch the Scamalytics page
	url := "https://scamalytics.com/ip/" + ip
	req, err := createBrowserRequest(url)
	if err != nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "request error"}
	}

	// Add referer to look more legitimate
	req.Header.Set("Referer", "https://scamalytics.com/")

	resp, err := client.Do(req)
	if err != nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "fetch error"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "status " + strconv.Itoa(resp.StatusCode)}
	}

	// Read response body (handle gzip if needed)
	var body []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			body, _ = io.ReadAll(resp.Body)
		} else {
			defer reader.Close()
			body, err = io.ReadAll(reader)
			if err != nil {
				return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "gzip read error"}
			}
		}
	} else {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "read error"}
		}
	}

	html := string(body)
	score := -1

	// Updated patterns for current Scamalytics HTML structure
	patterns := []string{
		`"score"\s*:\s*(\d+)`,                               // JSON-like score
		`(?i)fraud\s*score[:\s]*</?\w+[^>]*>\s*(\d+)`,       // Fraud Score: <span>XX</span>
		`(?i)<div[^>]*class="[^"]*score[^"]*"[^>]*>(\d+)<`,  // <div class="score">XX</div>
		`(?i)>(\d+)</div>\s*</div>\s*<div[^>]*score`,        // Score in nested div
		`(?i)fraud[^<]*<[^>]+>\s*(\d+)\s*<`,                 // Fraud ... <tag>XX</tag>
		`(?i)risk[:\s]*(\d+)%`,                              // Risk: XX%
		`data-score="(\d+)"`,                                // data-score attribute
		`(?i)score[^>]*>\s*(\d+)\s*<`,                       // Generic score pattern
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			if s, err := strconv.Atoi(matches[1]); err == nil && s >= 0 && s <= 100 {
				score = s
				break
			}
		}
	}

	if score == -1 {
		// Check if we got a Cloudflare or bot protection page
		if strings.Contains(html, "cloudflare") || strings.Contains(html, "challenge") || strings.Contains(html, "captcha") {
			return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "bot protection"}
		}
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "parse error"}
	}

	return TrustScoreResult{Score: score, Risk: getRiskLevel(score), Available: true}
}

// getIPQualityScore fetches the fraud score from IPQualityScore for an IP
// Falls back to ip-api.com for basic proxy/VPN detection
func getIPQualityScore(ip string) TrustScoreResult {
	// Validate IP format
	if net.ParseIP(ip) == nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "invalid IP"}
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Try ip-api.com first (free, no auth needed, includes proxy detection)
	apiURL := "http://ip-api.com/json/" + ip + "?fields=status,proxy,hosting,query"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "request error"}
	}

	resp, err := client.Do(req)
	if err != nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "fetch error"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "status " + strconv.Itoa(resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "read error"}
	}

	// Parse JSON response
	var result struct {
		Status  string `json:"status"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
		Query   string `json:"query"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "parse error"}
	}

	if result.Status != "success" {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "lookup failed"}
	}

	// Calculate a score based on proxy/hosting flags
	// proxy=true or hosting=true indicates higher risk
	score := 0
	risk := "low"
	if result.Proxy {
		score = 75 // Known proxy
		risk = "high"
	} else if result.Hosting {
		score = 50 // Datacenter/hosting IP
		risk = "medium"
	} else {
		score = 10 // Residential IP
		risk = "low"
	}

	return TrustScoreResult{Score: score, Risk: risk, Available: true}
}

// getCombinedTrustScore fetches fraud scores from both Scamalytics and IPQualityScore
func getCombinedTrustScore(ip string) CombinedTrustScore {
	// Fetch from both sources concurrently
	var scamResult, ipqsResult TrustScoreResult
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		scamResult = getScamalyticsScore(ip)
	}()
	go func() {
		defer wg.Done()
		ipqsResult = getIPQualityScore(ip)
	}()
	wg.Wait()

	return CombinedTrustScore{
		Scamalytics:    scamResult,
		IPQualityScore: ipqsResult,
	}
}

func handleCheckBlacklistAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Collect all proxy IPs
	server.healthMu.RLock()
	proxies := make([]struct {
		Index     int    `json:"index"`
		Name      string `json:"name"`
		IPAddress string `json:"ip_address"`
	}, 0)
	for _, h := range server.proxyHealth {
		if h.IPAddress != "" && h.IPAddress != "unknown" {
			proxies = append(proxies, struct {
				Index     int    `json:"index"`
				Name      string `json:"name"`
				IPAddress string `json:"ip_address"`
			}{
				Index:     h.Index,
				Name:      server.getProxyName(h.Index),
				IPAddress: h.IPAddress,
			})
		}
	}
	server.healthMu.RUnlock()

	// Sort by index
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].Index < proxies[j].Index
	})

	// Check each proxy IP for trust score from both sources
	results := make([]map[string]interface{}, 0)
	scamLowRisk, scamMedRisk, scamHighRisk := 0, 0, 0
	ipqsLowRisk, ipqsMedRisk, ipqsHighRisk := 0, 0, 0
	scamTotalScore, ipqsTotalScore := 0, 0
	scamScoredCount, ipqsScoredCount := 0, 0

	for _, p := range proxies {
		combined := getCombinedTrustScore(p.IPAddress)

		// Track Scamalytics stats
		if combined.Scamalytics.Available {
			scamTotalScore += combined.Scamalytics.Score
			scamScoredCount++
			switch combined.Scamalytics.Risk {
			case "low":
				scamLowRisk++
			case "medium":
				scamMedRisk++
			case "high", "very high":
				scamHighRisk++
			}
		}

		// Track IPQualityScore stats
		if combined.IPQualityScore.Available {
			ipqsTotalScore += combined.IPQualityScore.Score
			ipqsScoredCount++
			switch combined.IPQualityScore.Risk {
			case "low":
				ipqsLowRisk++
			case "medium":
				ipqsMedRisk++
			case "high", "very high":
				ipqsHighRisk++
			}
		}

		results = append(results, map[string]interface{}{
			"index":      p.Index,
			"name":       p.Name,
			"ip_address": p.IPAddress,
			"scamalytics": map[string]interface{}{
				"score":     combined.Scamalytics.Score,
				"risk":      combined.Scamalytics.Risk,
				"available": combined.Scamalytics.Available,
				"error":     combined.Scamalytics.Error,
			},
			"ipqualityscore": map[string]interface{}{
				"score":     combined.IPQualityScore.Score,
				"risk":      combined.IPQualityScore.Risk,
				"available": combined.IPQualityScore.Available,
				"error":     combined.IPQualityScore.Error,
			},
		})
	}

	scamAvgScore := -1
	if scamScoredCount > 0 {
		scamAvgScore = scamTotalScore / scamScoredCount
	}
	ipqsAvgScore := -1
	if ipqsScoredCount > 0 {
		ipqsAvgScore = ipqsTotalScore / ipqsScoredCount
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"total_checked": len(proxies),
		"scamalytics": map[string]interface{}{
			"low_risk_count":    scamLowRisk,
			"medium_risk_count": scamMedRisk,
			"high_risk_count":   scamHighRisk,
			"average_score":     scamAvgScore,
			"scored_count":      scamScoredCount,
		},
		"ipqualityscore": map[string]interface{}{
			"low_risk_count":    ipqsLowRisk,
			"medium_risk_count": ipqsMedRisk,
			"high_risk_count":   ipqsHighRisk,
			"average_score":     ipqsAvgScore,
			"scored_count":      ipqsScoredCount,
		},
		"results": results,
	})
}

func handleDeviceConnectionsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	deviceIP := r.URL.Query().Get("device_ip")
	if deviceIP == "" {
		http.Error(w, "device_ip required", http.StatusBadRequest)
		return
	}

	connections := server.getDeviceConnections(deviceIP)
	json.NewEncoder(w).Encode(connections)
}

func handleNetworkOverviewAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	server.apMu.RLock()
	defer server.apMu.RUnlock()

	// Gather active AP devices with their current activity
	activeDevices := make([]map[string]interface{}, 0)
	now := time.Now()

	for _, device := range server.apDevices {
		if !device.Confirmed {
			continue
		}

		timeSinceSeen := now.Sub(device.LastSeen).Minutes()

		// Only include devices seen in last 30 minutes
		if timeSinceSeen > 30 {
			continue
		}

		// Get recent connections for this device
		recentConns := server.getDeviceConnections(device.IP)
		recentHosts := make([]string, 0)
		for i, conn := range recentConns {
			if i >= 5 {
				break
			}
			recentHosts = append(recentHosts, conn.Host)
		}

		// Calculate current data rate (bytes per minute over last seen)
		dataRate := int64(0)
		if timeSinceSeen < 5 && timeSinceSeen > 0 {
			dataRate = int64(float64(device.BytesIn+device.BytesOut) / timeSinceSeen)
		}

		name := device.CustomName
		if name == "" {
			name = device.Hostname
		}
		if name == "" {
			name = device.IP
		}

		activeDevices = append(activeDevices, map[string]interface{}{
			"ip":              device.IP,
			"mac":             device.MAC,
			"name":            name,
			"group":           device.Group,
			"is_active":       timeSinceSeen < 5,
			"last_seen_min":   timeSinceSeen,
			"bytes_in":        device.BytesIn,
			"bytes_out":       device.BytesOut,
			"data_rate":       dataRate,
			"request_count":   device.RequestCount,
			"error_count":     device.ErrorCount,
			"recent_hosts":    recentHosts,
			"confirmed":       device.Confirmed,
		})
	}

	// Sort by activity (most recently seen first)
	sort.Slice(activeDevices, func(i, j int) bool {
		iSeen := activeDevices[i]["last_seen_min"].(float64)
		jSeen := activeDevices[j]["last_seen_min"].(float64)
		return iSeen < jSeen
	})

	// Calculate totals
	totalBytesIn := int64(0)
	totalBytesOut := int64(0)
	activeCount := 0
	for _, d := range activeDevices {
		totalBytesIn += d["bytes_in"].(int64)
		totalBytesOut += d["bytes_out"].(int64)
		if d["is_active"].(bool) {
			activeCount++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"devices":        activeDevices,
		"total_devices":  len(activeDevices),
		"active_count":   activeCount,
		"total_bytes_in": totalBytesIn,
		"total_bytes_out": totalBytesOut,
	})
}

