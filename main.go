package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

type Device struct {
	ID            string    `json:"id"`
	IP            string    `json:"ip"`
	Name          string    `json:"name"`
	CustomName    string    `json:"custom_name"`
	Group         string    `json:"group"`
	UpstreamProxy string    `json:"upstream_proxy"`
	Status        string    `json:"status"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	RequestCount  int64     `json:"request_count"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	Notes         string    `json:"notes"`
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error"`
	LastErrorTime time.Time `json:"last_error_time"`
}

type ProxyHealth struct {
	Index           int       `json:"index"`
	ProxyString     string    `json:"proxy_string"`
	IPAddress       string    `json:"ip_address"`
	TotalRequests   int64     `json:"total_requests"`
	SuccessCount    int64     `json:"success_count"`
	FailureCount    int64     `json:"failure_count"`
	SuccessRate     float64   `json:"success_rate"`
	LastSuccess     time.Time `json:"last_success"`
	LastFailure     time.Time `json:"last_failure"`
	LastError       string    `json:"last_error"`
	AvgResponseTime int64     `json:"avg_response_time_ms"`
	Status          string    `json:"status"`
	BytesIn         int64     `json:"bytes_in"`
	BytesOut        int64     `json:"bytes_out"`
	ActiveDevices   int       `json:"active_devices"`
}

type TrafficSnapshot struct {
	Timestamp     time.Time `json:"timestamp"`
	TotalBytesIn  int64     `json:"total_bytes_in"`
	TotalBytesOut int64     `json:"total_bytes_out"`
	TotalRequests int64     `json:"total_requests"`
	ActiveDevices int       `json:"active_devices"`
	ErrorCount    int64     `json:"error_count"`
}

type DeviceConfig struct {
	CustomName string `json:"custom_name"`
	Group      string `json:"group"`
	Notes      string `json:"notes"`
	ProxyIndex int    `json:"proxy_index"`
}

type UserCredentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
}

type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PersistentData struct {
	DeviceConfigs   map[string]DeviceConfig `json:"device_configs"`
	Groups          []string                `json:"groups"`
	Users           []UserCredentials       `json:"users"`
	TrafficHistory  []TrafficSnapshot       `json:"traffic_history"`
	ProxyHealthData map[int]*ProxyHealth    `json:"proxy_health_data"`
	SystemSettings  SystemSettings          `json:"system_settings"`
}

type SystemSettings struct {
	SessionTimeout       int `json:"session_timeout_hours"`
	TrafficRetentionDays int `json:"traffic_retention_days"`
	DeviceTimeoutMinutes int `json:"device_timeout_minutes"`
}

type ProxyServer struct {
	devices        map[string]*Device
	mu             sync.RWMutex
	proxyPool      []string
	proxyHealth    map[int]*ProxyHealth
	healthMu       sync.RWMutex
	poolIndex      int
	poolMu         sync.Mutex
	proxyPort      int
	dashPort       int
	persistentData PersistentData
	persistMu      sync.RWMutex
	dataFile       string
	sessions       map[string]*Session
	sessionMu      sync.RWMutex
}

type ProxyInfo struct {
	Index int    `json:"index"`
	Host  string `json:"host"`
	Port  string `json:"port"`
	User  string `json:"user"`
	Pass  string `json:"pass"`
	Full  string `json:"full"`
}

type changeProxyRequest struct {
	DeviceIP   string `json:"device_ip"`
	ProxyIndex int    `json:"proxy_index"`
}

type updateDeviceRequest struct {
	DeviceIP   string `json:"device_ip"`
	CustomName string `json:"custom_name"`
	Group      string `json:"group"`
	Notes      string `json:"notes"`
}

type bulkChangeProxyRequest struct {
	DeviceIPs  []string `json:"device_ips"`
	ProxyIndex int      `json:"proxy_index"`
}

type addGroupRequest struct {
	GroupName string `json:"group_name"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

var server *ProxyServer

func getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		addrs, _ := net.InterfaceAddrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
		return "localhost"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func main() {
	log.Println("===========================================")
	log.Println("🌐 Lumier Dynamics - Pure Go Proxy Server")
	log.Println("    Enterprise Edition v3.0")
	log.Println("===========================================")

	server = &ProxyServer{
		devices:     make(map[string]*Device),
		proxyPool:   loadProxyPool(),
		proxyHealth: make(map[int]*ProxyHealth),
		proxyPort:   8888,
		dashPort:    8080,
		dataFile:    "device_data.json",
		sessions:    make(map[string]*Session),
		persistentData: PersistentData{
			DeviceConfigs:   make(map[string]DeviceConfig),
			Groups:          []string{"Default", "Floor 1", "Floor 2", "Team A", "Team B"},
			Users:           []UserCredentials{},
			TrafficHistory:  []TrafficSnapshot{},
			ProxyHealthData: make(map[int]*ProxyHealth),
			SystemSettings: SystemSettings{
				SessionTimeout:       24,
				TrafficRetentionDays: 7,
				DeviceTimeoutMinutes: 30,
			},
		},
	}

	server.loadPersistentData()
	server.initializeProxyHealth()

	if len(server.persistentData.Users) == 0 {
		server.createDefaultAdmin()
	}

	if len(server.proxyPool) == 0 {
		log.Println("⚠️  WARNING: No upstream proxies loaded!")
	} else {
		log.Printf("✅ Loaded %d upstream proxies\n", len(server.proxyPool))
	}

	go cleanupInactiveDevices()
	go autoSaveData()
	go collectTrafficSnapshots()
	go cleanupExpiredSessions()
	go proxyHealthChecker()
	go startDashboard()

	serverIP := getServerIP()
	log.Printf("🚀 Proxy server starting on port %d\n", server.proxyPort)
	log.Printf("📊 Dashboard: http://%s:%d\n", serverIP, server.dashPort)
	log.Println("🔐 Default login: admin / admin123")
	log.Printf("📱 Phone setup: Proxy %s:%d\n", serverIP, server.proxyPort)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", server.proxyPort), http.HandlerFunc(handleProxy)); err != nil {
		log.Fatal(err)
	}
}

func loadProxyPool() []string {
	data, err := os.ReadFile("proxies.txt")
	if err != nil {
		return []string{}
	}
	var proxies []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}
	return proxies
}

func (s *ProxyServer) initializeProxyHealth() {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	for i, proxyStr := range s.proxyPool {
		if existing, ok := s.persistentData.ProxyHealthData[i]; ok {
			s.proxyHealth[i] = existing
		} else {
			s.proxyHealth[i] = &ProxyHealth{
				Index:       i,
				ProxyString: proxyStr,
				IPAddress:   extractProxyIP(proxyStr),
				Status:      "unknown",
			}
		}
	}
}

func extractProxyIP(proxyStr string) string {
	if idx := strings.Index(proxyStr, "-ip-"); idx != -1 {
		rest := proxyStr[idx+4:]
		if colonIdx := strings.Index(rest, ":"); colonIdx != -1 {
			return rest[:colonIdx]
		}
		return rest
	}
	parts := strings.Split(proxyStr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

func generateSalt() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(hash[:])
}

func (s *ProxyServer) createDefaultAdmin() {
	salt := generateSalt()
	s.persistMu.Lock()
	s.persistentData.Users = append(s.persistentData.Users, UserCredentials{
		Username:     "admin",
		PasswordHash: hashPassword("admin123", salt),
		Salt:         salt,
	})
	s.persistMu.Unlock()
	go s.savePersistentData()
}

func (s *ProxyServer) validateCredentials(username, password string) bool {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()
	for _, user := range s.persistentData.Users {
		if user.Username == username {
			hash := hashPassword(password, user.Salt)
			return subtle.ConstantTimeCompare([]byte(hash), []byte(user.PasswordHash)) == 1
		}
	}
	return false
}

func (s *ProxyServer) createSession(username string) string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := base64.URLEncoding.EncodeToString(bytes)
	s.sessionMu.Lock()
	s.sessions[token] = &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(s.persistentData.SystemSettings.SessionTimeout) * time.Hour),
	}
	s.sessionMu.Unlock()
	return token
}

func (s *ProxyServer) validateSession(token string) (*Session, bool) {
	s.sessionMu.RLock()
	session, exists := s.sessions[token]
	s.sessionMu.RUnlock()
	if !exists || time.Now().After(session.ExpiresAt) {
		if exists {
			s.sessionMu.Lock()
			delete(s.sessions, token)
			s.sessionMu.Unlock()
		}
		return nil, false
	}
	return session, true
}

func (s *ProxyServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if _, valid := s.validateSession(cookie.Value); !valid {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func cleanupExpiredSessions() {
	for range time.NewTicker(1 * time.Hour).C {
		server.sessionMu.Lock()
		now := time.Now()
		for token, session := range server.sessions {
			if now.After(session.ExpiresAt) {
				delete(server.sessions, token)
			}
		}
		server.sessionMu.Unlock()
	}
}

// ============================================================================
// PERSISTENCE
// ============================================================================

func (s *ProxyServer) loadPersistentData() {
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.persistentData)
	if s.persistentData.DeviceConfigs == nil {
		s.persistentData.DeviceConfigs = make(map[string]DeviceConfig)
	}
	if s.persistentData.Groups == nil {
		s.persistentData.Groups = []string{"Default"}
	}
	if s.persistentData.ProxyHealthData == nil {
		s.persistentData.ProxyHealthData = make(map[int]*ProxyHealth)
	}
}

func (s *ProxyServer) savePersistentData() {
	s.persistMu.RLock()
	s.healthMu.RLock()
	s.persistentData.ProxyHealthData = make(map[int]*ProxyHealth)
	for k, v := range s.proxyHealth {
		s.persistentData.ProxyHealthData[k] = v
	}
	s.healthMu.RUnlock()
	data, _ := json.MarshalIndent(s.persistentData, "", "  ")
	s.persistMu.RUnlock()
	os.WriteFile(s.dataFile, data, 0644)
}

func autoSaveData() {
	for range time.NewTicker(5 * time.Minute).C {
		server.savePersistentData()
	}
}

// ============================================================================
// TRAFFIC ANALYTICS
// ============================================================================

func collectTrafficSnapshots() {
	for range time.NewTicker(5 * time.Minute).C {
		server.mu.RLock()
		var totalBytesIn, totalBytesOut, totalRequests, totalErrors int64
		activeDevices := 0
		for _, device := range server.devices {
			totalBytesIn += device.BytesIn
			totalBytesOut += device.BytesOut
			totalRequests += device.RequestCount
			totalErrors += device.ErrorCount
			if time.Since(device.LastSeen) < 5*time.Minute {
				activeDevices++
			}
		}
		server.mu.RUnlock()

		snapshot := TrafficSnapshot{
			Timestamp:     time.Now(),
			TotalBytesIn:  totalBytesIn,
			TotalBytesOut: totalBytesOut,
			TotalRequests: totalRequests,
			ActiveDevices: activeDevices,
			ErrorCount:    totalErrors,
		}

		server.persistMu.Lock()
		server.persistentData.TrafficHistory = append(server.persistentData.TrafficHistory, snapshot)
		cutoff := time.Now().AddDate(0, 0, -server.persistentData.SystemSettings.TrafficRetentionDays)
		var filtered []TrafficSnapshot
		for _, s := range server.persistentData.TrafficHistory {
			if s.Timestamp.After(cutoff) {
				filtered = append(filtered, s)
			}
		}
		server.persistentData.TrafficHistory = filtered
		server.persistMu.Unlock()
	}
}

// ============================================================================
// PROXY HEALTH MONITORING
// ============================================================================

func (s *ProxyServer) recordProxySuccess(proxyIndex int, responseTime time.Duration, bytesIn, bytesOut int64) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	health, exists := s.proxyHealth[proxyIndex]
	if !exists {
		return
	}
	health.TotalRequests++
	health.SuccessCount++
	health.LastSuccess = time.Now()
	health.BytesIn += bytesIn
	health.BytesOut += bytesOut
	if health.AvgResponseTime == 0 {
		health.AvgResponseTime = responseTime.Milliseconds()
	} else {
		health.AvgResponseTime = (health.AvgResponseTime + responseTime.Milliseconds()) / 2
	}
	if health.TotalRequests > 0 {
		health.SuccessRate = float64(health.SuccessCount) / float64(health.TotalRequests) * 100
	}
	health.Status = s.calculateProxyStatus(health)
}

func (s *ProxyServer) recordProxyFailure(proxyIndex int, errorMsg string) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	health, exists := s.proxyHealth[proxyIndex]
	if !exists {
		return
	}
	health.TotalRequests++
	health.FailureCount++
	health.LastFailure = time.Now()
	health.LastError = errorMsg
	if health.TotalRequests > 0 {
		health.SuccessRate = float64(health.SuccessCount) / float64(health.TotalRequests) * 100
	}
	health.Status = s.calculateProxyStatus(health)
}

func (s *ProxyServer) calculateProxyStatus(health *ProxyHealth) string {
	if health.TotalRequests < 10 {
		return "unknown"
	}
	if health.SuccessRate >= 95 {
		return "healthy"
	}
	if health.SuccessRate >= 80 {
		return "degraded"
	}
	return "unhealthy"
}

func (s *ProxyServer) getProxyIndexByString(proxyStr string) int {
	for i, p := range s.proxyPool {
		if p == proxyStr {
			return i
		}
	}
	return -1
}

func proxyHealthChecker() {
	for range time.NewTicker(1 * time.Minute).C {
		server.mu.RLock()
		proxyCounts := make(map[int]int)
		for _, device := range server.devices {
			if time.Since(device.LastSeen) < 5*time.Minute {
				idx := server.getProxyIndexByString(device.UpstreamProxy)
				if idx >= 0 {
					proxyCounts[idx]++
				}
			}
		}
		server.mu.RUnlock()

		server.healthMu.Lock()
		for idx, health := range server.proxyHealth {
			health.ActiveDevices = proxyCounts[idx]
		}
		server.healthMu.Unlock()
	}
}

// ============================================================================
// PROXY HANDLING
// ============================================================================

func (s *ProxyServer) getNextProxy() string {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	if len(s.proxyPool) == 0 {
		return ""
	}
	proxy := s.proxyPool[s.poolIndex]
	s.poolIndex = (s.poolIndex + 1) % len(s.proxyPool)
	return proxy
}

func (s *ProxyServer) getOrCreateDevice(clientIP string) *Device {
	s.mu.Lock()
	defer s.mu.Unlock()

	if device, exists := s.devices[clientIP]; exists {
		device.LastSeen = time.Now()
		return device
	}

	s.persistMu.RLock()
	savedConfig, hasSavedConfig := s.persistentData.DeviceConfigs[clientIP]
	s.persistMu.RUnlock()

	var upstreamProxy, customName, group, notes string = s.getNextProxy(), "", "Default", ""
	if hasSavedConfig {
		if savedConfig.ProxyIndex >= 0 && savedConfig.ProxyIndex < len(s.proxyPool) {
			upstreamProxy = s.proxyPool[savedConfig.ProxyIndex]
		}
		customName, group, notes = savedConfig.CustomName, savedConfig.Group, savedConfig.Notes
	}

	device := &Device{
		ID:            fmt.Sprintf("device-%d", len(s.devices)+1),
		IP:            clientIP,
		Name:          fmt.Sprintf("Phone-%s", clientIP),
		CustomName:    customName,
		Group:         group,
		Notes:         notes,
		UpstreamProxy: upstreamProxy,
		Status:        "active",
		FirstSeen:     time.Now(),
		LastSeen:      time.Now(),
	}
	s.devices[clientIP] = device
	log.Printf("📱 New device: %s -> %s\n", clientIP, extractProxyIP(upstreamProxy))
	return device
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	device := server.getOrCreateDevice(clientIP)
	device.RequestCount++

	if r.Method == http.MethodConnect {
		handleHTTPS(w, r, device)
	} else {
		handleHTTP(w, r, device)
	}
}

func handleHTTPS(w http.ResponseWriter, r *http.Request, device *Device) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	startTime := time.Now()
	proxyIndex := server.getProxyIndexByString(device.UpstreamProxy)

	targetConn, err := dialThroughSOCKS5(target, device.UpstreamProxy)
	if err != nil {
		device.ErrorCount++
		device.LastError = err.Error()
		device.LastErrorTime = time.Now()
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, err.Error())
		}
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	done := make(chan bool, 2)
	var bytesOut, bytesIn int64

	go func() {
		n, _ := io.Copy(targetConn, clientConn)
		bytesOut = n
		device.BytesOut += n
		done <- true
	}()

	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		bytesIn = n
		device.BytesIn += n
		done <- true
	}()

	<-done
	if proxyIndex >= 0 {
		server.recordProxySuccess(proxyIndex, time.Since(startTime), bytesIn, bytesOut)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request, device *Device) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	startTime := time.Now()
	proxyIndex := server.getProxyIndexByString(device.UpstreamProxy)

	targetConn, err := dialThroughSOCKS5(host, device.UpstreamProxy)
	if err != nil {
		device.ErrorCount++
		device.LastError = err.Error()
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, err.Error())
		}
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	r.RequestURI = ""
	if err := r.Write(targetConn); err != nil {
		device.ErrorCount++
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, err.Error())
		}
		http.Error(w, "Failed to send request", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		device.ErrorCount++
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, err.Error())
		}
		http.Error(w, "Failed to read response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	device.BytesIn += n

	if proxyIndex >= 0 {
		server.recordProxySuccess(proxyIndex, time.Since(startTime), n, 0)
	}
}

func dialThroughSOCKS5(target, proxyStr string) (net.Conn, error) {
	if proxyStr == "" {
		return net.DialTimeout("tcp", target, 30*time.Second)
	}

	parts := strings.Split(proxyStr, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid proxy format")
	}

	auth := &proxy.Auth{User: parts[2], Password: strings.Join(parts[3:], ":")}
	dialer, err := proxy.SOCKS5("tcp", parts[0]+":"+parts[1], auth, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", target)
}

func cleanupInactiveDevices() {
	for range time.NewTicker(10 * time.Minute).C {
		timeout := time.Duration(server.persistentData.SystemSettings.DeviceTimeoutMinutes) * time.Minute
		server.mu.Lock()
		for ip, device := range server.devices {
			if time.Since(device.LastSeen) > timeout {
				delete(server.devices, ip)
			}
		}
		server.mu.Unlock()
	}
}
// ============================================================================
// DASHBOARD SERVER
// ============================================================================

func startDashboard() {
	http.HandleFunc("/", handleLoginPage)
	http.HandleFunc("/api/login", handleLoginAPI)
	http.HandleFunc("/api/logout", handleLogoutAPI)
	http.HandleFunc("/api/session-check", handleSessionCheckAPI)

	http.HandleFunc("/dashboard", server.requireAuth(handleDashboard))
	http.HandleFunc("/health", server.requireAuth(handleHealthPage))
	http.HandleFunc("/analytics", server.requireAuth(handleAnalyticsPage))
	http.HandleFunc("/settings", server.requireAuth(handleSettingsPage))

	http.HandleFunc("/api/devices", server.requireAuth(handleDevicesAPI))
	http.HandleFunc("/api/stats", server.requireAuth(handleStatsAPI))
	http.HandleFunc("/api/server-ip", server.requireAuth(handleServerIPAPI))
	http.HandleFunc("/api/proxies", server.requireAuth(handleProxiesAPI))
	http.HandleFunc("/api/change-proxy", server.requireAuth(handleChangeProxyAPI))
	http.HandleFunc("/api/update-device", server.requireAuth(handleUpdateDeviceAPI))
	http.HandleFunc("/api/bulk-change-proxy", server.requireAuth(handleBulkChangeProxyAPI))
	http.HandleFunc("/api/groups", server.requireAuth(handleGroupsAPI))
	http.HandleFunc("/api/add-group", server.requireAuth(handleAddGroupAPI))
	http.HandleFunc("/api/export", server.requireAuth(handleExportAPI))
	http.HandleFunc("/api/proxy-health", server.requireAuth(handleProxyHealthAPI))
	http.HandleFunc("/api/traffic-history", server.requireAuth(handleTrafficHistoryAPI))
	http.HandleFunc("/api/change-password", server.requireAuth(handleChangePasswordAPI))

	log.Printf("📊 Dashboard on port %d\n", server.dashPort)
	http.ListenAndServe(fmt.Sprintf(":%d", server.dashPort), nil)
}

func handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !server.validateCredentials(req.Username, req.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token := server.createSession(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
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
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: -1})
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

func handleDevicesAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	devices := make([]*Device, 0, len(server.devices))
	for _, d := range server.devices {
		devices = append(devices, d)
	}
	server.mu.RUnlock()
	sort.Slice(devices, func(i, j int) bool {
		ni, nj := devices[i].CustomName, devices[j].CustomName
		if ni == "" {
			ni = devices[i].Name
		}
		if nj == "" {
			nj = devices[j].Name
		}
		return ni < nj
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

func handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	activeCount, totalRequests, totalErrors, totalBytesIn, totalBytesOut := 0, int64(0), int64(0), int64(0), int64(0)
	for _, d := range server.devices {
		if time.Since(d.LastSeen) < 5*time.Minute {
			activeCount++
		}
		totalRequests += d.RequestCount
		totalErrors += d.ErrorCount
		totalBytesIn += d.BytesIn
		totalBytesOut += d.BytesOut
	}
	totalDevices := len(server.devices)
	server.mu.RUnlock()

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
			proxies = append(proxies, ProxyInfo{Index: i, Host: parts[0], Port: parts[1], User: parts[2], Pass: parts[3], Full: line})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proxies)
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

func handleTrafficHistoryAPI(w http.ResponseWriter, r *http.Request) {
	server.persistMu.RLock()
	history := server.persistentData.TrafficHistory
	server.persistMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func handleChangeProxyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req changeProxyRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.mu.Lock()
	device, ok := server.devices[req.DeviceIP]
	server.mu.Unlock()
	if !ok {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	server.poolMu.Lock()
	if req.ProxyIndex < 0 || req.ProxyIndex >= len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "invalid proxy index", http.StatusBadRequest)
		return
	}
	newProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	server.mu.Lock()
	device.UpstreamProxy = newProxy
	device.LastSeen = time.Now()
	server.mu.Unlock()

	server.persistMu.Lock()
	config := server.persistentData.DeviceConfigs[req.DeviceIP]
	config.ProxyIndex = req.ProxyIndex
	server.persistentData.DeviceConfigs[req.DeviceIP] = config
	server.persistMu.Unlock()
	go server.savePersistentData()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleUpdateDeviceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req updateDeviceRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.mu.Lock()
	device, ok := server.devices[req.DeviceIP]
	if ok {
		device.CustomName = req.CustomName
		device.Group = req.Group
		device.Notes = req.Notes
	}
	server.mu.Unlock()
	if !ok {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	server.persistMu.Lock()
	config := server.persistentData.DeviceConfigs[req.DeviceIP]
	config.CustomName = req.CustomName
	config.Group = req.Group
	config.Notes = req.Notes
	server.persistentData.DeviceConfigs[req.DeviceIP] = config
	server.persistMu.Unlock()
	go server.savePersistentData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleBulkChangeProxyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req bulkChangeProxyRequest
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
	newProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	updated := 0
	for _, ip := range req.DeviceIPs {
		server.mu.Lock()
		if device, ok := server.devices[ip]; ok {
			device.UpstreamProxy = newProxy
			updated++
		}
		server.mu.Unlock()
		server.persistMu.Lock()
		config := server.persistentData.DeviceConfigs[ip]
		config.ProxyIndex = req.ProxyIndex
		server.persistentData.DeviceConfigs[ip] = config
		server.persistMu.Unlock()
	}
	go server.savePersistentData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "updated": updated})
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

func handleExportAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	devices := make([]*Device, 0)
	for _, d := range server.devices {
		devices = append(devices, d)
	}
	server.mu.RUnlock()
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

func handleAnalyticsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(analyticsPageHTML))
}

func handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(settingsPageHTML))
}

const loginPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Login</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-container{background:rgba(255,255,255,0.95);padding:40px;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.3);width:100%;max-width:400px}.logo{text-align:center;margin-bottom:30px}.logo h1{color:#667eea;font-size:2em;margin-bottom:5px}.logo p{color:#666;font-size:0.9em}.form-group{margin-bottom:20px}.form-group label{display:block;font-weight:600;color:#333;margin-bottom:8px}.form-group input{width:100%;padding:14px 16px;border:2px solid #e0e0e0;border-radius:10px;font-size:1em}.form-group input:focus{outline:none;border-color:#667eea}.login-btn{width:100%;padding:14px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer}.login-btn:hover{opacity:0.9}.login-btn:disabled{opacity:0.5;cursor:not-allowed}.error-msg{background:#ffebee;color:#c62828;padding:12px;border-radius:8px;margin-bottom:20px;display:none}.error-msg.show{display:block}</style></head>
<body><div class="login-container"><div class="logo"><h1>🌐 Lumier Dynamics</h1><p>Enterprise Proxy Management v3.0</p></div><div class="error-msg" id="errorMsg"></div><form onsubmit="return handleLogin(event)"><div class="form-group"><label>Username</label><input type="text" id="username" placeholder="Enter username" required autofocus></div><div class="form-group"><label>Password</label><input type="password" id="password" placeholder="Enter password" required></div><button type="submit" class="login-btn" id="loginBtn">Sign In</button></form></div>
<script>async function handleLogin(e){e.preventDefault();const btn=document.getElementById('loginBtn'),err=document.getElementById('errorMsg');btn.disabled=true;btn.textContent='Signing in...';err.classList.remove('show');try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});if(r.ok)window.location.href='/dashboard';else{err.textContent='Invalid username or password';err.classList.add('show');btn.disabled=false;btn.textContent='Sign In';}}catch(e){err.textContent='Connection error';err.classList.add('show');btn.disabled=false;btn.textContent='Sign In';}return false;}</script></body></html>`

const navHTML = `<nav style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:15px 30px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px"><div style="display:flex;align-items:center;gap:10px"><span style="font-size:1.5em">🌐</span><span style="color:white;font-size:1.3em;font-weight:bold">Lumier Dynamics</span></div><div style="display:flex;gap:5px;flex-wrap:wrap"><a href="/dashboard" class="nav-link" id="nav-dashboard">📱 Devices</a><a href="/health" class="nav-link" id="nav-health">💚 Health</a><a href="/analytics" class="nav-link" id="nav-analytics">📊 Analytics</a><a href="/settings" class="nav-link" id="nav-settings">⚙️ Settings</a></div><div style="display:flex;align-items:center;gap:15px;color:white"><span id="currentUser">Admin</span><button onclick="logout()" style="background:rgba(255,255,255,0.2);color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:500">Logout</button></div></nav>`

const baseStyles = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;min-height:100vh}.nav-link{color:rgba(255,255,255,0.85);text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:500}.nav-link:hover,.nav-link.active{background:rgba(255,255,255,0.2);color:white}.container{max-width:1600px;margin:0 auto;padding:25px}.page-header{margin-bottom:25px}.page-header h1{color:#333;font-size:1.8em;margin-bottom:5px}.page-header p{color:#666}.card{background:white;border-radius:12px;padding:25px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}.card h2{color:#333;font-size:1.3em;margin-bottom:15px;padding-bottom:10px;border-bottom:2px solid #f0f0f0}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:20px;margin-bottom:25px}.stat-card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.05);text-align:center;cursor:pointer;transition:transform 0.2s}.stat-card:hover{transform:translateY(-3px)}.stat-value{font-size:2.2em;font-weight:bold;color:#667eea;margin-bottom:5px}.stat-label{color:#666;font-size:0.85em;text-transform:uppercase;letter-spacing:1px}.btn{padding:10px 18px;border:none;border-radius:8px;cursor:pointer;font-size:0.95em;font-weight:600;transition:all 0.2s}.btn-primary{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white}.btn-primary:hover{opacity:0.9}.btn-secondary{background:#f5f5f5;color:#333;border:2px solid #e0e0e0}.btn-secondary:hover{background:#e8e8e8}.toast{position:fixed;bottom:30px;right:30px;background:#333;color:white;padding:15px 25px;border-radius:10px;z-index:1001;animation:slideIn 0.3s ease}.toast.success{background:#4caf50}.toast.error{background:#f44336}@keyframes slideIn{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}.loading{text-align:center;padding:40px;color:#666}`

const baseJS = `async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/';}function showToast(msg,type=''){const t=document.createElement('div');t.className='toast '+type;t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}function formatBytes(b){if(!b)return"0 B";const k=1024,s=["B","KB","MB","GB","TB"];const i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+" "+s[i];}function formatNumber(n){if(!n)return"0";if(n>=1e6)return(n/1e6).toFixed(1)+"M";if(n>=1e3)return(n/1e3).toFixed(1)+"K";return n.toString();}fetch('/api/session-check').then(r=>r.json()).then(d=>{if(!d.valid)window.location.href='/';else if(document.getElementById('currentUser'))document.getElementById('currentUser').textContent=d.username;});`

const dashboardPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Devices</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.toolbar{background:white;padding:15px 20px;border-radius:12px;margin-bottom:20px;box-shadow:0 2px 10px rgba(0,0,0,0.05);display:flex;flex-wrap:wrap;gap:15px;align-items:center}.search-box{flex:1;min-width:200px;position:relative}.search-box input{width:100%;padding:10px 15px 10px 40px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.search-box input:focus{outline:none;border-color:#667eea}.search-box::before{content:"🔍";position:absolute;left:12px;top:50%;transform:translateY(-50%)}.filter-group{display:flex;gap:10px;align-items:center}.filter-group label{font-weight:600;color:#555;font-size:0.9em}.filter-group select{padding:8px 12px;border:2px solid #e0e0e0;border-radius:8px}.device-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}.device-card{background:white;border:2px solid #e8e8e8;border-radius:12px;padding:18px;transition:all 0.2s;position:relative}.device-card:hover{border-color:#667eea;box-shadow:0 5px 20px rgba(102,126,234,0.15)}.device-card.selected{border-color:#667eea;background:#f8f9ff}.device-checkbox{position:absolute;top:15px;right:15px;width:20px;height:20px;cursor:pointer}.device-name{font-size:1.15em;font-weight:bold;color:#333;margin-bottom:5px;padding-right:30px;cursor:pointer}.device-name:hover{color:#667eea}.device-group{display:inline-block;background:#e8f5e9;color:#2e7d32;padding:3px 10px;border-radius:12px;font-size:0.8em;font-weight:600;margin-bottom:10px}.device-info{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:0.9em}.info-row{display:flex;justify-content:space-between;padding:3px 0}.info-label{color:#888}.status-badge{padding:3px 10px;border-radius:12px;font-size:0.85em;font-weight:600}.status-active{background:#e8f5e9;color:#2e7d32}.status-inactive{background:#ffebee;color:#c62828}.proxy-selector{margin-top:12px;padding-top:12px;border-top:1px solid #eee;grid-column:1/-1}.proxy-selector label{display:block;font-size:0.85em;color:#666;margin-bottom:6px}.proxy-selector select{width:100%;padding:8px;border:2px solid #e0e0e0;border-radius:6px;margin-bottom:8px}.current-proxy{font-size:0.85em;color:#667eea;font-weight:600}.change-btn{width:100%;padding:8px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600}.change-btn:hover{opacity:0.9}.pagination{display:flex;justify-content:center;align-items:center;gap:10px;margin-top:20px}.pagination button{padding:8px 16px;border:2px solid #e0e0e0;background:white;border-radius:6px;cursor:pointer;font-weight:600}.pagination button:hover:not(:disabled){border-color:#667eea;color:#667eea}.pagination button:disabled{opacity:0.5;cursor:not-allowed}.bulk-actions{display:flex;gap:10px;align-items:center}.selected-count{background:#667eea;color:white;padding:5px 12px;border-radius:20px;font-size:0.85em;font-weight:600}.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:1000}.modal{background:white;border-radius:15px;padding:25px;width:90%;max-width:450px}.modal h3{margin-bottom:20px;color:#333}.modal-field{margin-bottom:15px}.modal-field label{display:block;font-weight:600;color:#555;margin-bottom:5px}.modal-field input,.modal-field select,.modal-field textarea{width:100%;padding:10px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.modal-field textarea{resize:vertical;min-height:80px}.modal-buttons{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.setup-box{background:#e3f2fd;padding:12px 20px;border-radius:10px;margin-bottom:20px;border-left:4px solid #2196F3}.setup-box code{background:#fff;padding:2px 6px;border-radius:4px;font-family:monospace;color:#d32f2f;font-weight:bold}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>📱 Device Management</h1><p>Monitor and manage all connected devices</p></div><div class="setup-box">📱 Phone Setup: Wi-Fi → Proxy Manual → Host: <code id="serverIP">...</code> Port: <code>8888</code></div><div class="stats-grid"><div class="stat-card" onclick="filterByStatus('all')"><div class="stat-value" id="totalDevices">-</div><div class="stat-label">Total</div></div><div class="stat-card" onclick="filterByStatus('active')"><div class="stat-value" id="activeDevices">-</div><div class="stat-label">Active</div></div><div class="stat-card" onclick="filterByStatus('inactive')"><div class="stat-value" id="inactiveDevices">-</div><div class="stat-label">Inactive</div></div><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Proxies</div></div><div class="stat-card"><div class="stat-value" id="totalRequests">-</div><div class="stat-label">Requests</div></div></div><div class="toolbar"><div class="search-box"><input type="text" id="searchInput" placeholder="Search devices..." oninput="applyFilters()"></div><div class="filter-group"><label>Group:</label><select id="groupFilter" onchange="applyFilters()"><option value="">All</option></select></div><div class="filter-group"><label>Sort:</label><select id="sortBy" onchange="applyFilters()"><option value="name">Name</option><option value="ip">IP</option><option value="lastSeen">Last Seen</option><option value="requests">Requests</option></select></div><button class="btn btn-secondary" onclick="loadData()">🔄 Refresh</button><button class="btn btn-secondary" onclick="location.href='/api/export'">📤 Export</button><div class="bulk-actions" id="bulkActions" style="display:none"><span class="selected-count"><span id="selectedCount">0</span> selected</span><select id="bulkProxySelect"></select><button class="btn btn-primary" onclick="bulkChangeProxy()">Change</button><button class="btn btn-secondary" onclick="clearSelection()">Clear</button></div></div><div class="card"><h2>Connected Devices</h2><div id="devicesList" class="device-grid"><div class="loading">Loading...</div></div><div class="pagination" id="pagination"></div></div></div><div class="modal-overlay" id="editModal" style="display:none"><div class="modal"><h3>✏️ Edit Device</h3><div class="modal-field"><label>Custom Name</label><input type="text" id="editName" placeholder="e.g., Samsung S23"></div><div class="modal-field"><label>Group</label><select id="editGroup"></select></div><div class="modal-field"><label>Notes</label><textarea id="editNotes" placeholder="Optional notes..."></textarea></div><input type="hidden" id="editDeviceIP"><div class="modal-buttons"><button class="btn btn-secondary" onclick="closeEditModal()">Cancel</button><button class="btn btn-primary" onclick="saveDeviceEdit()">Save</button></div></div></div><script>` + baseJS + `document.getElementById('nav-dashboard').classList.add('active');fetch("/api/server-ip").then(r=>r.text()).then(ip=>document.getElementById("serverIP").textContent=ip);let allDevices=[],allProxies=[],allGroups=[],filteredDevices=[],selectedDevices=new Set(),currentPage=1,statusFilter='all';const PER_PAGE=20;function getDisplayName(d){return d.custom_name||d.name||'Unknown';}function isActive(d){return(Date.now()-new Date(d.last_seen))/60000<5;}function proxyLabel(p,i){let ip=p.user&&p.user.includes('ip-')?p.user.split('ip-')[1]:'unknown';return'#'+(i+1)+' – '+ip;}function filterByStatus(s){statusFilter=s;applyFilters();}function applyFilters(){const search=document.getElementById('searchInput').value.toLowerCase();const group=document.getElementById('groupFilter').value;const sort=document.getElementById('sortBy').value;filteredDevices=allDevices.filter(d=>{if(statusFilter==='active'&&!isActive(d))return false;if(statusFilter==='inactive'&&isActive(d))return false;if(group&&d.group!==group)return false;if(search&&!getDisplayName(d).toLowerCase().includes(search)&&!d.ip.includes(search))return false;return true;});filteredDevices.sort((a,b)=>{if(sort==='name')return getDisplayName(a).localeCompare(getDisplayName(b));if(sort==='ip')return a.ip.localeCompare(b.ip);if(sort==='lastSeen')return new Date(b.last_seen)-new Date(a.last_seen);if(sort==='requests')return(b.request_count||0)-(a.request_count||0);return 0;});currentPage=1;renderDevices();}function renderDevices(){const c=document.getElementById('devicesList');if(!filteredDevices.length){c.innerHTML='<div class="loading">No devices found</div>';document.getElementById('pagination').innerHTML='';return;}const pages=Math.ceil(filteredDevices.length/PER_PAGE);const start=(currentPage-1)*PER_PAGE;const pageDevices=filteredDevices.slice(start,start+PER_PAGE);c.innerHTML=pageDevices.map(d=>{const mins=Math.floor((Date.now()-new Date(d.last_seen))/60000);const active=mins<5;const sel=selectedDevices.has(d.ip);const pIdx=allProxies.findIndex(p=>p.full===d.upstream_proxy);const opts=allProxies.map((p,i)=>'<option value="'+i+'" '+(i===pIdx?'selected':'')+'>'+proxyLabel(p,i)+'</option>').join('');const pLabel=pIdx>=0?proxyLabel(allProxies[pIdx],pIdx):'N/A';return'<div class="device-card '+(sel?'selected':'')+'"><input type="checkbox" class="device-checkbox" '+(sel?'checked':'')+' onchange="toggleSel(\''+d.ip+'\',this.checked)"><div class="device-name" onclick="openEditModal(\''+d.ip+'\')">'+escapeHtml(getDisplayName(d))+' ✏️</div><div class="device-group">'+escapeHtml(d.group||'Default')+'</div><div class="device-info"><div class="info-row"><span class="info-label">Status:</span><span class="status-badge '+(active?'status-active':'status-inactive')+'">'+(active?'● Active':'○ Inactive')+'</span></div><div class="info-row"><span class="info-label">IP:</span><span><strong>'+d.ip+'</strong></span></div><div class="info-row"><span class="info-label">Requests:</span><span>'+formatNumber(d.request_count)+'</span></div><div class="info-row"><span class="info-label">Errors:</span><span style="color:'+(d.error_count>0?'#c62828':'#666')+'">'+(d.error_count||0)+'</span></div><div class="info-row"><span class="info-label">Data:</span><span>↓'+formatBytes(d.bytes_in)+'</span></div><div class="info-row"><span class="info-label">Last seen:</span><span>'+(mins<1?'Now':mins+' min')+'</span></div><div class="proxy-selector"><label>Proxy: <span class="current-proxy">'+pLabel+'</span></label><select id="proxy-'+d.ip+'">'+opts+'</select><button class="change-btn" onclick="changeProxy(\''+d.ip+'\')">Change Proxy</button></div></div></div>';}).join('');const pag=document.getElementById('pagination');pag.innerHTML=pages>1?'<button onclick="goPage('+(currentPage-1)+')" '+(currentPage===1?'disabled':'')+'>← Prev</button><span>Page '+currentPage+' of '+pages+'</span><button onclick="goPage('+(currentPage+1)+')" '+(currentPage===pages?'disabled':'')+'>Next →</button>':'<span>'+filteredDevices.length+' devices</span>';updateBulk();}function goPage(p){const pages=Math.ceil(filteredDevices.length/PER_PAGE);if(p>=1&&p<=pages){currentPage=p;renderDevices();}}function escapeHtml(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}function toggleSel(ip,checked){checked?selectedDevices.add(ip):selectedDevices.delete(ip);updateBulk();renderDevices();}function clearSelection(){selectedDevices.clear();updateBulk();renderDevices();}function updateBulk(){const b=document.getElementById('bulkActions');b.style.display=selectedDevices.size>0?'flex':'none';document.getElementById('selectedCount').textContent=selectedDevices.size;}function changeProxy(ip){const idx=parseInt(document.getElementById('proxy-'+ip).value);fetch('/api/change-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:ip,proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxy changed','success');loadData();}});}function bulkChangeProxy(){const idx=parseInt(document.getElementById('bulkProxySelect').value);fetch('/api/bulk-change-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ips:Array.from(selectedDevices),proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.ok){showToast(d.updated+' devices updated','success');selectedDevices.clear();loadData();}});}function openEditModal(ip){const d=allDevices.find(x=>x.ip===ip);if(!d)return;document.getElementById('editDeviceIP').value=ip;document.getElementById('editName').value=d.custom_name||'';document.getElementById('editNotes').value=d.notes||'';document.getElementById('editGroup').innerHTML=allGroups.map(g=>'<option value="'+g+'" '+(g===d.group?'selected':'')+'>'+g+'</option>').join('');document.getElementById('editModal').style.display='flex';}function closeEditModal(){document.getElementById('editModal').style.display='none';}function saveDeviceEdit(){const ip=document.getElementById('editDeviceIP').value;fetch('/api/update-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:ip,custom_name:document.getElementById('editName').value,group:document.getElementById('editGroup').value,notes:document.getElementById('editNotes').value})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Device updated','success');closeEditModal();loadData();}});}function loadGroups(){return fetch('/api/groups').then(r=>r.json()).then(g=>{allGroups=g;document.getElementById('groupFilter').innerHTML='<option value="">All</option>'+g.map(x=>'<option value="'+x+'">'+x+'</option>').join('');});}function loadData(){Promise.all([fetch('/api/stats').then(r=>r.json()),fetch('/api/devices').then(r=>r.json()),fetch('/api/proxies').then(r=>r.json()),loadGroups()]).then(([stats,devices,proxies])=>{document.getElementById('totalDevices').textContent=stats.total_devices||0;document.getElementById('activeDevices').textContent=stats.active_devices||0;document.getElementById('inactiveDevices').textContent=(stats.total_devices-stats.active_devices)||0;document.getElementById('totalProxies').textContent=stats.total_proxies||0;document.getElementById('totalRequests').textContent=formatNumber(stats.total_requests||0);allDevices=devices||[];allProxies=proxies||[];document.getElementById('bulkProxySelect').innerHTML=allProxies.map((p,i)=>'<option value="'+i+'">'+proxyLabel(p,i)+'</option>').join('');applyFilters();});}loadData();setInterval(loadData,15000);</script></body></html>`

const healthPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Proxy Health</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:20px}.proxy-card{background:white;border-radius:12px;padding:20px;box-shadow:0 2px 10px rgba(0,0,0,0.05);border-left:4px solid #ccc}.proxy-card.healthy{border-left-color:#4caf50}.proxy-card.degraded{border-left-color:#ff9800}.proxy-card.unhealthy{border-left-color:#f44336}.proxy-card.unknown{border-left-color:#9e9e9e}.proxy-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.proxy-name{font-size:1.2em;font-weight:bold;color:#333}.proxy-status{padding:5px 12px;border-radius:20px;font-size:0.85em;font-weight:600}.proxy-status.healthy{background:#e8f5e9;color:#2e7d32}.proxy-status.degraded{background:#fff3e0;color:#e65100}.proxy-status.unhealthy{background:#ffebee;color:#c62828}.proxy-status.unknown{background:#f5f5f5;color:#666}.proxy-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px}.proxy-stat{padding:10px;background:#f8f9fa;border-radius:8px}.proxy-stat-value{font-size:1.3em;font-weight:bold;color:#667eea}.proxy-stat-label{font-size:0.8em;color:#666;text-transform:uppercase}.progress-bar{height:8px;background:#e0e0e0;border-radius:4px;overflow:hidden;margin-top:10px}.progress-fill{height:100%;border-radius:4px;transition:width 0.3s}.progress-fill.good{background:#4caf50}.progress-fill.warning{background:#ff9800}.progress-fill.bad{background:#f44336}.last-error{margin-top:10px;padding:10px;background:#ffebee;border-radius:8px;font-size:0.85em;color:#c62828;word-break:break-all}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>💚 Proxy Health Monitor</h1><p>Real-time health status of all upstream proxies</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Total Proxies</div></div><div class="stat-card"><div class="stat-value" id="healthyProxies" style="color:#4caf50">-</div><div class="stat-label">Healthy</div></div><div class="stat-card"><div class="stat-value" id="degradedProxies" style="color:#ff9800">-</div><div class="stat-label">Degraded</div></div><div class="stat-card"><div class="stat-value" id="unhealthyProxies" style="color:#f44336">-</div><div class="stat-label">Unhealthy</div></div><div class="stat-card"><div class="stat-value" id="avgSuccessRate">-</div><div class="stat-label">Avg Success</div></div></div><div class="card"><h2>Proxy Status</h2><button class="btn btn-secondary" onclick="loadHealth()" style="float:right;margin-top:-45px">🔄 Refresh</button><div id="healthGrid" class="health-grid"><div class="loading">Loading...</div></div></div></div><script>` + baseJS + `document.getElementById('nav-health').classList.add('active');function loadHealth(){fetch('/api/proxy-health').then(r=>r.json()).then(data=>{let healthy=0,degraded=0,unhealthy=0,totalRate=0;data.forEach(p=>{if(p.status==='healthy')healthy++;else if(p.status==='degraded')degraded++;else if(p.status==='unhealthy')unhealthy++;totalRate+=p.success_rate||0;});document.getElementById('totalProxies').textContent=data.length;document.getElementById('healthyProxies').textContent=healthy;document.getElementById('degradedProxies').textContent=degraded;document.getElementById('unhealthyProxies').textContent=unhealthy;document.getElementById('avgSuccessRate').textContent=data.length?(totalRate/data.length).toFixed(1)+'%':'-';document.getElementById('healthGrid').innerHTML=data.map(p=>{const rate=p.success_rate||0;const rateClass=rate>=95?'good':rate>=80?'warning':'bad';return'<div class="proxy-card '+p.status+'"><div class="proxy-header"><span class="proxy-name">#'+(p.index+1)+' – '+p.ip_address+'</span><span class="proxy-status '+p.status+'">'+p.status.toUpperCase()+'</span></div><div class="proxy-stats"><div class="proxy-stat"><div class="proxy-stat-value">'+formatNumber(p.total_requests)+'</div><div class="proxy-stat-label">Requests</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+rate.toFixed(1)+'%</div><div class="proxy-stat-label">Success Rate</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+formatNumber(p.success_count)+'</div><div class="proxy-stat-label">Success</div></div><div class="proxy-stat"><div class="proxy-stat-value" style="color:#c62828">'+formatNumber(p.failure_count)+'</div><div class="proxy-stat-label">Failures</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+p.avg_response_time_ms+'ms</div><div class="proxy-stat-label">Avg Response</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+p.active_devices+'</div><div class="proxy-stat-label">Active Devices</div></div></div><div class="progress-bar"><div class="progress-fill '+rateClass+'" style="width:'+rate+'%"></div></div>'+(p.last_error?'<div class="last-error">Last error: '+p.last_error+'</div>':'')+'</div>';}).join('');});}loadHealth();setInterval(loadHealth,30000);</script></body></html>`

const analyticsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Analytics</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.chart-container{background:white;border-radius:12px;padding:25px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}.chart-container h2{margin-bottom:20px}.chart{width:100%;height:300px;position:relative}.chart-bars{display:flex;align-items:flex-end;height:250px;gap:4px;padding:0 10px;border-bottom:2px solid #e0e0e0}.chart-bar{flex:1;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:4px 4px 0 0;min-width:8px;position:relative;transition:height 0.3s}.chart-bar:hover{opacity:0.8}.chart-bar .tooltip{position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#333;color:white;padding:5px 10px;border-radius:4px;font-size:0.8em;white-space:nowrap;opacity:0;transition:opacity 0.2s;pointer-events:none}.chart-bar:hover .tooltip{opacity:1}.chart-labels{display:flex;gap:4px;padding:10px 10px 0}.chart-label{flex:1;text-align:center;font-size:0.7em;color:#666}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>📊 Traffic Analytics</h1><p>Historical traffic data and trends</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalData">-</div><div class="stat-label">Total Data</div></div><div class="stat-card"><div class="stat-value" id="totalReqs">-</div><div class="stat-label">Total Requests</div></div><div class="stat-card"><div class="stat-value" id="peakDevices">-</div><div class="stat-label">Peak Devices</div></div><div class="stat-card"><div class="stat-value" id="errorRate">-</div><div class="stat-label">Error Rate</div></div></div><div class="chart-container"><h2>📈 Traffic Over Time</h2><button class="btn btn-secondary" onclick="loadAnalytics()" style="float:right;margin-top:-45px">🔄 Refresh</button><div class="chart"><div class="chart-bars" id="trafficBars"></div><div class="chart-labels" id="trafficLabels"></div></div></div><div class="chart-container"><h2>📊 Active Devices Over Time</h2><div class="chart"><div class="chart-bars" id="deviceBars"></div><div class="chart-labels" id="deviceLabels"></div></div></div></div><script>` + baseJS + `document.getElementById('nav-analytics').classList.add('active');function loadAnalytics(){fetch('/api/traffic-history').then(r=>r.json()).then(data=>{if(!data||!data.length){document.getElementById('trafficBars').innerHTML='<div class="loading">No data yet. Traffic data is collected every 5 minutes.</div>';return;}const totalBytes=data.reduce((a,d)=>a+(d.total_bytes_in||0)+(d.total_bytes_out||0),0);const totalReqs=data.length>0?data[data.length-1].total_requests:0;const peakDevices=Math.max(...data.map(d=>d.active_devices||0));const totalErrors=data.length>0?data[data.length-1].error_count:0;const errorRate=totalReqs>0?((totalErrors/totalReqs)*100).toFixed(2)+'%':'0%';document.getElementById('totalData').textContent=formatBytes(totalBytes);document.getElementById('totalReqs').textContent=formatNumber(totalReqs);document.getElementById('peakDevices').textContent=peakDevices;document.getElementById('errorRate').textContent=errorRate;const maxBytes=Math.max(...data.map(d=>(d.total_bytes_in||0)+(d.total_bytes_out||0)));const maxDevices=Math.max(...data.map(d=>d.active_devices||0));document.getElementById('trafficBars').innerHTML=data.map(d=>{const bytes=(d.total_bytes_in||0)+(d.total_bytes_out||0);const h=maxBytes>0?(bytes/maxBytes*230):5;return'<div class="chart-bar" style="height:'+h+'px"><span class="tooltip">'+formatBytes(bytes)+'</span></div>';}).join('');document.getElementById('trafficLabels').innerHTML=data.map((d,i)=>{if(i%Math.ceil(data.length/8)===0){return'<div class="chart-label">'+new Date(d.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+'</div>';}return'<div class="chart-label"></div>';}).join('');document.getElementById('deviceBars').innerHTML=data.map(d=>{const h=maxDevices>0?(d.active_devices/maxDevices*230):5;return'<div class="chart-bar" style="height:'+h+'px;background:linear-gradient(135deg,#4caf50 0%,#2e7d32 100%)"><span class="tooltip">'+d.active_devices+' devices</span></div>';}).join('');document.getElementById('deviceLabels').innerHTML=data.map((d,i)=>{if(i%Math.ceil(data.length/8)===0){return'<div class="chart-label">'+new Date(d.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+'</div>';}return'<div class="chart-label"></div>';}).join('');});}loadAnalytics();setInterval(loadAnalytics,60000);</script></body></html>`

const settingsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Settings</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.settings-section{background:white;border-radius:12px;padding:25px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}.settings-section h2{margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #f0f0f0}.form-group{margin-bottom:20px}.form-group label{display:block;font-weight:600;color:#333;margin-bottom:8px}.form-group input{width:100%;max-width:400px;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.form-group input:focus{outline:none;border-color:#667eea}.form-group small{display:block;color:#666;margin-top:5px;font-size:0.85em}.success-msg{background:#e8f5e9;color:#2e7d32;padding:12px;border-radius:8px;margin-bottom:20px;display:none}.success-msg.show{display:block}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>⚙️ Settings</h1><p>Configure your Lumier Dynamics system</p></div><div class="settings-section"><h2>🔐 Change Password</h2><div class="success-msg" id="pwSuccess">Password changed successfully!</div><form onsubmit="return changePassword(event)"><div class="form-group"><label>Current Password</label><input type="password" id="oldPassword" required></div><div class="form-group"><label>New Password</label><input type="password" id="newPassword" required><small>Choose a strong password with at least 8 characters</small></div><div class="form-group"><label>Confirm New Password</label><input type="password" id="confirmPassword" required></div><button type="submit" class="btn btn-primary">Change Password</button></form></div><div class="settings-section"><h2>📱 Device Groups</h2><p style="margin-bottom:15px;color:#666">Manage device groups for better organization</p><div id="groupsList" style="margin-bottom:15px"></div><div style="display:flex;gap:10px"><input type="text" id="newGroupName" placeholder="New group name..." style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;flex:1;max-width:300px"><button class="btn btn-primary" onclick="addGroup()">Add Group</button></div></div><div class="settings-section"><h2>ℹ️ System Information</h2><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px"><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Version:</strong> 3.0.0</div><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Server IP:</strong> <span id="sysServerIP">...</span></div><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Proxy Port:</strong> 8888</div><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Dashboard Port:</strong> 8080</div></div></div></div><script>` + baseJS + `document.getElementById('nav-settings').classList.add('active');fetch('/api/server-ip').then(r=>r.text()).then(ip=>document.getElementById('sysServerIP').textContent=ip);function loadGroups(){fetch('/api/groups').then(r=>r.json()).then(groups=>{document.getElementById('groupsList').innerHTML=groups.map(g=>'<span style="display:inline-block;background:#e3f2fd;color:#1976d2;padding:8px 15px;border-radius:20px;margin:5px;font-weight:500">'+g+'</span>').join('');});}loadGroups();function addGroup(){const name=document.getElementById('newGroupName').value.trim();if(!name){showToast('Please enter a group name','error');return;}fetch('/api/add-group',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast(d.added?'Group added':'Group already exists',d.added?'success':'');document.getElementById('newGroupName').value='';loadGroups();}});}function changePassword(e){e.preventDefault();const oldPw=document.getElementById('oldPassword').value;const newPw=document.getElementById('newPassword').value;const confirmPw=document.getElementById('confirmPassword').value;if(newPw!==confirmPw){showToast('Passwords do not match','error');return false;}if(newPw.length<6){showToast('Password must be at least 6 characters','error');return false;}fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:oldPw,new_password:newPw})}).then(r=>{if(r.ok){document.getElementById('pwSuccess').classList.add('show');document.getElementById('oldPassword').value='';document.getElementById('newPassword').value='';document.getElementById('confirmPassword').value='';setTimeout(()=>document.getElementById('pwSuccess').classList.remove('show'),3000);}else{showToast('Current password is incorrect','error');}});return false;}</script></body></html>`
