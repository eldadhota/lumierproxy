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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

type Device struct {
	ID            string    `json:"id"`
	IP            string    `json:"ip"`
	Username      string    `json:"username"`
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
	// Session confirmation fields
	Confirmed     bool      `json:"confirmed"`
	ConfirmedAt   time.Time `json:"confirmed_at"`
	SessionStart  time.Time `json:"session_start"`
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
	Username         string    `json:"username"`
	CustomName       string    `json:"custom_name"`
	Group            string    `json:"group"`
	Notes            string    `json:"notes"`
	ProxyIndex       int       `json:"proxy_index"`
	LastIP           string    `json:"last_ip,omitempty"`            // Last known IP for IP-based device lookup
	LastConfirmed    time.Time `json:"last_confirmed,omitempty"`     // When device last confirmed correct proxy
	LastSessionStart time.Time `json:"last_session_start,omitempty"` // When current session started
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
	Supervisors     []Supervisor            `json:"supervisors"`
	AdminPassword   string                  `json:"admin_password"`
	ProxyNames      map[int]string          `json:"proxy_names"` // Custom names for proxies (index -> name)
}

type Supervisor struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type SystemSettings struct {
	SessionTimeout       int `json:"session_timeout_hours"`
	TrafficRetentionDays int `json:"traffic_retention_days"`
	DeviceTimeoutMinutes int `json:"device_timeout_minutes"`
}

// ============================================================================
// USERNAME PARSING FROM PROXY AUTH
// ============================================================================

// parseProxyUsername extracts the username from Proxy-Authorization header
// The header format is: Basic base64(username:password)
func parseProxyUsername(r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return ""
	}

	// Remove "Basic " prefix
	if !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	encoded := strings.TrimPrefix(auth, "Basic ")

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}

	// Split username:password and return username
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// findDeviceByUsername looks up a device by its username (primary identifier)
func (s *ProxyServer) findDeviceByUsername(username string) *Device {
	for _, device := range s.devices {
		if device.Username == username {
			return device
		}
	}
	return nil
}

// findDeviceByIP looks up a device by its current IP address
func (s *ProxyServer) findDeviceByIP(ip string) *Device {
	for _, device := range s.devices {
		if device.IP == ip {
			return device
		}
	}
	return nil
}

// findAnonymousDeviceByIP looks up an anonymous device (no username) by IP
func (s *ProxyServer) findAnonymousDeviceByIP(ip string) *Device {
	for _, device := range s.devices {
		if device.IP == ip && device.Username == "" {
			return device
		}
	}
	return nil
}

type ProxyServer struct {
	devices         map[string]*Device
	mu              sync.RWMutex
	proxyPool       []string
	proxyHealth     map[int]*ProxyHealth
	healthMu        sync.RWMutex
	poolIndex       int
	poolMu          sync.Mutex
	proxyPort       int
	dashPort        int
	bindAddr        string
	allowIPFallback bool
	authRequired    bool
	requireRegister bool
	persistentData  PersistentData
	persistMu       sync.RWMutex
	dataFile        string
	sessions        map[string]*Session
	appSessions     map[string]*Session
	sessionMu       sync.RWMutex
	startTime       time.Time
	logBuffer       []LogEntry
	logMu           sync.RWMutex
	cpuUsage        float64
	cpuMu           sync.RWMutex
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type ProxyInfo struct {
	Index      int    `json:"index"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	User       string `json:"user"`
	Pass       string `json:"pass"`
	Full       string `json:"full"`
	CustomName string `json:"custom_name"`
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
	Username   string `json:"username"`
}

type bulkChangeProxyRequest struct {
	DeviceIPs  []string `json:"device_ips"`
	ProxyIndex int      `json:"proxy_index"`
}

type addGroupRequest struct {
	GroupName string `json:"group_name"`
}

type deleteGroupRequest struct {
	GroupName string `json:"group_name"`
}

type addProxyRequest struct {
	ProxyString string `json:"proxy_string"`
}

type deleteProxyRequest struct {
	ProxyIndex int `json:"proxy_index"`
}

type deleteDeviceRequest struct {
	DeviceIP string `json:"device_ip"`
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
		devices:         make(map[string]*Device),
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
		appSessions:     make(map[string]*Session),
		startTime:       time.Now(),
		logBuffer:       make([]LogEntry, 0, 1000),
		persistentData: PersistentData{
			DeviceConfigs:   make(map[string]DeviceConfig),
			Groups:          []string{"Default", "Floor 1", "Floor 2", "Team A", "Team B"},
			Users:           []UserCredentials{},
			TrafficHistory:  []TrafficSnapshot{},
			ProxyHealthData: make(map[int]*ProxyHealth),
			SystemSettings: SystemSettings{
				SessionTimeout:       2, // 2 hours default WiFi session timeout
				TrafficRetentionDays: 7,
				DeviceTimeoutMinutes: 30,
			},
		},
	}

	server.loadPersistentData()
	server.restoreDevicesFromConfig() // Restore devices so IP-based lookup works after restart
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
	go cpuMonitor()
	go startDashboard()

	serverIP := getServerIP()
	log.Printf("🚀 Proxy server starting on port %d\n", server.proxyPort)
	log.Printf("📊 Dashboard: http://%s:%d\n", serverIP, server.dashPort)
	log.Println("🔐 Default login: admin / admin123")
	log.Printf("📱 Phone setup: Proxy %s:%d\n", serverIP, server.proxyPort)

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", server.bindAddr, server.proxyPort), http.HandlerFunc(handleProxy)); err != nil {
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

func (s *ProxyServer) createAppSession(username string) *Session {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := base64.URLEncoding.EncodeToString(bytes)
	s.sessionMu.Lock()
	s.appSessions[token] = &Session{
		Token:     token,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(s.persistentData.SystemSettings.SessionTimeout) * time.Hour),
	}
	s.sessionMu.Unlock()
	return s.appSessions[token]
}

func (s *ProxyServer) validateAppSession(token, username string) (*Session, bool) {
	s.sessionMu.RLock()
	session, ok := s.appSessions[token]
	s.sessionMu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) || session.Username != username {
		if ok {
			s.sessionMu.Lock()
			delete(s.appSessions, token)
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
		for token, session := range server.appSessions {
			if now.After(session.ExpiresAt) {
				delete(server.appSessions, token)
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
	// Initialize default supervisors if empty
	if len(s.persistentData.Supervisors) == 0 {
		s.persistentData.Supervisors = []Supervisor{
			{Name: "Mirko", Password: "DobroJeMirko321a"},
			{Name: "Ana", Password: "SupervisorAna123"},
			{Name: "Marko", Password: "SupervisorMarko456"},
			{Name: "Ivan", Password: "SupervisorIvan789"},
		}
	}
	// Initialize default admin password if empty
	if s.persistentData.AdminPassword == "" {
		s.persistentData.AdminPassword = "Drnda123"
	}
	// Initialize proxy names map if empty
	if s.persistentData.ProxyNames == nil {
		s.persistentData.ProxyNames = make(map[int]string)
	}
}

// getProxyName returns the custom name for a proxy or the default "SG{n}" format
func (s *ProxyServer) getProxyName(index int) string {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()
	if name, ok := s.persistentData.ProxyNames[index]; ok && name != "" {
		return name
	}
	return fmt.Sprintf("SG%d", index+1)
}

// restoreDevicesFromConfig recreates device objects from saved configs so that
// IP-based lookup works immediately after a server restart. Without this,
// registered devices would be blocked until they re-register because the
// in-memory devices map would be empty.
func (s *ProxyServer) restoreDevicesFromConfig() {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()

	count := 0
	for username, cfg := range s.persistentData.DeviceConfigs {
		// Skip IP-keyed entries (used for allowIPFallback mode)
		if cfg.Username == "" || cfg.Username != username {
			continue
		}

		// Determine upstream proxy
		var upstreamProxy string
		s.poolMu.Lock()
		if cfg.ProxyIndex >= 0 && cfg.ProxyIndex < len(s.proxyPool) {
			upstreamProxy = s.proxyPool[cfg.ProxyIndex]
		} else if len(s.proxyPool) > 0 {
			upstreamProxy = s.proxyPool[0]
		}
		s.poolMu.Unlock()

		device := &Device{
			ID:            fmt.Sprintf("device-%s", username),
			IP:            cfg.LastIP, // Restore last known IP
			Username:      username,
			Name:          username,
			CustomName:    cfg.CustomName,
			Group:         cfg.Group,
			Notes:         cfg.Notes,
			UpstreamProxy: upstreamProxy,
			Status:        "active",
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
		}

		s.mu.Lock()
		s.devices[username] = device
		s.mu.Unlock()
		count++
	}

	if count > 0 {
		log.Printf("📱 Restored %d registered devices from config\n", count)
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
	// Check if this is a proxy-side/destination error (not our proxy's fault)
	if isProxySideError(errorMsg) {
		// Still count the request but don't penalize the proxy health
		s.healthMu.Lock()
		defer s.healthMu.Unlock()
		health, exists := s.proxyHealth[proxyIndex]
		if !exists {
			return
		}
		health.TotalRequests++
		health.SuccessCount++ // Count as success since proxy worked fine
		if health.TotalRequests > 0 {
			health.SuccessRate = float64(health.SuccessCount) / float64(health.TotalRequests) * 100
		}
		health.Status = s.calculateProxyStatus(health)
		return
	}

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

// isProxySideError checks if an error is caused by the destination/ruleset
// rather than the proxy itself being unhealthy
func isProxySideError(errMsg string) bool {
	proxySideErrors := []string{
		"connection not allowed by ruleset",
		"not allowed by ruleset",
		"host unreachable",
		"network unreachable",
		"connection refused",
		"ttl expired",
		"no route to host",
		"address not supported",
		"connection reset by peer",
		"broken pipe",
	}
	errLower := strings.ToLower(errMsg)
	for _, e := range proxySideErrors {
		if strings.Contains(errLower, e) {
			return true
		}
	}
	return false
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
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
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
// SYSTEM MONITORING
// ============================================================================

func cpuMonitor() {
	var lastTotal, lastIdle uint64
	for range time.NewTicker(2 * time.Second).C {
		total, idle := getCPUTimes()
		if lastTotal > 0 {
			totalDelta := total - lastTotal
			idleDelta := idle - lastIdle
			if totalDelta > 0 {
				usage := 100.0 * (1.0 - float64(idleDelta)/float64(totalDelta))
				server.cpuMu.Lock()
				server.cpuUsage = usage
				server.cpuMu.Unlock()
			}
		}
		lastTotal, lastIdle = total, idle
	}
}

func getCPUTimes() (total, idle uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 1 {
		return 0, 0
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	for i := 1; i < len(fields); i++ {
		var val uint64
		fmt.Sscanf(fields[i], "%d", &val)
		total += val
		if i == 4 {
			idle = val
		}
	}
	return total, idle
}

func (s *ProxyServer) addLog(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}
	s.logMu.Lock()
	s.logBuffer = append(s.logBuffer, entry)
	// Keep only last 500 entries
	if len(s.logBuffer) > 500 {
		s.logBuffer = s.logBuffer[len(s.logBuffer)-500:]
	}
	s.logMu.Unlock()
}

func (s *ProxyServer) getLogs(limit int) []LogEntry {
	s.logMu.RLock()
	defer s.logMu.RUnlock()
	if limit <= 0 || limit > len(s.logBuffer) {
		limit = len(s.logBuffer)
	}
	start := len(s.logBuffer) - limit
	if start < 0 {
		start = 0
	}
	result := make([]LogEntry, limit)
	copy(result, s.logBuffer[start:])
	return result
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

func (s *ProxyServer) getOrCreateDevice(clientIP string, username string) (*Device, error) {
	// Optionally recover the username from the last saved config for this IP if
	// IP-based fallback is explicitly allowed.
	if username == "" && s.allowIPFallback {
		s.persistMu.RLock()
		if cfg, ok := s.persistentData.DeviceConfigs[clientIP]; ok && cfg.Username != "" {
			username = cfg.Username
		}
		s.persistMu.RUnlock()
	}

	// When no username is provided (e.g., Android WiFi proxy which can't send
	// Proxy-Authorization headers), look up if there's a registered device with
	// this IP. This allows registered devices to use the proxy without needing
	// to send credentials with every request.
	if username == "" && s.requireRegister {
		s.mu.RLock()
		existingDevice := s.findDeviceByIP(clientIP)
		if existingDevice != nil && existingDevice.Username != "" {
			// Found a registered device with this IP - use it directly
			existingDevice.LastSeen = time.Now()
			s.mu.RUnlock()
			return existingDevice, nil
		}
		s.mu.RUnlock()
		// No registered device found for this IP
		return nil, fmt.Errorf("registration required: no username presented")
	}

	// Check persistence for a registered profile when required.
	s.persistMu.RLock()
	var savedConfig DeviceConfig
	var hasSavedConfig bool
	if username != "" {
		savedConfig, hasSavedConfig = s.persistentData.DeviceConfigs[username]
	}
	s.persistMu.RUnlock()

	if username != "" && s.requireRegister && !hasSavedConfig {
		return nil, fmt.Errorf("registration required: unknown username '%s'", username)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// First, try to find device by username (primary identifier)
	if username != "" {
		if device := s.findDeviceByUsername(username); device != nil {
			// Update IP if it changed (device got new IP from DHCP)
			if device.IP != clientIP {
				oldIP := device.IP
				device.IP = clientIP
				log.Printf("📱 Device '%s' IP changed: %s -> %s\n", username, oldIP, clientIP)
				s.addLog("info", fmt.Sprintf("Device '%s' IP changed: %s -> %s", username, oldIP, clientIP))
			}
			device.LastSeen = time.Now()
			return device, nil
		}
	}

	// For requests without username, optionally allow IP-based reuse for
	// backwards compatibility when explicitly enabled.
	if username == "" && s.allowIPFallback {
		if device := s.findDeviceByIP(clientIP); device != nil {
			device.LastSeen = time.Now()
			return device, nil
		}
	}

	var upstreamProxy, customName, group, notes string = s.getNextProxy(), "", "Default", ""
	if hasSavedConfig {
		if savedConfig.ProxyIndex >= 0 && savedConfig.ProxyIndex < len(s.proxyPool) {
			upstreamProxy = s.proxyPool[savedConfig.ProxyIndex]
		}
		customName, group, notes = savedConfig.CustomName, savedConfig.Group, savedConfig.Notes
	}

	// If registration is required and there is still no username, deny the
	// request instead of creating an anonymous device.
	if username == "" && s.requireRegister {
		return nil, fmt.Errorf("registration required: no username mapping found")
	}

	// Generate device ID based on username if available
	var deviceID, deviceName string
	if username != "" {
		deviceID = fmt.Sprintf("device-%s", username)
		deviceName = username
	} else {
		deviceID = fmt.Sprintf("device-%d", len(s.devices)+1)
		deviceName = fmt.Sprintf("Anonymous-%s", clientIP)
	}

	device := &Device{
		ID:            deviceID,
		IP:            clientIP,
		Username:      username,
		Name:          deviceName,
		CustomName:    customName,
		Group:         group,
		Notes:         notes,
		UpstreamProxy: upstreamProxy,
		Status:        "active",
		FirstSeen:     time.Now(),
		LastSeen:      time.Now(),
	}

	// Store by username if available, otherwise by IP
	if username != "" {
		s.devices[username] = device
		log.Printf("📱 New device: '%s' (%s) -> %s\n", username, clientIP, extractProxyIP(upstreamProxy))
		s.addLog("info", fmt.Sprintf("New device connected: '%s' (%s) -> Proxy %s", username, clientIP, extractProxyIP(upstreamProxy)))
	} else {
		s.devices[clientIP] = device
		log.Printf("📱 New anonymous device: %s -> %s\n", clientIP, extractProxyIP(upstreamProxy))
		s.addLog("info", fmt.Sprintf("New anonymous device: %s -> Proxy %s", clientIP, extractProxyIP(upstreamProxy)))
	}

	// Save new device config for persistence
	go s.saveDeviceConfig(device)

	return device, nil
}

// saveDeviceConfig saves a device's config to persistent storage
func (s *ProxyServer) saveDeviceConfig(device *Device) {
	// Read device fields under lock to avoid race conditions
	s.mu.RLock()
	upstreamProxy := device.UpstreamProxy
	username := device.Username
	customName := device.CustomName
	group := device.Group
	notes := device.Notes
	deviceIP := device.IP
	s.mu.RUnlock()

	// Find proxy index under pool lock
	s.poolMu.Lock()
	proxyIndex := 0
	for i, p := range s.proxyPool {
		if p == upstreamProxy {
			proxyIndex = i
			break
		}
	}
	s.poolMu.Unlock()

	cfg := DeviceConfig{
		Username:   username,
		CustomName: customName,
		Group:      group,
		Notes:      notes,
		ProxyIndex: proxyIndex,
		LastIP:     deviceIP,
	}

	s.persistMu.Lock()
	// Persist profiles by username as the primary key. When IP-based
	// fallback is enabled, also store the latest IP as an alias so that
	// proxy requests that arrive without auth headers can still be bound
	// to the correct username/profile instead of creating anonymous
	// devices for the same phone.
	if username != "" {
		s.persistentData.DeviceConfigs[username] = cfg
		if s.allowIPFallback && deviceIP != "" {
			s.persistentData.DeviceConfigs[deviceIP] = cfg
		}
	}
	s.persistMu.Unlock()

	go s.savePersistentData()
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Allow the mobile app to hit its API on the proxy port (e.g., if the user
	// enters 8888 instead of the dashboard port). This avoids forwarding the
	// app's own control calls through an upstream proxy, which would hang or
	// fail.
	switch r.URL.Path {
	case "/api/app/proxies":
		handleAppProxiesAPI(w, r)
		return
	case "/api/app/register":
		handleAppRegisterAPI(w, r)
		return
	case "/api/app/change-proxy":
		handleAppChangeProxyAPI(w, r)
		return
	case "/api/app/authenticate":
		handleAppAuthenticateAPI(w, r)
		return
	case "/api/app/whoami":
		handleAppWhoAmI(w, r)
		return
	case "/api/app/check-ip":
		handleAppCheckIP(w, r)
		return
	case "/api/app/validate-password":
		handleAppValidatePassword(w, r)
		return
	}

	username := parseProxyUsername(r)
	device, err := server.getOrCreateDevice(clientIP, username)
	if err != nil {
		http.Error(w, "Registration required: please authenticate in the app", http.StatusProxyAuthRequired)
		return
	}
	atomic.AddInt64(&device.RequestCount, 1)

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
		errMsg := err.Error()
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, errMsg)
		}
		// Only count as device error if it's not a proxy-side issue
		if !isProxySideError(errMsg) {
			atomic.AddInt64(&device.ErrorCount, 1)
			server.mu.Lock()
			device.LastError = errMsg
			device.LastErrorTime = time.Now()
			server.mu.Unlock()
			server.addLog("error", fmt.Sprintf("HTTPS proxy error for %s: %s", device.IP, errMsg))
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
		atomic.AddInt64(&device.BytesOut, n)
		done <- true
	}()

	go func() {
		n, _ := io.Copy(clientConn, targetConn)
		bytesIn = n
		atomic.AddInt64(&device.BytesIn, n)
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
		errMsg := err.Error()
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, errMsg)
		}
		if !isProxySideError(errMsg) {
			atomic.AddInt64(&device.ErrorCount, 1)
			server.mu.Lock()
			device.LastError = errMsg
			server.mu.Unlock()
		}
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	r.RequestURI = ""
	if err := r.Write(targetConn); err != nil {
		errMsg := err.Error()
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, errMsg)
		}
		if !isProxySideError(errMsg) {
			atomic.AddInt64(&device.ErrorCount, 1)
		}
		http.Error(w, "Failed to send request", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		errMsg := err.Error()
		if proxyIndex >= 0 {
			server.recordProxyFailure(proxyIndex, errMsg)
		}
		if !isProxySideError(errMsg) {
			atomic.AddInt64(&device.ErrorCount, 1)
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
	atomic.AddInt64(&device.BytesIn, n)

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

	// Public app API (no auth required)
	http.HandleFunc("/api/app/proxies", handleAppProxiesAPI)
	http.HandleFunc("/api/app/register", handleAppRegisterAPI)
	http.HandleFunc("/api/app/change-proxy", handleAppChangeProxyAPI)
	http.HandleFunc("/api/app/authenticate", handleAppAuthenticateAPI)
	http.HandleFunc("/api/app/whoami", handleAppWhoAmI)
	http.HandleFunc("/api/app/check-ip", handleAppCheckIP)
	http.HandleFunc("/api/app/validate-password", handleAppValidatePassword)

	http.HandleFunc("/dashboard", server.requireAuth(handleDashboard))
	http.HandleFunc("/health", server.requireAuth(handleHealthPage))
	http.HandleFunc("/analytics", server.requireAuth(handleAnalyticsPage))
	http.HandleFunc("/settings", server.requireAuth(handleSettingsPage))
	http.HandleFunc("/monitoring", server.requireAuth(handleMonitoringPage))

	http.HandleFunc("/api/devices", server.requireAuth(handleDevicesAPI))
	http.HandleFunc("/api/stats", server.requireAuth(handleStatsAPI))
	http.HandleFunc("/api/server-ip", server.requireAuth(handleServerIPAPI))
	http.HandleFunc("/api/proxies", server.requireAuth(handleProxiesAPI))
	http.HandleFunc("/api/change-proxy", server.requireAuth(handleChangeProxyAPI))
	http.HandleFunc("/api/update-device", server.requireAuth(handleUpdateDeviceAPI))
	http.HandleFunc("/api/bulk-change-proxy", server.requireAuth(handleBulkChangeProxyAPI))
	http.HandleFunc("/api/groups", server.requireAuth(handleGroupsAPI))
	http.HandleFunc("/api/add-group", server.requireAuth(handleAddGroupAPI))
	http.HandleFunc("/api/delete-group", server.requireAuth(handleDeleteGroupAPI))
	http.HandleFunc("/api/add-proxy", server.requireAuth(handleAddProxyAPI))
	http.HandleFunc("/api/delete-proxy", server.requireAuth(handleDeleteProxyAPI))
	http.HandleFunc("/api/delete-device", server.requireAuth(handleDeleteDeviceAPI))
	http.HandleFunc("/api/export", server.requireAuth(handleExportAPI))
	http.HandleFunc("/api/bulk-import-proxies", server.requireAuth(handleBulkImportProxiesAPI))
	http.HandleFunc("/api/proxy-health", server.requireAuth(handleProxyHealthAPI))
	http.HandleFunc("/api/traffic-history", server.requireAuth(handleTrafficHistoryAPI))
	http.HandleFunc("/api/change-password", server.requireAuth(handleChangePasswordAPI))
	http.HandleFunc("/api/system-stats", server.requireAuth(handleSystemStatsAPI))
	http.HandleFunc("/api/logs", server.requireAuth(handleLogsAPI))
	http.HandleFunc("/api/supervisors", server.requireAuth(handleSupervisorsAPI))
	http.HandleFunc("/api/add-supervisor", server.requireAuth(handleAddSupervisorAPI))
	http.HandleFunc("/api/update-supervisor", server.requireAuth(handleUpdateSupervisorAPI))
	http.HandleFunc("/api/delete-supervisor", server.requireAuth(handleDeleteSupervisorAPI))
	http.HandleFunc("/api/admin-password", server.requireAuth(handleAdminPasswordAPI))
	http.HandleFunc("/api/update-proxy-name", server.requireAuth(handleUpdateProxyNameAPI))
	http.HandleFunc("/api/reorder-proxies", server.requireAuth(handleReorderProxiesAPI))

	log.Printf("📊 Dashboard on port %d\n", server.dashPort)
	addr := fmt.Sprintf("%s:%d", server.bindAddr, server.dashPort)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("failed to start dashboard on %s: %v", addr, err)
	}
}

func parseEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		log.Printf("⚠️  Invalid %s value '%s', using default %d\n", key, value, fallback)
		return fallback
	}

	return parsed
}

func parseEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}

	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		log.Printf("⚠️  Invalid %s value '%s', using default %t\n", key, value, fallback)
		return fallback
	}
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

// DeviceWithStatus extends Device with online status for API response
type DeviceWithStatus struct {
	*Device
	Online bool `json:"online"`
}

func handleDevicesAPI(w http.ResponseWriter, r *http.Request) {
	// Check if we want to include offline devices
	includeOffline := r.URL.Query().Get("include_offline") == "true"

	server.mu.RLock()
	activeUsernames := make(map[string]bool)
	devices := make([]DeviceWithStatus, 0)

	// Add all active devices
	for _, d := range server.devices {
		isOnline := time.Since(d.LastSeen) < 5*time.Minute
		devices = append(devices, DeviceWithStatus{Device: d, Online: isOnline})
		if d.Username != "" {
			activeUsernames[d.Username] = true
		}
	}
	server.mu.RUnlock()

	// Add offline registered devices from persistent config
	if includeOffline {
		server.persistMu.RLock()
		for username, cfg := range server.persistentData.DeviceConfigs {
			// Skip if already in active devices or if it's an IP-keyed entry
			if activeUsernames[username] || cfg.Username == "" || cfg.Username != username {
				continue
			}

			// Get proxy string
			var upstreamProxy string
			server.poolMu.Lock()
			if cfg.ProxyIndex >= 0 && cfg.ProxyIndex < len(server.proxyPool) {
				upstreamProxy = server.proxyPool[cfg.ProxyIndex]
			}
			server.poolMu.Unlock()

			offlineDevice := &Device{
				ID:            fmt.Sprintf("device-%s", username),
				IP:            cfg.LastIP,
				Username:      username,
				Name:          username,
				CustomName:    cfg.CustomName,
				Group:         cfg.Group,
				Notes:         cfg.Notes,
				UpstreamProxy: upstreamProxy,
				Status:        "offline",
			}
			devices = append(devices, DeviceWithStatus{Device: offlineDevice, Online: false})
		}
		server.persistMu.RUnlock()
	}

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

// ============================================================================
// APP API (public endpoints for mobile app)
// ============================================================================

type AppProxyInfo struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
}

// handleAppProxiesAPI returns list of proxy names for the mobile app (no auth required)
func handleAppProxiesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	username := strings.TrimSpace(r.Header.Get("X-App-Username"))
	if username == "" {
		username = strings.TrimSpace(r.URL.Query().Get("username"))
	}

	if !ensureAppAuth(w, r, username) {
		return
	}

	server.poolMu.Lock()
	defer server.poolMu.Unlock()

	proxies := make([]AppProxyInfo, 0)
	for i := range server.proxyPool {
		proxies = append(proxies, AppProxyInfo{
			Index: i,
			Name:  server.getProxyName(i),
		})
	}
	json.NewEncoder(w).Encode(proxies)
}

type AppRegisterRequest struct {
	Username   string `json:"username"`
	ProxyIndex int    `json:"proxy_index"`
	Password   string `json:"password,omitempty"`   // Required for registration
	Supervisor string `json:"supervisor,omitempty"` // Supervisor name for change-proxy logging
}

// Registration password - devices must provide this to register
const registrationPassword = "Drnda123"

type AppAuthRequest struct {
	Username string `json:"username"`
}

type AppAuthResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Token      string `json:"token,omitempty"`
	Username   string `json:"username,omitempty"`
	ProxyIndex int    `json:"proxy_index,omitempty"`
	ProxyName  string `json:"proxy_name,omitempty"`
}

type AppRegisterResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Username   string `json:"username"`
	ProxyName  string `json:"proxy_name"`
	ProxyIndex int    `json:"proxy_index,omitempty"`
	Token      string `json:"token,omitempty"`
}

// ensureAppAuth enforces the optional pre-authentication gate for app calls
func ensureAppAuth(w http.ResponseWriter, r *http.Request, username string) bool {
	if !server.authRequired {
		return true
	}

	if r.Method == http.MethodOptions {
		return true
	}

	if strings.TrimSpace(username) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Authentication required: send username"})
		return false
	}

	token := strings.TrimSpace(r.Header.Get("X-App-Token"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Authentication required"})
		return false
	}

	if _, ok := server.validateAppSession(token, username); !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Session expired, please authenticate"})
		return false
	}

	return true
}

// handleAppRegisterAPI registers a device with username and proxy selection (password protected)
func handleAppRegisterAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-App-Token, X-App-Username")
		return
	}

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Method not allowed"})
		return
	}

	var req AppRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Invalid request"})
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Username required"})
		return
	}

	// Validate registration password
	if req.Password != registrationPassword {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		log.Printf("⚠️ App: Registration denied - invalid password for username '%s' (IP: %s)\n", username, clientIP)
		server.addLog("warning", fmt.Sprintf("App: Registration denied - invalid password for '%s' (IP: %s)", username, clientIP))
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Invalid registration password"})
		return
	}

	if !ensureAppAuth(w, r, username) {
		return
	}

	// Validate proxy index
	server.poolMu.Lock()
	if req.ProxyIndex < 0 || req.ProxyIndex >= len(server.proxyPool) {
		server.poolMu.Unlock()
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Invalid proxy selection"})
		return
	}
	selectedProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	proxyName := fmt.Sprintf("SG%d", req.ProxyIndex+1)

	// Get client IP
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Check if device already exists with this username
	server.mu.Lock()
	existingDevice := server.findDeviceByUsername(username)
	if existingDevice != nil {
		// Update existing device
		existingDevice.IP = clientIP
		existingDevice.UpstreamProxy = selectedProxy
		existingDevice.LastSeen = time.Now()
		server.mu.Unlock()
		go server.saveDeviceConfig(existingDevice)
		log.Printf("📱 App: Device '%s' updated -> %s\n", username, proxyName)
	} else {
		// Create new device
		device := &Device{
			ID:            fmt.Sprintf("device-%s", username),
			IP:            clientIP,
			Username:      username,
			Name:          username,
			Group:         "Default",
			UpstreamProxy: selectedProxy,
			Status:        "active",
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
		}
		server.devices[username] = device
		server.mu.Unlock()
		go server.saveDeviceConfig(device)
		log.Printf("📱 App: New device '%s' registered -> %s\n", username, proxyName)
		server.addLog("info", fmt.Sprintf("App: Device '%s' registered with %s", username, proxyName))
	}

	json.NewEncoder(w).Encode(AppRegisterResponse{
		Success:    true,
		Message:    "Device registered",
		Username:   username,
		ProxyName:  proxyName,
		ProxyIndex: req.ProxyIndex,
	})
}

// handleAppChangeProxyAPI updates a device's proxy selection (only for existing registered devices)
func handleAppChangeProxyAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-App-Token, X-App-Username")
		return
	}

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Method not allowed"})
		return
	}

	var req AppRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Invalid request"})
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Username required"})
		return
	}

	server.poolMu.Lock()
	if req.ProxyIndex < 0 || req.ProxyIndex >= len(server.proxyPool) {
		server.poolMu.Unlock()
		json.NewEncoder(w).Encode(AppRegisterResponse{Success: false, Message: "Invalid proxy selection"})
		return
	}
	selectedProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	proxyName := fmt.Sprintf("SG%d", req.ProxyIndex+1)
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Only allow changing proxy for existing registered devices
	server.mu.Lock()
	device := server.findDeviceByUsername(username)
	if device == nil {
		server.mu.Unlock()
		log.Printf("⚠️ App: Change proxy failed - username '%s' not registered\n", username)
		server.addLog("warning", fmt.Sprintf("App: Change proxy denied - username '%s' not registered (IP: %s)", username, clientIP))
		json.NewEncoder(w).Encode(AppRegisterResponse{
			Success: false,
			Message: "Username not registered. Please register first using the Register button.",
		})
		return
	}

	// Log the proxy change with old and new proxy info
	oldProxyIndex := server.getProxyIndexByString(device.UpstreamProxy)
	oldProxyName := fmt.Sprintf("SG%d", oldProxyIndex+1)

	device.IP = clientIP
	device.UpstreamProxy = selectedProxy
	device.LastSeen = time.Now()
	server.mu.Unlock()

	go server.saveDeviceConfig(device)

	// Log proxy change with supervisor name if provided
	supervisorInfo := ""
	if req.Supervisor != "" {
		supervisorInfo = fmt.Sprintf(" by Supervisor %s", req.Supervisor)
	}
	log.Printf("📱 App: Device '%s' proxy changed: %s -> %s%s (IP: %s)\n", username, oldProxyName, proxyName, supervisorInfo, clientIP)
	server.addLog("info", fmt.Sprintf("App: Device '%s' proxy changed: %s -> %s%s (IP: %s)", username, oldProxyName, proxyName, supervisorInfo, clientIP))

	json.NewEncoder(w).Encode(AppRegisterResponse{
		Success:    true,
		Message:    "Proxy updated",
		Username:   username,
		ProxyName:  proxyName,
		ProxyIndex: req.ProxyIndex,
	})
}

// handleAppAuthenticateAPI issues a short-lived session token keyed by username
func handleAppAuthenticateAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-App-Token, X-App-Username")
		return
	}

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(AppAuthResponse{Success: false, Message: "Method not allowed"})
		return
	}

	var req AppAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(AppAuthResponse{Success: false, Message: "Invalid request"})
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		json.NewEncoder(w).Encode(AppAuthResponse{Success: false, Message: "Username required"})
		return
	}

	server.poolMu.Lock()
	if len(server.proxyPool) == 0 {
		server.poolMu.Unlock()
		json.NewEncoder(w).Encode(AppAuthResponse{Success: false, Message: "No upstream proxies configured"})
		return
	}
	server.poolMu.Unlock()

	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	server.persistMu.RLock()
	cfg, hasCfg := server.persistentData.DeviceConfigs[username]
	server.persistMu.RUnlock()

	proxyIndex := 0
	if hasCfg && cfg.ProxyIndex >= 0 {
		proxyIndex = cfg.ProxyIndex
	}

	server.poolMu.Lock()
	if proxyIndex >= len(server.proxyPool) {
		proxyIndex = 0
	}
	selectedProxy := server.proxyPool[proxyIndex]
	proxyName := fmt.Sprintf("SG%d", proxyIndex+1)
	server.poolMu.Unlock()

	server.mu.Lock()
	device := server.findDeviceByUsername(username)
	if device == nil {
		device = &Device{
			ID:            fmt.Sprintf("device-%s", username),
			IP:            clientIP,
			Username:      username,
			Name:          username,
			Group:         "Default",
			UpstreamProxy: selectedProxy,
			Status:        "active",
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
		}
		server.devices[username] = device
	} else {
		device.IP = clientIP
		if device.UpstreamProxy == "" {
			device.UpstreamProxy = selectedProxy
		}
		device.LastSeen = time.Now()
	}
	server.mu.Unlock()

	go server.saveDeviceConfig(device)
	session := server.createAppSession(username)

	json.NewEncoder(w).Encode(AppAuthResponse{
		Success:    true,
		Message:    "Authenticated",
		Token:      session.Token,
		Username:   username,
		ProxyIndex: proxyIndex,
		ProxyName:  proxyName,
	})
}

// fetchPublicIPThroughProxy fetches the public IP by making a request through the SOCKS5 proxy
func fetchPublicIPThroughProxy(proxyStr string) (string, error) {
	if proxyStr == "" {
		return "", fmt.Errorf("no proxy configured")
	}

	parts := strings.Split(proxyStr, ":")
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid proxy format")
	}

	auth := &proxy.Auth{User: parts[2], Password: strings.Join(parts[3:], ":")}
	dialer, err := proxy.SOCKS5("tcp", parts[0]+":"+parts[1], auth, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return "", fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	// Create HTTP client with SOCKS5 transport
	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// Try multiple IP check services
	ipServices := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
	}

	for _, service := range ipServices {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" && net.ParseIP(ip) != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("failed to fetch public IP from all services")
}

// fetchPublicIPAndGeoThroughProxy fetches the public IP and geolocation through the SOCKS5 proxy
func fetchPublicIPAndGeoThroughProxy(proxyStr string) (ip, country, city string, err error) {
	if proxyStr == "" {
		return "", "", "", fmt.Errorf("no proxy configured")
	}

	parts := strings.Split(proxyStr, ":")
	if len(parts) < 4 {
		return "", "", "", fmt.Errorf("invalid proxy format")
	}

	auth := &proxy.Auth{User: parts[2], Password: strings.Join(parts[3:], ":")}
	dialer, err := proxy.SOCKS5("tcp", parts[0]+":"+parts[1], auth, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	transport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	// Try ip-api.com first for IP + geolocation in one request
	resp, err := client.Get("http://ip-api.com/json/?fields=status,message,country,city,query")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			var result struct {
				Status  string `json:"status"`
				Message string `json:"message"`
				Country string `json:"country"`
				City    string `json:"city"`
				Query   string `json:"query"` // This is the IP
			}
			if json.Unmarshal(body, &result) == nil && result.Status == "success" {
				return result.Query, result.Country, result.City, nil
			}
		}
	}

	// Fallback: get IP from simple services, then lookup geo separately
	ipServices := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
	}

	for _, service := range ipServices {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		fetchedIP := strings.TrimSpace(string(body))
		if fetchedIP != "" && net.ParseIP(fetchedIP) != nil {
			// Try to get geolocation for this IP
			geoCountry, geoCity := fetchGeoForIP(client, fetchedIP)
			return fetchedIP, geoCountry, geoCity, nil
		}
	}

	return "", "", "", fmt.Errorf("failed to fetch public IP from all services")
}

// fetchGeoForIP looks up geolocation for an IP address
func fetchGeoForIP(client *http.Client, ip string) (country, city string) {
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city", ip))
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}

	var result struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if json.Unmarshal(body, &result) == nil && result.Status == "success" {
		return result.Country, result.City
	}
	return "", ""
}

// handleAppWhoAmI reports the public IP as seen through the device's assigned proxy
func handleAppWhoAmI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-App-Token, X-App-Username")
		return
	}

	username := strings.TrimSpace(r.Header.Get("X-App-Username"))
	if username == "" {
		username = strings.TrimSpace(r.URL.Query().Get("username"))
	}

	if !ensureAppAuth(w, r, username) {
		return
	}

	// Look up the device to get its assigned proxy
	server.mu.RLock()
	device := server.findDeviceByUsername(username)
	var proxyStr string
	if device != nil {
		proxyStr = device.UpstreamProxy
	}
	server.mu.RUnlock()

	if proxyStr == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":      "",
			"country": "",
			"error":   "No proxy assigned - please register first",
		})
		return
	}

	// Fetch public IP and geolocation through the proxy
	publicIP, country, city, err := fetchPublicIPAndGeoThroughProxy(proxyStr)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":      "",
			"country": "",
			"city":    "",
			"error":   fmt.Sprintf("Failed to check IP: %v", err),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"ip":      publicIP,
		"country": country,
		"city":    city,
	})
}

// extractIPFromProxyString extracts the IP address embedded in a proxy string
// Format: host:port:username:password where username may contain ip-X.X.X.X
func extractIPFromProxyString(proxyStr string) string {
	// Look for pattern like ip-XXX.XXX.XXX.XXX in the proxy string
	re := regexp.MustCompile(`ip-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	matches := re.FindStringSubmatch(proxyStr)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// handleAppCheckIP checks which proxy an IP belongs to
func handleAppCheckIP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		return
	}

	// Get IP from query param or JSON body
	ipToCheck := r.URL.Query().Get("ip")
	if ipToCheck == "" && r.Method == http.MethodPost {
		var req struct {
			IP string `json:"ip"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		ipToCheck = req.IP
	}

	if ipToCheck == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    false,
			"message":    "IP address required",
			"proxy_name": "",
			"matched":    false,
		})
		return
	}

	// Search through proxies to find one with matching IP
	server.poolMu.Lock()
	var matchedIndex int = -1
	for i, proxy := range server.proxyPool {
		proxyIP := extractIPFromProxyString(proxy)
		if proxyIP == ipToCheck {
			matchedIndex = i
			break
		}
	}
	server.poolMu.Unlock()

	if matchedIndex >= 0 {
		proxyName := fmt.Sprintf("SG%d", matchedIndex+1)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"matched":     true,
			"proxy_name":  proxyName,
			"proxy_index": matchedIndex,
			"message":     fmt.Sprintf("IP belongs to %s", proxyName),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"matched":    false,
			"proxy_name": "",
			"message":    "WARNING: IP does not match any configured proxy!",
		})
	}
}

// handleAppValidatePassword validates admin or supervisor password from the Android app
func handleAppValidatePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		return
	}

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"message": "Method not allowed",
		})
		return
	}

	var req struct {
		Password string `json:"password"`
		Type     string `json:"type"` // "admin" or "supervisor"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   false,
			"message": "Invalid request",
		})
		return
	}

	server.persistMu.RLock()
	defer server.persistMu.RUnlock()

	if req.Type == "admin" {
		// Validate admin password
		if req.Password == server.persistentData.AdminPassword {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid": true,
				"name":  "Admin",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid":   false,
				"message": "Invalid admin password",
			})
		}
		return
	}

	// Validate supervisor password
	for _, s := range server.persistentData.Supervisors {
		if s.Password == req.Password {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid": true,
				"name":  s.Name,
			})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":   false,
		"message": "Invalid supervisor password",
	})
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
		server.proxyHealth[newIndex] = &ProxyHealth{Index: newIndex}
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
	// Find device by IP (the UI sends IP as device identifier)
	server.mu.Lock()
	device := server.findDeviceByIP(req.DeviceIP)
	server.mu.Unlock()
	if device == nil {
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

	go server.saveDeviceConfig(device)

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
	// Find device by IP (the UI sends IP as device identifier)
	server.mu.Lock()
	device := server.findDeviceByIP(req.DeviceIP)
	if device == nil {
		server.mu.Unlock()
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	// Get old key for re-keying if username changes
	oldKey := device.Username

	// Update device fields
	device.CustomName = req.CustomName
	device.Group = req.Group
	device.Notes = req.Notes

	// Handle username change
	newUsername := strings.TrimSpace(req.Username)
	usernameChanged := device.Username != newUsername

	if usernameChanged {
		// Remove device from old key
		delete(server.devices, oldKey)

		// Update username and name
		device.Username = newUsername
		if newUsername != "" {
			device.Name = newUsername
		} else {
			device.Name = fmt.Sprintf("Anonymous-%s", device.IP)
		}

		// Add device with new key
		newKey := newUsername
		if newKey == "" {
			newKey = device.IP
		}
		server.devices[newKey] = device
	}
	server.mu.Unlock()

	// Update persistent data for username only
	server.persistMu.Lock()
	if usernameChanged && oldKey != "" {
		delete(server.persistentData.DeviceConfigs, oldKey)
	}
	server.persistMu.Unlock()

	go server.saveDeviceConfig(device)
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
		device := server.findDeviceByIP(ip)
		if device != nil {
			device.UpstreamProxy = newProxy
			updated++
			server.mu.Unlock()
			go server.saveDeviceConfig(device)
		} else {
			server.mu.Unlock()
		}
	}
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
	// Also update in-memory devices
	server.mu.Lock()
	for _, device := range server.devices {
		if device.Group == req.GroupName {
			device.Group = "Default"
		}
	}
	server.mu.Unlock()
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
		Index:       newIndex,
		ProxyString: req.ProxyString,
		IPAddress:   extractProxyIP(req.ProxyString),
		Status:      "unknown",
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
	// Check if any devices are using this proxy
	deletedProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()

	server.mu.RLock()
	devicesUsingProxy := 0
	for _, device := range server.devices {
		if device.UpstreamProxy == deletedProxy {
			devicesUsingProxy++
		}
	}
	server.mu.RUnlock()

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

func handleDeleteDeviceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deleteDeviceRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.DeviceIP == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Find device by IP to get the proper key (Username or IP)
	server.mu.Lock()
	device := server.findDeviceByIP(req.DeviceIP)
	exists := device != nil
	var deviceKey string
	if device != nil {
		if device.Username != "" {
			deviceKey = device.Username
		} else {
			deviceKey = device.IP
		}
		delete(server.devices, deviceKey)
	}
	server.mu.Unlock()

	// Delete from persistent data by Username to ensure cleanup
	server.persistMu.Lock()
	if device != nil && device.Username != "" {
		delete(server.persistentData.DeviceConfigs, device.Username)
	}
	server.persistMu.Unlock()

	go server.savePersistentData()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "deleted": exists})
}

func saveProxyPool() {
	server.poolMu.Lock()
	defer server.poolMu.Unlock()
	var lines []string
	for _, proxy := range server.proxyPool {
		lines = append(lines, proxy)
	}
	content := strings.Join(lines, "\n")
	os.WriteFile("proxies.txt", []byte(content), 0644)
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

	server.mu.RLock()
	var totalBytesIn, totalBytesOut, totalRequests int64
	activeDevices := 0
	for _, d := range server.devices {
		totalBytesIn += d.BytesIn
		totalBytesOut += d.BytesOut
		totalRequests += d.RequestCount
		if time.Since(d.LastSeen) < 5*time.Minute {
			activeDevices++
		}
	}
	totalDevices := len(server.devices)
	server.mu.RUnlock()

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

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, mins, secs)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

func handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	logs := server.getLogs(100)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
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
const loginPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Login</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-container{background:rgba(255,255,255,0.95);padding:40px;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.3);width:100%;max-width:400px}.logo{text-align:center;margin-bottom:30px}.logo h1{color:#667eea;font-size:2em;margin-bottom:5px}.logo p{color:#666;font-size:0.9em}.form-group{margin-bottom:20px}.form-group label{display:block;font-weight:600;color:#333;margin-bottom:8px}.form-group input{width:100%;padding:14px 16px;border:2px solid #e0e0e0;border-radius:10px;font-size:1em}.form-group input:focus{outline:none;border-color:#667eea}.login-btn{width:100%;padding:14px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer}.login-btn:hover{opacity:0.9}.login-btn:disabled{opacity:0.5;cursor:not-allowed}.error-msg{background:#ffebee;color:#c62828;padding:12px;border-radius:8px;margin-bottom:20px;display:none}.error-msg.show{display:block}</style></head>
<body><div class="login-container"><div class="logo"><h1>🌐 Lumier Dynamics</h1><p>Enterprise Proxy Management v3.0</p></div><div class="error-msg" id="errorMsg"></div><form onsubmit="return handleLogin(event)"><div class="form-group"><label>Username</label><input type="text" id="username" placeholder="Enter username" required autofocus></div><div class="form-group"><label>Password</label><input type="password" id="password" placeholder="Enter password" required></div><button type="submit" class="login-btn" id="loginBtn">Sign In</button></form></div>
<script>async function handleLogin(e){e.preventDefault();const btn=document.getElementById('loginBtn'),err=document.getElementById('errorMsg');btn.disabled=true;btn.textContent='Signing in...';err.classList.remove('show');try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});if(r.ok)window.location.href='/dashboard';else{err.textContent='Invalid username or password';err.classList.add('show');btn.disabled=false;btn.textContent='Sign In';}}catch(e){err.textContent='Connection error';err.classList.add('show');btn.disabled=false;btn.textContent='Sign In';}return false;}</script></body></html>`

const navHTML = `<nav style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:15px 30px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px"><div style="display:flex;align-items:center;gap:10px"><span style="font-size:1.5em">🌐</span><span style="color:white;font-size:1.3em;font-weight:bold">Lumier Dynamics</span></div><div style="display:flex;gap:5px;flex-wrap:wrap"><a href="/dashboard" class="nav-link" id="nav-dashboard">📱 Devices</a><a href="/health" class="nav-link" id="nav-health">💚 Health</a><a href="/analytics" class="nav-link" id="nav-analytics">📊 Analytics</a><a href="/monitoring" class="nav-link" id="nav-monitoring">🖥️ Monitor</a><a href="/settings" class="nav-link" id="nav-settings">⚙️ Settings</a></div><div style="display:flex;align-items:center;gap:15px;color:white"><span id="currentUser">Admin</span><button onclick="logout()" style="background:rgba(255,255,255,0.2);color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:500">Logout</button></div></nav>`

const baseStyles = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;min-height:100vh}.nav-link{color:rgba(255,255,255,0.85);text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:500}.nav-link:hover,.nav-link.active{background:rgba(255,255,255,0.2);color:white}.container{max-width:1600px;margin:0 auto;padding:25px}.page-header{margin-bottom:25px}.page-header h1{color:#333;font-size:1.8em;margin-bottom:5px}.page-header p{color:#666}.card{background:white;border-radius:12px;padding:25px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}.card h2{color:#333;font-size:1.3em;margin-bottom:15px;padding-bottom:10px;border-bottom:2px solid #f0f0f0}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:20px;margin-bottom:25px}.stat-card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.05);text-align:center;cursor:pointer;transition:transform 0.2s}.stat-card:hover{transform:translateY(-3px)}.stat-value{font-size:2.2em;font-weight:bold;color:#667eea;margin-bottom:5px}.stat-label{color:#666;font-size:0.85em;text-transform:uppercase;letter-spacing:1px}.btn{padding:10px 18px;border:none;border-radius:8px;cursor:pointer;font-size:0.95em;font-weight:600;transition:all 0.2s}.btn-primary{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white}.btn-primary:hover{opacity:0.9}.btn-secondary{background:#f5f5f5;color:#333;border:2px solid #e0e0e0}.btn-secondary:hover{background:#e8e8e8}.toast{position:fixed;bottom:30px;right:30px;background:#333;color:white;padding:15px 25px;border-radius:10px;z-index:1001;animation:slideIn 0.3s ease}.toast.success{background:#4caf50}.toast.error{background:#f44336}@keyframes slideIn{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}.loading{text-align:center;padding:40px;color:#666}`

const baseJS = `async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/';}function showToast(msg,type=''){const t=document.createElement('div');t.className='toast '+type;t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}function formatBytes(b){if(!b)return"0 B";const k=1024,s=["B","KB","MB","GB","TB"];const i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+" "+s[i];}function formatNumber(n){if(!n)return"0";if(n>=1e6)return(n/1e6).toFixed(1)+"M";if(n>=1e3)return(n/1e3).toFixed(1)+"K";return n.toString();}fetch('/api/session-check').then(r=>r.json()).then(d=>{if(!d.valid)window.location.href='/';else if(document.getElementById('currentUser'))document.getElementById('currentUser').textContent=d.username;});`

const dashboardPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Devices</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.toolbar{background:white;padding:15px 20px;border-radius:12px;margin-bottom:20px;box-shadow:0 2px 10px rgba(0,0,0,0.05);display:flex;flex-wrap:wrap;gap:15px;align-items:center}.search-box{flex:1;min-width:200px;position:relative}.search-box input{width:100%;padding:10px 15px 10px 40px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.search-box input:focus{outline:none;border-color:#667eea}.search-box::before{content:"🔍";position:absolute;left:12px;top:50%;transform:translateY(-50%)}.filter-group{display:flex;gap:10px;align-items:center}.filter-group label{font-weight:600;color:#555;font-size:0.9em}.filter-group select{padding:8px 12px;border:2px solid #e0e0e0;border-radius:8px}.device-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}.device-card{background:white;border:2px solid #e8e8e8;border-radius:12px;padding:18px;transition:all 0.2s;position:relative}.device-card:hover{border-color:#667eea;box-shadow:0 5px 20px rgba(102,126,234,0.15)}.device-card.selected{border-color:#667eea;background:#f8f9ff}.device-checkbox{position:absolute;top:15px;right:15px;width:20px;height:20px;cursor:pointer}.device-name{font-size:1.15em;font-weight:bold;color:#333;margin-bottom:5px;padding-right:30px;cursor:pointer}.device-name:hover{color:#667eea}.device-group{display:inline-block;background:#e8f5e9;color:#2e7d32;padding:3px 10px;border-radius:12px;font-size:0.8em;font-weight:600;margin-bottom:10px}.device-info{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:0.9em}.info-row{display:flex;justify-content:space-between;padding:3px 0}.info-label{color:#888}.status-badge{padding:3px 10px;border-radius:12px;font-size:0.85em;font-weight:600}.status-active{background:#e8f5e9;color:#2e7d32}.status-inactive{background:#ffebee;color:#c62828}.proxy-selector{margin-top:12px;padding-top:12px;border-top:1px solid #eee;grid-column:1/-1}.proxy-selector label{display:block;font-size:0.85em;color:#666;margin-bottom:6px}.proxy-selector select{width:100%;padding:8px;border:2px solid #e0e0e0;border-radius:6px;margin-bottom:8px}.current-proxy{font-size:0.85em;color:#667eea;font-weight:600}.change-btn{width:100%;padding:8px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600}.change-btn:hover{opacity:0.9}.pagination{display:flex;justify-content:center;align-items:center;gap:10px;margin-top:20px}.pagination button{padding:8px 16px;border:2px solid #e0e0e0;background:white;border-radius:6px;cursor:pointer;font-weight:600}.pagination button:hover:not(:disabled){border-color:#667eea;color:#667eea}.pagination button:disabled{opacity:0.5;cursor:not-allowed}.bulk-actions{display:flex;gap:10px;align-items:center}.selected-count{background:#667eea;color:white;padding:5px 12px;border-radius:20px;font-size:0.85em;font-weight:600}.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:1000}.modal{background:white;border-radius:15px;padding:25px;width:90%;max-width:450px}.modal h3{margin-bottom:20px;color:#333}.modal-field{margin-bottom:15px}.modal-field label{display:block;font-weight:600;color:#555;margin-bottom:5px}.modal-field input,.modal-field select,.modal-field textarea{width:100%;padding:10px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.modal-field textarea{resize:vertical;min-height:80px}.modal-buttons{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.setup-box{background:#e3f2fd;padding:12px 20px;border-radius:10px;margin-bottom:20px;border-left:4px solid #2196F3}.setup-box code{background:#fff;padding:2px 6px;border-radius:4px;font-family:monospace;color:#d32f2f;font-weight:bold}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>📱 Device Management</h1><p>Monitor and manage all connected devices</p></div><div class="setup-box">📱 Phone Setup: Wi-Fi → Proxy Manual → Host: <code id="serverIP">...</code> Port: <code>8888</code> Username: <code>your-device-name</code> (password can be anything)</div><div class="stats-grid"><div class="stat-card" onclick="filterByStatus('all')"><div class="stat-value" id="totalDevices">-</div><div class="stat-label">Total</div></div><div class="stat-card" onclick="filterByStatus('active')"><div class="stat-value" id="activeDevices">-</div><div class="stat-label">Active</div></div><div class="stat-card" onclick="filterByStatus('inactive')"><div class="stat-value" id="inactiveDevices">-</div><div class="stat-label">Inactive</div></div><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Proxies</div></div><div class="stat-card"><div class="stat-value" id="totalRequests">-</div><div class="stat-label">Requests</div></div></div><div class="toolbar"><div class="search-box"><input type="text" id="searchInput" placeholder="Search devices..." oninput="applyFilters()"></div><div class="filter-group"><label>Group:</label><select id="groupFilter" onchange="applyFilters()"><option value="">All</option></select></div><div class="filter-group"><label>Sort:</label><select id="sortBy" onchange="applyFilters()"><option value="name">Name</option><option value="ip">IP</option><option value="lastSeen">Last Seen</option><option value="requests">Requests</option></select></div><div class="filter-group"><label><input type="checkbox" id="showOffline" onchange="loadData()" style="margin-right:5px">Show Offline</label></div><button class="btn btn-secondary" onclick="loadData()">🔄 Refresh</button><button class="btn btn-secondary" onclick="location.href='/api/export'">📤 Export</button><div class="bulk-actions" id="bulkActions" style="display:none"><span class="selected-count"><span id="selectedCount">0</span> selected</span><select id="bulkProxySelect"></select><button class="btn btn-primary" onclick="bulkChangeProxy()">Change</button><button class="btn btn-secondary" onclick="clearSelection()">Clear</button></div></div><div class="card"><h2>Connected Devices</h2><div id="devicesList" class="device-grid"><div class="loading">Loading...</div></div><div class="pagination" id="pagination"></div></div></div><div class="modal-overlay" id="editModal" style="display:none"><div class="modal"><h3>✏️ Edit Device</h3><div class="modal-field"><label>Username (Device ID)</label><input type="text" id="editUsername" placeholder="e.g., phone1, samsung-s23"></div><div class="modal-field"><label>Custom Name</label><input type="text" id="editName" placeholder="e.g., Samsung S23"></div><div class="modal-field"><label>Group</label><select id="editGroup"></select></div><div class="modal-field"><label>Notes</label><textarea id="editNotes" placeholder="Optional notes..."></textarea></div><input type="hidden" id="editDeviceIP"><div class="modal-buttons"><button class="btn btn-secondary" onclick="closeEditModal()">Cancel</button><button class="btn btn-primary" onclick="saveDeviceEdit()">Save</button></div></div></div><script>` + baseJS + `document.getElementById('nav-dashboard').classList.add('active');fetch("/api/server-ip").then(r=>r.text()).then(ip=>document.getElementById("serverIP").textContent=ip);let allDevices=[],allProxies=[],allGroups=[],filteredDevices=[],selectedDevices=new Set(),currentPage=1,statusFilter='all';const PER_PAGE=20;function getDisplayName(d){return d.custom_name||d.name||'Unknown';}function isActive(d){return(Date.now()-new Date(d.last_seen))/60000<5;}function proxyLabel(p,i){let ip=p.user&&p.user.includes('ip-')?p.user.split('ip-')[1]:'unknown';return'#'+(i+1)+' – '+ip;}function filterByStatus(s){statusFilter=s;applyFilters();}function applyFilters(){const search=document.getElementById('searchInput').value.toLowerCase();const group=document.getElementById('groupFilter').value;const sort=document.getElementById('sortBy').value;filteredDevices=allDevices.filter(d=>{if(statusFilter==='active'&&!isActive(d))return false;if(statusFilter==='inactive'&&isActive(d))return false;if(group&&d.group!==group)return false;if(search&&!getDisplayName(d).toLowerCase().includes(search)&&!d.ip.includes(search)&&!(d.username&&d.username.toLowerCase().includes(search)))return false;return true;});filteredDevices.sort((a,b)=>{if(sort==='name')return getDisplayName(a).localeCompare(getDisplayName(b));if(sort==='ip')return a.ip.localeCompare(b.ip);if(sort==='lastSeen')return new Date(b.last_seen)-new Date(a.last_seen);if(sort==='requests')return(b.request_count||0)-(a.request_count||0);return 0;});currentPage=1;renderDevices();}function renderDevices(){const c=document.getElementById('devicesList');if(!filteredDevices.length){c.innerHTML='<div class="loading">No devices found</div>';document.getElementById('pagination').innerHTML='';return;}const pages=Math.ceil(filteredDevices.length/PER_PAGE);const start=(currentPage-1)*PER_PAGE;const pageDevices=filteredDevices.slice(start,start+PER_PAGE);c.innerHTML=pageDevices.map(d=>{const mins=Math.floor((Date.now()-new Date(d.last_seen))/60000);const active=mins<5;const sel=selectedDevices.has(d.ip);const pIdx=allProxies.findIndex(p=>p.full===d.upstream_proxy);const opts=allProxies.map((p,i)=>'<option value="'+i+'" '+(i===pIdx?'selected':'')+'>'+proxyLabel(p,i)+'</option>').join('');const pLabel=pIdx>=0?proxyLabel(allProxies[pIdx],pIdx):'N/A';return'<div class="device-card '+(sel?'selected':'')+'"><input type="checkbox" class="device-checkbox" '+(sel?'checked':'')+' onchange="toggleSel(\''+d.ip+'\',this.checked)"><div class="device-name" onclick="openEditModal(\''+d.ip+'\')">'+escapeHtml(getDisplayName(d))+' ✏️</div><div class="device-group">'+escapeHtml(d.group||'Default')+'</div><div class="device-info"><div class="info-row"><span class="info-label">Status:</span><span class="status-badge '+(active?'status-active':'status-inactive')+'">'+(active?'● Active':'○ Inactive')+'</span></div><div class="info-row"><span class="info-label">IP:</span><span><strong>'+d.ip+'</strong></span></div><div class="info-row"><span class="info-label">User:</span><span style="font-weight:600;color:#667eea">'+(d.username||'<em>anonymous</em>')+'</span></div><div class="info-row"><span class="info-label">Requests:</span><span>'+formatNumber(d.request_count)+'</span></div><div class="info-row"><span class="info-label">Errors:</span><span style="color:'+(d.error_count>0?'#c62828':'#666')+'">'+(d.error_count||0)+'</span></div><div class="info-row"><span class="info-label">Data:</span><span>↓'+formatBytes(d.bytes_in)+'</span></div><div class="info-row"><span class="info-label">Last seen:</span><span>'+(mins<1?'Now':mins+' min')+'</span></div><div class="proxy-selector"><label>Proxy: <span class="current-proxy">'+pLabel+'</span></label><select id="proxy-'+d.ip+'">'+opts+'</select><button class="change-btn" onclick="changeProxy(\''+d.ip+'\')">Change Proxy</button><button class="change-btn" style="background:#ef5350;margin-top:8px" onclick="deleteDevice(\''+d.ip+'\',\''+escapeHtml(getDisplayName(d))+'\')">Delete Device</button></div></div></div>';}).join('');const pag=document.getElementById('pagination');pag.innerHTML=pages>1?'<button onclick="goPage('+(currentPage-1)+')" '+(currentPage===1?'disabled':'')+'>← Prev</button><span>Page '+currentPage+' of '+pages+'</span><button onclick="goPage('+(currentPage+1)+')" '+(currentPage===pages?'disabled':'')+'>Next →</button>':'<span>'+filteredDevices.length+' devices</span>';updateBulk();}function goPage(p){const pages=Math.ceil(filteredDevices.length/PER_PAGE);if(p>=1&&p<=pages){currentPage=p;renderDevices();}}function escapeHtml(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}function toggleSel(ip,checked){checked?selectedDevices.add(ip):selectedDevices.delete(ip);updateBulk();renderDevices();}function clearSelection(){selectedDevices.clear();updateBulk();renderDevices();}function updateBulk(){const b=document.getElementById('bulkActions');b.style.display=selectedDevices.size>0?'flex':'none';document.getElementById('selectedCount').textContent=selectedDevices.size;}function changeProxy(ip){const idx=parseInt(document.getElementById('proxy-'+ip).value);fetch('/api/change-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:ip,proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxy changed','success');loadData();}});}function bulkChangeProxy(){const idx=parseInt(document.getElementById('bulkProxySelect').value);fetch('/api/bulk-change-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ips:Array.from(selectedDevices),proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.ok){showToast(d.updated+' devices updated','success');selectedDevices.clear();loadData();}});}function openEditModal(ip){const d=allDevices.find(x=>x.ip===ip);if(!d)return;document.getElementById('editDeviceIP').value=ip;document.getElementById('editUsername').value=d.username||'';document.getElementById('editName').value=d.custom_name||'';document.getElementById('editNotes').value=d.notes||'';document.getElementById('editGroup').innerHTML=allGroups.map(g=>'<option value="'+g+'" '+(g===d.group?'selected':'')+'>'+g+'</option>').join('');document.getElementById('editModal').style.display='flex';}function closeEditModal(){document.getElementById('editModal').style.display='none';}function saveDeviceEdit(){const ip=document.getElementById('editDeviceIP').value;fetch('/api/update-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:ip,username:document.getElementById('editUsername').value,custom_name:document.getElementById('editName').value,group:document.getElementById('editGroup').value,notes:document.getElementById('editNotes').value})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Device updated','success');closeEditModal();loadData();}});}function loadGroups(){return fetch('/api/groups').then(r=>r.json()).then(g=>{allGroups=g;document.getElementById('groupFilter').innerHTML='<option value="">All</option>'+g.map(x=>'<option value="'+x+'">'+x+'</option>').join('');});}function loadData(){const showOffline=document.getElementById('showOffline').checked;Promise.all([fetch('/api/stats').then(r=>r.json()),fetch('/api/devices'+(showOffline?'?include_offline=true':'')).then(r=>r.json()),fetch('/api/proxies').then(r=>r.json()),loadGroups()]).then(([stats,devices,proxies])=>{document.getElementById('totalDevices').textContent=stats.total_devices||0;document.getElementById('activeDevices').textContent=stats.active_devices||0;document.getElementById('inactiveDevices').textContent=(stats.total_devices-stats.active_devices)||0;document.getElementById('totalProxies').textContent=stats.total_proxies||0;document.getElementById('totalRequests').textContent=formatNumber(stats.total_requests||0);allDevices=devices||[];allProxies=proxies||[];document.getElementById('bulkProxySelect').innerHTML=allProxies.map((p,i)=>'<option value="'+i+'">'+proxyLabel(p,i)+'</option>').join('');applyFilters();});}function deleteDevice(ip,name){if(!confirm('Delete device "'+name+'" ('+ip+')? This will remove all saved settings for this device.')){return;}fetch('/api/delete-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:ip})}).then(r=>{if(r.ok)return r.json();throw new Error('Failed');}).then(d=>{if(d.ok){showToast('Device deleted','success');loadData();}}).catch(()=>showToast('Failed to delete device','error'));}loadData();setInterval(loadData,15000);</script></body></html>`

const healthPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Proxy Health</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:20px}.proxy-card{background:white;border-radius:12px;padding:20px;box-shadow:0 2px 10px rgba(0,0,0,0.05);border-left:4px solid #ccc}.proxy-card.healthy{border-left-color:#4caf50}.proxy-card.degraded{border-left-color:#ff9800}.proxy-card.unhealthy{border-left-color:#f44336}.proxy-card.unknown{border-left-color:#9e9e9e}.proxy-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.proxy-name{font-size:1.2em;font-weight:bold;color:#333}.proxy-status{padding:5px 12px;border-radius:20px;font-size:0.85em;font-weight:600}.proxy-status.healthy{background:#e8f5e9;color:#2e7d32}.proxy-status.degraded{background:#fff3e0;color:#e65100}.proxy-status.unhealthy{background:#ffebee;color:#c62828}.proxy-status.unknown{background:#f5f5f5;color:#666}.proxy-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px}.proxy-stat{padding:10px;background:#f8f9fa;border-radius:8px}.proxy-stat-value{font-size:1.3em;font-weight:bold;color:#667eea}.proxy-stat-label{font-size:0.8em;color:#666;text-transform:uppercase}.progress-bar{height:8px;background:#e0e0e0;border-radius:4px;overflow:hidden;margin-top:10px}.progress-fill{height:100%;border-radius:4px;transition:width 0.3s}.progress-fill.good{background:#4caf50}.progress-fill.warning{background:#ff9800}.progress-fill.bad{background:#f44336}.last-error{margin-top:10px;padding:10px;background:#ffebee;border-radius:8px;font-size:0.85em;color:#c62828;word-break:break-all}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>💚 Proxy Health Monitor</h1><p>Real-time health status of all upstream proxies</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Total Proxies</div></div><div class="stat-card"><div class="stat-value" id="healthyProxies" style="color:#4caf50">-</div><div class="stat-label">Healthy</div></div><div class="stat-card"><div class="stat-value" id="degradedProxies" style="color:#ff9800">-</div><div class="stat-label">Degraded</div></div><div class="stat-card"><div class="stat-value" id="unhealthyProxies" style="color:#f44336">-</div><div class="stat-label">Unhealthy</div></div><div class="stat-card"><div class="stat-value" id="avgSuccessRate">-</div><div class="stat-label">Avg Success</div></div></div><div class="card"><h2>Proxy Status</h2><button class="btn btn-secondary" onclick="loadHealth()" style="float:right;margin-top:-45px">🔄 Refresh</button><div id="healthGrid" class="health-grid"><div class="loading">Loading...</div></div></div></div><script>` + baseJS + `document.getElementById('nav-health').classList.add('active');function loadHealth(){fetch('/api/proxy-health').then(r=>r.json()).then(data=>{let healthy=0,degraded=0,unhealthy=0,totalRate=0;data.forEach(p=>{if(p.status==='healthy')healthy++;else if(p.status==='degraded')degraded++;else if(p.status==='unhealthy')unhealthy++;totalRate+=p.success_rate||0;});document.getElementById('totalProxies').textContent=data.length;document.getElementById('healthyProxies').textContent=healthy;document.getElementById('degradedProxies').textContent=degraded;document.getElementById('unhealthyProxies').textContent=unhealthy;document.getElementById('avgSuccessRate').textContent=data.length?(totalRate/data.length).toFixed(1)+'%':'-';document.getElementById('healthGrid').innerHTML=data.map(p=>{const rate=p.success_rate||0;const rateClass=rate>=95?'good':rate>=80?'warning':'bad';return'<div class="proxy-card '+p.status+'"><div class="proxy-header"><span class="proxy-name">#'+(p.index+1)+' – '+p.ip_address+'</span><span class="proxy-status '+p.status+'">'+p.status.toUpperCase()+'</span></div><div class="proxy-stats"><div class="proxy-stat"><div class="proxy-stat-value">'+formatNumber(p.total_requests)+'</div><div class="proxy-stat-label">Requests</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+rate.toFixed(1)+'%</div><div class="proxy-stat-label">Success Rate</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+formatNumber(p.success_count)+'</div><div class="proxy-stat-label">Success</div></div><div class="proxy-stat"><div class="proxy-stat-value" style="color:#c62828">'+formatNumber(p.failure_count)+'</div><div class="proxy-stat-label">Failures</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+p.avg_response_time_ms+'ms</div><div class="proxy-stat-label">Avg Response</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+p.active_devices+'</div><div class="proxy-stat-label">Active Devices</div></div></div><div class="progress-bar"><div class="progress-fill '+rateClass+'" style="width:'+rate+'%"></div></div>'+(p.last_error?'<div class="last-error">Last error: '+p.last_error+'</div>':'')+'</div>';}).join('');});}loadHealth();setInterval(loadHealth,30000);</script></body></html>`

const analyticsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Analytics</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.chart-container{background:white;border-radius:12px;padding:25px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}.chart-container h2{margin-bottom:20px}.chart{width:100%;height:300px;position:relative}.chart-bars{display:flex;align-items:flex-end;height:250px;gap:4px;padding:0 10px;border-bottom:2px solid #e0e0e0}.chart-bar{flex:1;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:4px 4px 0 0;min-width:8px;position:relative;transition:height 0.3s}.chart-bar:hover{opacity:0.8}.chart-bar .tooltip{position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#333;color:white;padding:5px 10px;border-radius:4px;font-size:0.8em;white-space:nowrap;opacity:0;transition:opacity 0.2s;pointer-events:none}.chart-bar:hover .tooltip{opacity:1}.chart-labels{display:flex;gap:4px;padding:10px 10px 0}.chart-label{flex:1;text-align:center;font-size:0.7em;color:#666}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>📊 Traffic Analytics</h1><p>Historical traffic data and trends</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalData">-</div><div class="stat-label">Total Data</div></div><div class="stat-card"><div class="stat-value" id="totalReqs">-</div><div class="stat-label">Total Requests</div></div><div class="stat-card"><div class="stat-value" id="peakDevices">-</div><div class="stat-label">Peak Devices</div></div><div class="stat-card"><div class="stat-value" id="errorRate">-</div><div class="stat-label">Error Rate</div></div></div><div class="chart-container"><h2>📈 Traffic Over Time</h2><button class="btn btn-secondary" onclick="loadAnalytics()" style="float:right;margin-top:-45px">🔄 Refresh</button><div class="chart"><div class="chart-bars" id="trafficBars"></div><div class="chart-labels" id="trafficLabels"></div></div></div><div class="chart-container"><h2>📊 Active Devices Over Time</h2><div class="chart"><div class="chart-bars" id="deviceBars"></div><div class="chart-labels" id="deviceLabels"></div></div></div></div><script>` + baseJS + `document.getElementById('nav-analytics').classList.add('active');function loadAnalytics(){fetch('/api/traffic-history').then(r=>r.json()).then(data=>{if(!data||!data.length){document.getElementById('trafficBars').innerHTML='<div class="loading">No data yet. Traffic data is collected every 5 minutes.</div>';return;}const totalBytes=data.reduce((a,d)=>a+(d.total_bytes_in||0)+(d.total_bytes_out||0),0);const totalReqs=data.length>0?data[data.length-1].total_requests:0;const peakDevices=Math.max(...data.map(d=>d.active_devices||0));const totalErrors=data.length>0?data[data.length-1].error_count:0;const errorRate=totalReqs>0?((totalErrors/totalReqs)*100).toFixed(2)+'%':'0%';document.getElementById('totalData').textContent=formatBytes(totalBytes);document.getElementById('totalReqs').textContent=formatNumber(totalReqs);document.getElementById('peakDevices').textContent=peakDevices;document.getElementById('errorRate').textContent=errorRate;const maxBytes=Math.max(...data.map(d=>(d.total_bytes_in||0)+(d.total_bytes_out||0)));const maxDevices=Math.max(...data.map(d=>d.active_devices||0));document.getElementById('trafficBars').innerHTML=data.map(d=>{const bytes=(d.total_bytes_in||0)+(d.total_bytes_out||0);const h=maxBytes>0?(bytes/maxBytes*230):5;return'<div class="chart-bar" style="height:'+h+'px"><span class="tooltip">'+formatBytes(bytes)+'</span></div>';}).join('');document.getElementById('trafficLabels').innerHTML=data.map((d,i)=>{if(i%Math.ceil(data.length/8)===0){return'<div class="chart-label">'+new Date(d.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+'</div>';}return'<div class="chart-label"></div>';}).join('');document.getElementById('deviceBars').innerHTML=data.map(d=>{const h=maxDevices>0?(d.active_devices/maxDevices*230):5;return'<div class="chart-bar" style="height:'+h+'px;background:linear-gradient(135deg,#4caf50 0%,#2e7d32 100%)"><span class="tooltip">'+d.active_devices+' devices</span></div>';}).join('');document.getElementById('deviceLabels').innerHTML=data.map((d,i)=>{if(i%Math.ceil(data.length/8)===0){return'<div class="chart-label">'+new Date(d.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+'</div>';}return'<div class="chart-label"></div>';}).join('');});}loadAnalytics();setInterval(loadAnalytics,60000);</script></body></html>`

const settingsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Settings</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.settings-section{background:white;border-radius:12px;padding:25px;box-shadow:0 2px 10px rgba(0,0,0,0.05);margin-bottom:20px}.settings-section h2{margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #f0f0f0}.form-group{margin-bottom:20px}.form-group label{display:block;font-weight:600;color:#333;margin-bottom:8px}.form-group input{width:100%;max-width:400px;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.form-group input:focus{outline:none;border-color:#667eea}.form-group small{display:block;color:#666;margin-top:5px;font-size:0.85em}.success-msg{background:#e8f5e9;color:#2e7d32;padding:12px;border-radius:8px;margin-bottom:20px;display:none}.success-msg.show{display:block}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>⚙️ Settings</h1><p>Configure your Lumier Dynamics system</p></div><div class="settings-section"><h2>🔐 Change Password</h2><div class="success-msg" id="pwSuccess">Password changed successfully!</div><form onsubmit="return changePassword(event)"><div class="form-group"><label>Current Password</label><input type="password" id="oldPassword" required></div><div class="form-group"><label>New Password</label><input type="password" id="newPassword" required><small>Choose a strong password with at least 8 characters</small></div><div class="form-group"><label>Confirm New Password</label><input type="password" id="confirmPassword" required></div><button type="submit" class="btn btn-primary">Change Password</button></form></div><div class="settings-section"><h2>📱 Device Groups</h2><p style="margin-bottom:15px;color:#666">Manage device groups for better organization</p><div id="groupsList" style="margin-bottom:15px"></div><div style="display:flex;gap:10px"><input type="text" id="newGroupName" placeholder="New group name..." style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;flex:1;max-width:300px"><button class="btn btn-primary" onclick="addGroup()">Add Group</button></div></div><div class="settings-section"><h2>🌐 Proxy Management</h2><p style="margin-bottom:15px;color:#666">Manage and organize upstream SOCKS5 proxies</p><table id="proxyTable" style="width:100%;border-collapse:collapse;margin-bottom:20px"><thead><tr style="background:#f5f5f5"><th style="padding:12px;text-align:left;border-bottom:2px solid #e0e0e0">#</th><th style="padding:12px;text-align:left;border-bottom:2px solid #e0e0e0">Name</th><th style="padding:12px;text-align:left;border-bottom:2px solid #e0e0e0">IP Address</th><th style="padding:12px;text-align:center;border-bottom:2px solid #e0e0e0">Order</th><th style="padding:12px;text-align:center;border-bottom:2px solid #e0e0e0">Actions</th></tr></thead><tbody id="proxyTableBody"></tbody></table><div style="display:flex;gap:10px;flex-wrap:wrap"><input type="text" id="newProxyString" placeholder="host:port:username:password" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;flex:1;min-width:300px;max-width:500px"><button class="btn btn-primary" onclick="addProxy()">Add Proxy</button></div><p style="margin-top:10px;color:#888;font-size:0.85em">Format: host:port:username:password (e.g., proxy.example.com:1080:user:pass)</p><div style="margin-top:20px;padding-top:20px;border-top:1px solid #eee"><h3 style="margin-bottom:15px;font-size:1.1em">📥 Bulk Import Proxies</h3><p style="margin-bottom:10px;color:#666;font-size:0.9em">Paste multiple proxies (one per line) in format: host:port:username:password</p><textarea id="bulkProxies" placeholder="brd.superproxy.io:22228:brd-customer-xxx-ip-1.2.3.4:password&#10;brd.superproxy.io:22228:brd-customer-xxx-ip-5.6.7.8:password&#10;..." style="width:100%;height:150px;padding:10px;border:2px solid #e0e0e0;border-radius:8px;font-family:monospace;font-size:0.9em"></textarea><div style="margin-top:10px;display:flex;gap:10px;align-items:center"><button class="btn btn-primary" onclick="bulkImportProxies()">Import Proxies</button><span id="bulkImportResult" style="color:#666;font-size:0.9em"></span></div></div></div><div class="settings-section"><h2>👤 Supervisor Management</h2><p style="margin-bottom:15px;color:#666">Manage supervisor accounts for the Android app (used for Change Proxy authentication)</p><div style="margin-bottom:20px"><h3 style="font-size:1em;margin-bottom:10px">🔐 Admin Password (for Register Device)</h3><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><input type="password" id="adminPassword" placeholder="Admin password" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:250px"><button class="btn btn-primary" onclick="updateAdminPassword()">Update Admin Password</button><button class="btn btn-secondary" onclick="togglePasswordVisibility('adminPassword')" style="padding:10px">👁️</button></div></div><div style="margin-bottom:15px"><h3 style="font-size:1em;margin-bottom:10px">👥 Supervisors (for Change Proxy)</h3><div id="supervisorsList" style="margin-bottom:15px"></div><div style="display:flex;gap:10px;flex-wrap:wrap"><input type="text" id="newSupervisorName" placeholder="Name" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:150px"><input type="password" id="newSupervisorPassword" placeholder="Password" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:200px"><button class="btn btn-primary" onclick="addSupervisor()">Add Supervisor</button></div></div></div><div class="settings-section"><h2>ℹ️ System Information</h2><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px"><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Version:</strong> 3.0.0</div><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Server IP:</strong> <span id="sysServerIP">...</span></div><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Proxy Port:</strong> 8888</div><div style="background:#f8f9fa;padding:15px;border-radius:8px"><strong>Dashboard Port:</strong> 8080</div></div></div></div><script>` + baseJS + `document.getElementById('nav-settings').classList.add('active');fetch('/api/server-ip').then(r=>r.text()).then(ip=>document.getElementById('sysServerIP').textContent=ip);function loadGroups(){fetch('/api/groups').then(r=>r.json()).then(groups=>{document.getElementById('groupsList').innerHTML=groups.map(g=>{const isDefault=g==='Default';return'<span style="display:inline-flex;align-items:center;gap:8px;background:#e3f2fd;color:#1976d2;padding:8px 15px;border-radius:20px;margin:5px;font-weight:500">'+g+(isDefault?'':' <button onclick="deleteGroup(\''+g+'\')" style="background:#ef5350;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:14px;line-height:1;display:flex;align-items:center;justify-content:center" title="Delete group">&times;</button>')+'</span>';}).join('');});}loadGroups();function deleteGroup(name){if(!confirm('Delete group "'+name+'"? Devices in this group will be moved to Default.')){return;}fetch('/api/delete-group',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_name:name})}).then(r=>{if(r.ok)return r.json();throw new Error('Failed to delete');}).then(d=>{if(d.ok){showToast('Group deleted','success');loadGroups();}}).catch(()=>showToast('Failed to delete group','error'));}function addGroup(){const name=document.getElementById('newGroupName').value.trim();if(!name){showToast('Please enter a group name','error');return;}fetch('/api/add-group',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast(d.added?'Group added':'Group already exists',d.added?'success':'');document.getElementById('newGroupName').value='';loadGroups();}});}function changePassword(e){e.preventDefault();const oldPw=document.getElementById('oldPassword').value;const newPw=document.getElementById('newPassword').value;const confirmPw=document.getElementById('confirmPassword').value;if(newPw!==confirmPw){showToast('Passwords do not match','error');return false;}if(newPw.length<6){showToast('Password must be at least 6 characters','error');return false;}fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:oldPw,new_password:newPw})}).then(r=>{if(r.ok){document.getElementById('pwSuccess').classList.add('show');document.getElementById('oldPassword').value='';document.getElementById('newPassword').value='';document.getElementById('confirmPassword').value='';setTimeout(()=>document.getElementById('pwSuccess').classList.remove('show'),3000);}else{showToast('Current password is incorrect','error');}});return false;}let allProxies=[];function loadProxies(){fetch('/api/proxies').then(r=>r.json()).then(proxies=>{allProxies=proxies;const tbody=document.getElementById('proxyTableBody');if(!proxies.length){tbody.innerHTML='<tr><td colspan="5" style="padding:20px;text-align:center;color:#666">No proxies configured. Add your first proxy below.</td></tr>';return;}tbody.innerHTML=proxies.map((p,i)=>{let ip=p.user&&p.user.includes('ip-')?p.user.split('ip-')[1]:p.host;const name=p.custom_name||'SG'+String(i+1).padStart(2,'0');return'<tr style="border-bottom:1px solid #eee"><td style="padding:12px;font-weight:600;color:#667eea">'+(i+1)+'</td><td style="padding:12px"><input type="text" value="'+escapeAttr(name)+'" style="padding:8px 12px;border:2px solid #e0e0e0;border-radius:6px;font-weight:600;width:100px" onchange="updateProxyName('+i+',this.value)" placeholder="SG'+String(i+1).padStart(2,'0')+'"></td><td style="padding:12px;font-family:monospace;color:#333">'+ip+'</td><td style="padding:12px;text-align:center"><button onclick="moveProxy('+i+',-1)" style="background:#e3f2fd;border:none;border-radius:4px;padding:6px 10px;cursor:pointer;margin-right:5px" '+(i===0?'disabled':'')+' title="Move Up">↑</button><button onclick="moveProxy('+i+',1)" style="background:#e3f2fd;border:none;border-radius:4px;padding:6px 10px;cursor:pointer" '+(i===proxies.length-1?'disabled':'')+' title="Move Down">↓</button></td><td style="padding:12px;text-align:center"><button onclick="deleteProxy('+i+')" style="background:#ef5350;color:white;border:none;border-radius:6px;padding:6px 12px;cursor:pointer" title="Delete">🗑️</button></td></tr>';}).join('');});}function escapeAttr(s){return s.replace(/"/g,'&quot;');}function updateProxyName(idx,name){fetch('/api/update-proxy-name',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx,name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxy renamed to '+name,'success');}else{showToast('Failed to rename','error');}});}function moveProxy(idx,dir){const newOrder=allProxies.map((_,i)=>i);const targetIdx=idx+dir;if(targetIdx<0||targetIdx>=allProxies.length)return;[newOrder[idx],newOrder[targetIdx]]=[newOrder[targetIdx],newOrder[idx]];fetch('/api/reorder-proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:newOrder})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxies reordered','success');loadProxies();}else{showToast('Failed to reorder','error');}});}loadProxies();function addProxy(){const proxy=document.getElementById('newProxyString').value.trim();if(!proxy){showToast('Please enter a proxy string','error');return;}fetch('/api/add-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxy_string:proxy})}).then(r=>{if(!r.ok)return r.text().then(t=>{throw new Error(t);});return r.json();}).then(d=>{if(d.ok){showToast(d.added?'Proxy added':'Proxy already exists',d.added?'success':'');document.getElementById('newProxyString').value='';loadProxies();}}).catch(e=>showToast(e.message||'Failed to add proxy','error'));}function deleteProxy(idx){if(!confirm('Delete this proxy? Make sure no devices are using it.')){return;}fetch('/api/delete-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxy_index:idx})}).then(r=>{if(!r.ok)return r.text().then(t=>{throw new Error(t);});return r.json();}).then(d=>{if(d.ok){showToast('Proxy deleted','success');loadProxies();}}).catch(e=>showToast(e.message||'Failed to delete proxy','error'));}function bulkImportProxies(){const proxies=document.getElementById('bulkProxies').value.trim();if(!proxies){showToast('Please paste proxy strings','error');return;}document.getElementById('bulkImportResult').textContent='Importing...';fetch('/api/bulk-import-proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxies:proxies})}).then(r=>r.json()).then(d=>{if(d.success){const msg='Added '+d.added+' proxies'+(d.skipped>0?', skipped '+d.skipped:'');document.getElementById('bulkImportResult').innerHTML='<span style="color:#4caf50">✓ '+msg+'</span>';showToast(msg,'success');document.getElementById('bulkProxies').value='';loadProxies();}else{document.getElementById('bulkImportResult').innerHTML='<span style="color:#c62828">✗ Import failed</span>';showToast('Import failed','error');}}).catch(e=>{document.getElementById('bulkImportResult').innerHTML='<span style="color:#c62828">✗ Error</span>';showToast('Import error','error');});}function loadSupervisors(){fetch('/api/supervisors').then(r=>r.json()).then(data=>{document.getElementById('adminPassword').value=data.admin_password||'';const list=document.getElementById('supervisorsList');if(!data.supervisors||!data.supervisors.length){list.innerHTML='<p style="color:#666">No supervisors configured.</p>';return;}list.innerHTML=data.supervisors.map(s=>'<div style="display:inline-flex;align-items:center;gap:8px;background:#e8f5e9;color:#2e7d32;padding:8px 15px;border-radius:20px;margin:5px;font-weight:500">'+s.name+' <button onclick="editSupervisor(\''+s.name+'\',\''+s.password+'\')" style="background:#1976d2;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:12px" title="Edit">✎</button> <button onclick="deleteSupervisor(\''+s.name+'\')" style="background:#ef5350;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:14px;line-height:1" title="Delete">&times;</button></div>').join('');});}loadSupervisors();function togglePasswordVisibility(id){const input=document.getElementById(id);input.type=input.type==='password'?'text':'password';}function updateAdminPassword(){const pw=document.getElementById('adminPassword').value.trim();if(!pw){showToast('Please enter a password','error');return;}fetch('/api/admin-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Admin password updated','success');}else{showToast('Failed to update','error');}});}function addSupervisor(){const name=document.getElementById('newSupervisorName').value.trim();const pw=document.getElementById('newSupervisorPassword').value.trim();if(!name||!pw){showToast('Name and password required','error');return;}fetch('/api/add-supervisor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,password:pw})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Supervisor added','success');document.getElementById('newSupervisorName').value='';document.getElementById('newSupervisorPassword').value='';loadSupervisors();}else{showToast(d.message||'Failed to add','error');}});}function editSupervisor(name,pw){const newName=prompt('Supervisor name:',name);if(!newName)return;const newPw=prompt('Password:',pw);if(!newPw)return;fetch('/api/update-supervisor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_name:name,name:newName,password:newPw})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Supervisor updated','success');loadSupervisors();}else{showToast(d.message||'Failed to update','error');}});}function deleteSupervisor(name){if(!confirm('Delete supervisor "'+name+'"?'))return;fetch('/api/delete-supervisor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Supervisor deleted','success');loadSupervisors();}else{showToast(d.message||'Failed to delete','error');}});}</script></body></html>`

const monitoringPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Monitoring</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.monitor-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:25px}.monitor-card{background:white;padding:25px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.05);text-align:center}.monitor-value{font-size:2.5em;font-weight:bold;margin-bottom:5px}.monitor-label{color:#666;font-size:0.9em;text-transform:uppercase;letter-spacing:1px}.monitor-sublabel{color:#999;font-size:0.8em;margin-top:5px}.progress-ring{width:120px;height:120px;margin:0 auto 15px}.progress-ring circle{fill:none;stroke-width:10;transform:rotate(-90deg);transform-origin:center}.progress-ring .bg{stroke:#e0e0e0}.progress-ring .fg{stroke:#667eea;stroke-linecap:round;transition:stroke-dashoffset 0.5s}.logs-container{background:white;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.05);overflow:hidden}.logs-header{background:#333;color:white;padding:15px 20px;display:flex;justify-content:space-between;align-items:center}.logs-header h2{margin:0;font-size:1.1em}.logs-content{height:400px;overflow-y:auto;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;font-size:0.85em;padding:0}.log-entry{padding:8px 20px;border-bottom:1px solid #f0f0f0;display:flex;gap:15px}.log-entry:nth-child(odd){background:#fafafa}.log-time{color:#888;white-space:nowrap}.log-level{font-weight:600;text-transform:uppercase;font-size:0.8em;padding:2px 8px;border-radius:4px}.log-level.info{background:#e3f2fd;color:#1976d2}.log-level.error{background:#ffebee;color:#c62828}.log-level.warn{background:#fff3e0;color:#e65100}.log-msg{color:#333;word-break:break-word;flex:1}.auto-scroll{display:flex;align-items:center;gap:8px;font-size:0.9em}.auto-scroll input{width:18px;height:18px;cursor:pointer}</style></head><body>` + navHTML + `<div class="container"><div class="page-header"><h1>🖥️ System Monitoring</h1><p>Real-time server performance and logs</p></div><div class="monitor-grid"><div class="monitor-card"><svg class="progress-ring" id="cpuRing"><circle class="bg" cx="60" cy="60" r="50"/><circle class="fg" id="cpuCircle" cx="60" cy="60" r="50"/></svg><div class="monitor-value" id="cpuValue">-%</div><div class="monitor-label">CPU Usage</div></div><div class="monitor-card"><svg class="progress-ring" id="memRing"><circle class="bg" cx="60" cy="60" r="50"/><circle class="fg" id="memCircle" cx="60" cy="60" r="50" style="stroke:#4caf50"/></svg><div class="monitor-value" id="memValue">-</div><div class="monitor-label">Memory Used</div><div class="monitor-sublabel" id="memTotal">of -</div></div><div class="monitor-card"><div class="monitor-value" style="color:#2196F3" id="uptimeValue">-</div><div class="monitor-label">Uptime</div></div><div class="monitor-card"><div class="monitor-value" style="color:#ff9800" id="goroutines">-</div><div class="monitor-label">Goroutines</div></div><div class="monitor-card"><div class="monitor-value" style="color:#4caf50" id="netIn">-</div><div class="monitor-label">Network In</div></div><div class="monitor-card"><div class="monitor-value" style="color:#9c27b0" id="netOut">-</div><div class="monitor-label">Network Out</div></div></div><div class="logs-container"><div class="logs-header"><h2>📋 Live Logs</h2><div style="display:flex;gap:15px;align-items:center"><button class="btn btn-secondary" onclick="loadLogs()" style="padding:6px 12px;font-size:0.85em">🔄 Refresh</button><label class="auto-scroll"><input type="checkbox" id="autoScroll" checked> Auto-scroll</label></div></div><div class="logs-content" id="logsContent"><div class="loading">Loading logs...</div></div></div></div><script>` + baseJS + `document.getElementById('nav-monitoring').classList.add('active');const circumference=2*Math.PI*50;document.querySelectorAll('.progress-ring .fg').forEach(c=>{c.style.strokeDasharray=circumference;c.style.strokeDashoffset=circumference;});function setProgress(el,pct){const offset=circumference-(pct/100)*circumference;el.style.strokeDashoffset=offset;}function loadStats(){fetch('/api/system-stats').then(r=>r.json()).then(d=>{document.getElementById('cpuValue').textContent=d.cpu_usage.toFixed(1)+'%';setProgress(document.getElementById('cpuCircle'),d.cpu_usage);const memPct=(d.memory_used/d.memory_total)*100;document.getElementById('memValue').textContent=formatBytes(d.memory_used);document.getElementById('memTotal').textContent='of '+formatBytes(d.memory_total);setProgress(document.getElementById('memCircle'),memPct);document.getElementById('uptimeValue').textContent=d.uptime_formatted;document.getElementById('goroutines').textContent=d.goroutines;document.getElementById('netIn').textContent=formatBytes(d.total_bytes_in);document.getElementById('netOut').textContent=formatBytes(d.total_bytes_out);});}function loadLogs(){fetch('/api/logs').then(r=>r.json()).then(logs=>{const container=document.getElementById('logsContent');if(!logs||!logs.length){container.innerHTML='<div style="padding:20px;color:#666;text-align:center">No logs yet. Activity will appear here.</div>';return;}container.innerHTML=logs.map(l=>{const time=new Date(l.timestamp).toLocaleTimeString();return'<div class="log-entry"><span class="log-time">'+time+'</span><span class="log-level '+l.level+'">'+l.level+'</span><span class="log-msg">'+escapeHtml(l.message)+'</span></div>';}).join('');if(document.getElementById('autoScroll').checked){container.scrollTop=container.scrollHeight;}});}function escapeHtml(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}loadStats();loadLogs();setInterval(loadStats,2000);setInterval(loadLogs,3000);</script></body></html>`
