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
	Confirmed    bool      `json:"confirmed"`
	ConfirmedAt  time.Time `json:"confirmed_at"`
	SessionStart time.Time `json:"session_start"`
	// Device Health fields
	LastProxyCheck     time.Time `json:"last_proxy_check"`
	LastProxyIP        string    `json:"last_proxy_ip"`
	ProxyCheckStatus   string    `json:"proxy_check_status"` // "verified", "mismatch", "failed", "pending"
	ProxyCheckCountry  string    `json:"proxy_check_country"`
	ProxyCheckCity     string    `json:"proxy_check_city"`
	HealthScore        int       `json:"health_score"`         // 0-100
	ConsecutiveErrors  int       `json:"consecutive_errors"`   // Track consecutive failures
	LastSuccessfulReq  time.Time `json:"last_successful_req"`  // Last successful proxy request
	AvgResponseTime    int64     `json:"avg_response_time_ms"` // Average response time
	ResponseTimeCount  int64     `json:"response_time_count"`  // For calculating average
}

type DeviceHealth struct {
	Username          string    `json:"username"`
	IP                string    `json:"ip"`
	CustomName        string    `json:"custom_name"`
	ProxyName         string    `json:"proxy_name"`
	ProxyIP           string    `json:"proxy_ip"`
	Status            string    `json:"status"`             // "healthy", "degraded", "unhealthy", "offline", "unverified"
	HealthScore       int       `json:"health_score"`       // 0-100
	LastSeen          time.Time `json:"last_seen"`          // Last activity
	LastProxyCheck    time.Time `json:"last_proxy_check"`   // Last IP verification
	ProxyCheckStatus  string    `json:"proxy_check_status"` // "verified", "mismatch", "failed"
	ProxyCheckCountry string    `json:"proxy_check_country"`
	SessionValid      bool      `json:"session_valid"`
	SessionExpires    time.Time `json:"session_expires"`
	ErrorCount        int64     `json:"error_count"`
	ConsecutiveErrors int       `json:"consecutive_errors"`
	RequestCount      int64     `json:"request_count"`
	SuccessRate       float64   `json:"success_rate"`
	AvgResponseTime   int64     `json:"avg_response_time_ms"`
	BytesIn           int64     `json:"bytes_in"`
	BytesOut          int64     `json:"bytes_out"`
	Online            bool      `json:"online"`
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
	LastIP           string    `json:"last_ip,omitempty"`
	LastConfirmed    time.Time `json:"last_confirmed,omitempty"`
	LastSessionStart time.Time `json:"last_session_start,omitempty"`
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

type AuditLog struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Username  string    `json:"username"`
	IP        string    `json:"ip"`
	Details   string    `json:"details"`
	Success   bool      `json:"success"`
	Category  string    `json:"category"` // "auth", "config", "session", "proxy", "device"
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
	ProxyNames      map[int]string          `json:"proxy_names"`
	AuditLogs       []AuditLog              `json:"audit_logs"`
}

type Supervisor struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type SystemSettings struct {
	SessionTimeout          int `json:"session_timeout_hours"`
	TrafficRetentionDays    int `json:"traffic_retention_days"`
	DeviceTimeoutMinutes    int `json:"device_timeout_minutes"`
	DeviceHealthCheckMins   int `json:"device_health_check_mins"`
	AuditLogRetentionDays   int `json:"audit_log_retention_days"`
	MaxConsecutiveErrors    int `json:"max_consecutive_errors"`
}

type ProxyServer struct {
	devices          map[string]*Device
	mu               sync.RWMutex
	proxyPool        []string
	proxyHealth      map[int]*ProxyHealth
	healthMu         sync.RWMutex
	poolIndex        int
	poolMu           sync.Mutex
	proxyPort        int
	dashPort         int
	bindAddr         string
	allowIPFallback  bool
	authRequired     bool
	requireRegister  bool
	persistentData   PersistentData
	persistMu        sync.RWMutex
	dataFile         string
	sessions         map[string]*Session
	appSessions      map[string]*Session
	sessionMu        sync.RWMutex
	startTime        time.Time
	logBuffer        []LogEntry
	logMu            sync.RWMutex
	cpuUsage         float64
	cpuMu            sync.RWMutex
	deviceActivity   map[string][]DeviceActivity
	deviceActivityMu sync.RWMutex
	// Save debouncer
	saveChan     chan struct{}
	saveStopChan chan struct{}
	// Audit log buffer
	auditBuffer []AuditLog
	auditMu     sync.RWMutex
}

type LogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	DeviceIP   string    `json:"device_ip,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	Username   string    `json:"username,omitempty"`
	Category   string    `json:"category,omitempty"`
}

type DeviceActivity struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	Details    string    `json:"details"`
	Success    bool      `json:"success"`
	ProxyName  string    `json:"proxy_name,omitempty"`
	TargetHost string    `json:"target_host,omitempty"`
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
	Username string `json:"username"`
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
	log.Println("    Enterprise Edition v3.2 (Device Health)")
	log.Println("===========================================")

	bindAddr := strings.TrimSpace(os.Getenv("BIND_ADDR"))
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	proxyPort := parseEnvInt("PROXY_PORT", 8888)
	dashPort := parseEnvInt("DASHBOARD_PORT", 8080)
	allowIPFallback := parseEnvBool("ALLOW_IP_FALLBACK", false)
	authRequired := parseEnvBool("AUTH_REQUIRED", false)
	requireRegister := parseEnvBool("REQUIRE_REGISTER", true)

	server = &ProxyServer{
		devices:        make(map[string]*Device),
		proxyPool:      loadProxyPool(),
		proxyHealth:    make(map[int]*ProxyHealth),
		proxyPort:      proxyPort,
		dashPort:       dashPort,
		bindAddr:       bindAddr,
		allowIPFallback: allowIPFallback,
		authRequired:   authRequired,
		requireRegister: requireRegister,
		dataFile:       "device_data.json",
		sessions:       make(map[string]*Session),
		appSessions:    make(map[string]*Session),
		startTime:      time.Now(),
		logBuffer:      make([]LogEntry, 0, 1000),
		deviceActivity: make(map[string][]DeviceActivity),
		saveChan:       make(chan struct{}, 1),
		saveStopChan:   make(chan struct{}),
		auditBuffer:    make([]AuditLog, 0, 500),
		persistentData: PersistentData{
			DeviceConfigs:   make(map[string]DeviceConfig),
			Groups:          []string{"Default", "Floor 1", "Floor 2", "Team A", "Team B"},
			Users:           []UserCredentials{},
			TrafficHistory:  []TrafficSnapshot{},
			ProxyHealthData: make(map[int]*ProxyHealth),
			AuditLogs:       []AuditLog{},
			SystemSettings: SystemSettings{
				SessionTimeout:        2,
				TrafficRetentionDays:  7,
				DeviceTimeoutMinutes:  30,
				DeviceHealthCheckMins: 10,
				AuditLogRetentionDays: 30,
				MaxConsecutiveErrors:  5,
			},
		},
	}

	server.loadPersistentData()
	server.restoreDevicesFromConfig()
	server.initializeProxyHealth()

	if len(server.persistentData.Users) == 0 {
		server.createDefaultAdmin()
	}

	if len(server.proxyPool) == 0 {
		log.Println("⚠️  WARNING: No upstream proxies loaded!")
	} else {
		log.Printf("✅ Loaded %d upstream proxies\n", len(server.proxyPool))
	}

	// Start background workers
	go server.saveWorker()
	go cleanupInactiveDevices()
	go collectTrafficSnapshots()
	go cleanupExpiredSessions()
	go proxyHealthChecker()
	go cpuMonitor()
	go server.deviceHealthChecker()
	go server.auditLogCleanup()
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
// AUDIT LOGGING
// ============================================================================

func (s *ProxyServer) addAuditLog(event, username, ip, details, category string, success bool) {
	entry := AuditLog{
		Timestamp: time.Now(),
		Event:     event,
		Username:  username,
		IP:        ip,
		Details:   details,
		Success:   success,
		Category:  category,
	}
	s.auditMu.Lock()
	s.auditBuffer = append(s.auditBuffer, entry)
	if len(s.auditBuffer) > 1000 {
		s.auditBuffer = s.auditBuffer[len(s.auditBuffer)-1000:]
	}
	s.auditMu.Unlock()
	s.persistMu.Lock()
	s.persistentData.AuditLogs = append(s.persistentData.AuditLogs, entry)
	s.persistMu.Unlock()
	s.requestSave()
}

func (s *ProxyServer) getAuditLogs(limit int, category string) []AuditLog {
	s.auditMu.RLock()
	defer s.auditMu.RUnlock()
	var filtered []AuditLog
	for _, log := range s.auditBuffer {
		if category == "" || log.Category == category {
			filtered = append(filtered, log)
		}
	}
	if limit <= 0 || limit > len(filtered) {
		limit = len(filtered)
	}
	start := len(filtered) - limit
	if start < 0 {
		start = 0
	}
	result := make([]AuditLog, limit)
	copy(result, filtered[start:])
	return result
}

func (s *ProxyServer) auditLogCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		s.persistMu.Lock()
		retentionDays := s.persistentData.SystemSettings.AuditLogRetentionDays
		if retentionDays <= 0 {
			retentionDays = 30
		}
		cutoff := time.Now().AddDate(0, 0, -retentionDays)
		var filtered []AuditLog
		for _, log := range s.persistentData.AuditLogs {
			if log.Timestamp.After(cutoff) {
				filtered = append(filtered, log)
			}
		}
		s.persistentData.AuditLogs = filtered
		s.persistMu.Unlock()
		s.auditMu.Lock()
		var filteredBuffer []AuditLog
		for _, log := range s.auditBuffer {
			if log.Timestamp.After(cutoff) {
				filteredBuffer = append(filteredBuffer, log)
			}
		}
		s.auditBuffer = filteredBuffer
		s.auditMu.Unlock()
		s.requestSave()
	}
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
	s.requestSave()
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
// PERSISTENCE WITH DEBOUNCED SAVE
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
	if s.persistentData.AuditLogs == nil {
		s.persistentData.AuditLogs = []AuditLog{}
	}
	s.auditMu.Lock()
	s.auditBuffer = append(s.auditBuffer, s.persistentData.AuditLogs...)
	if len(s.auditBuffer) > 1000 {
		s.auditBuffer = s.auditBuffer[len(s.auditBuffer)-1000:]
	}
	s.auditMu.Unlock()
	if len(s.persistentData.Supervisors) == 0 {
		s.persistentData.Supervisors = []Supervisor{
			{Name: "Mirko", Password: "DobroJeMirko321a"},
		}
	}
	if s.persistentData.AdminPassword == "" {
		s.persistentData.AdminPassword = "Drnda123"
	}
	if s.persistentData.ProxyNames == nil {
		s.persistentData.ProxyNames = make(map[int]string)
	}
	if s.persistentData.SystemSettings.DeviceHealthCheckMins == 0 {
		s.persistentData.SystemSettings.DeviceHealthCheckMins = 10
	}
	if s.persistentData.SystemSettings.AuditLogRetentionDays == 0 {
		s.persistentData.SystemSettings.AuditLogRetentionDays = 30
	}
	if s.persistentData.SystemSettings.MaxConsecutiveErrors == 0 {
		s.persistentData.SystemSettings.MaxConsecutiveErrors = 5
	}
}

func (s *ProxyServer) getProxyName(index int) string {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()
	if name, ok := s.persistentData.ProxyNames[index]; ok && name != "" {
		return name
	}
	return fmt.Sprintf("SG%d", index+1)
}

func (s *ProxyServer) restoreDevicesFromConfig() {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()
	count := 0
	for username, cfg := range s.persistentData.DeviceConfigs {
		if cfg.Username == "" || cfg.Username != username {
			continue
		}
		var upstreamProxy string
		s.poolMu.Lock()
		if cfg.ProxyIndex >= 0 && cfg.ProxyIndex < len(s.proxyPool) {
			upstreamProxy = s.proxyPool[cfg.ProxyIndex]
		} else if len(s.proxyPool) > 0 {
			upstreamProxy = s.proxyPool[0]
		}
		s.poolMu.Unlock()
		device := &Device{
			ID:               fmt.Sprintf("device-%s", username),
			IP:               cfg.LastIP,
			Username:         username,
			Name:             username,
			CustomName:       cfg.CustomName,
			Group:            cfg.Group,
			Notes:            cfg.Notes,
			UpstreamProxy:    upstreamProxy,
			Status:           "active",
			FirstSeen:        time.Now(),
			LastSeen:         time.Now(),
			ProxyCheckStatus: "pending",
			HealthScore:      100,
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

// saveWorker - debounced save to prevent disk thrashing
func (s *ProxyServer) saveWorker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	needsSave := false
	for {
		select {
		case <-s.saveChan:
			needsSave = true
		case <-ticker.C:
			if needsSave {
				s.doSave()
				needsSave = false
			}
		case <-s.saveStopChan:
			if needsSave {
				s.doSave()
			}
			return
		}
	}
}

func (s *ProxyServer) requestSave() {
	select {
	case s.saveChan <- struct{}{}:
	default:
	}
}

func (s *ProxyServer) doSave() {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.healthMu.RLock()
	healthCopy := make(map[int]*ProxyHealth)
	for k, v := range s.proxyHealth {
		healthCopy[k] = &ProxyHealth{
			Index:           v.Index,
			ProxyString:     v.ProxyString,
			IPAddress:       v.IPAddress,
			TotalRequests:   v.TotalRequests,
			SuccessCount:    v.SuccessCount,
			FailureCount:    v.FailureCount,
			SuccessRate:     v.SuccessRate,
			LastSuccess:     v.LastSuccess,
			LastFailure:     v.LastFailure,
			LastError:       v.LastError,
			AvgResponseTime: v.AvgResponseTime,
			Status:          v.Status,
			BytesIn:         v.BytesIn,
			BytesOut:        v.BytesOut,
			ActiveDevices:   v.ActiveDevices,
		}
	}
	s.healthMu.RUnlock()
	s.persistentData.ProxyHealthData = healthCopy
	data, err := json.MarshalIndent(s.persistentData, "", "  ")
	if err != nil {
		log.Printf("Error marshaling persistent data: %v", err)
		return
	}
	tempFile := s.dataFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		log.Printf("Error writing temp file: %v", err)
		return
	}
	if err := os.Rename(tempFile, s.dataFile); err != nil {
		log.Printf("Error renaming temp file: %v", err)
		os.Remove(tempFile)
	}
}

func (s *ProxyServer) savePersistentData() {
	s.requestSave()
}

func (s *ProxyServer) updateDeviceHealthScore(device *Device) {
	score := 100
	s.persistMu.RLock()
	maxErrors := s.persistentData.SystemSettings.MaxConsecutiveErrors
	s.persistMu.RUnlock()
	if maxErrors <= 0 {
		maxErrors = 5
	}
	if device.ConsecutiveErrors > 0 {
		errorPenalty := (device.ConsecutiveErrors * 100) / maxErrors
		if errorPenalty > 50 {
			errorPenalty = 50
		}
		score -= errorPenalty
	}
	switch device.ProxyCheckStatus {
	case "mismatch":
		score -= 30
	case "failed":
		score -= 40
	case "pending":
		score -= 10
	}
	if device.RequestCount > 10 {
		errorRate := float64(device.ErrorCount) / float64(device.RequestCount)
		if errorRate > 0.1 {
			score -= int(errorRate * 30)
		}
	}
	if time.Since(device.LastSeen) > 5*time.Minute {
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	device.HealthScore = score
}

func getDeviceHealthStatus(device *Device) string {
	if time.Since(device.LastSeen) > 5*time.Minute {
		return "offline"
	}
	if device.ProxyCheckStatus == "pending" || device.LastProxyCheck.IsZero() {
		return "unverified"
	}
	switch {
	case device.HealthScore >= 80:
		return "healthy"
	case device.HealthScore >= 50:
		return "degraded"
	default:
		return "unhealthy"
	}
}

func calculateDeviceSuccessRate(device *Device) float64 {
	if device.RequestCount == 0 {
		return 100.0
	}
	successCount := device.RequestCount - device.ErrorCount
	return (float64(successCount) / float64(device.RequestCount)) * 100
}

func handleDeviceHealthAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	defer server.mu.RUnlock()
	server.persistMu.RLock()
	sessionTimeout := server.persistentData.SystemSettings.SessionTimeout
	server.persistMu.RUnlock()
	healthData := make([]DeviceHealth, 0, len(server.devices))
	for _, device := range server.devices {
		proxyIndex := server.getProxyIndexByString(device.UpstreamProxy)
		proxyName := server.getProxyName(proxyIndex)
		proxyIP := extractProxyIP(device.UpstreamProxy)
		sessionValid := server.isDeviceSessionValid(device)
		var sessionExpires time.Time
		if device.Confirmed && !device.SessionStart.IsZero() {
			sessionExpires = device.SessionStart.Add(time.Duration(sessionTimeout) * time.Hour)
		}
		displayName := device.CustomName
		if displayName == "" {
			displayName = device.Name
		}
		health := DeviceHealth{
			Username:          device.Username,
			IP:                device.IP,
			CustomName:        displayName,
			ProxyName:         proxyName,
			ProxyIP:           proxyIP,
			Status:            getDeviceHealthStatus(device),
			HealthScore:       device.HealthScore,
			LastSeen:          device.LastSeen,
			LastProxyCheck:    device.LastProxyCheck,
			ProxyCheckStatus:  device.ProxyCheckStatus,
			ProxyCheckCountry: device.ProxyCheckCountry,
			SessionValid:      sessionValid,
			SessionExpires:    sessionExpires,
			ErrorCount:        device.ErrorCount,
			ConsecutiveErrors: device.ConsecutiveErrors,
			RequestCount:      device.RequestCount,
			SuccessRate:       calculateDeviceSuccessRate(device),
			AvgResponseTime:   device.AvgResponseTime,
			BytesIn:           device.BytesIn,
			BytesOut:          device.BytesOut,
			Online:            time.Since(device.LastSeen) < 5*time.Minute,
		}
		healthData = append(healthData, health)
	}
	sort.Slice(healthData, func(i, j int) bool {
		if healthData[i].Online != healthData[j].Online {
			return healthData[i].Online
		}
		return healthData[i].HealthScore < healthData[j].HealthScore
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthData)
}

func handleDeviceHealthStatsAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	defer server.mu.RUnlock()
	var healthy, degraded, unhealthy, offline, unverified, total int
	var avgHealthScore int64
	for _, device := range server.devices {
		total++
		avgHealthScore += int64(device.HealthScore)
		status := getDeviceHealthStatus(device)
		switch status {
		case "healthy":
			healthy++
		case "degraded":
			degraded++
		case "unhealthy":
			unhealthy++
		case "offline":
			offline++
		case "unverified":
			unverified++
		}
	}
	avgScore := 0
	if total > 0 {
		avgScore = int(avgHealthScore / int64(total))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":            total,
		"healthy":          healthy,
		"degraded":         degraded,
		"unhealthy":        unhealthy,
		"offline":          offline,
		"unverified":       unverified,
		"avg_health_score": avgScore,
	})
}

func handleVerifyDeviceProxyAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.mu.RLock()
	device := server.findDeviceByUsername(req.Username)
	server.mu.RUnlock()
	if device == nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	publicIP, country, city, err := fetchPublicIPAndGeoThroughProxy(device.UpstreamProxy)
	server.mu.Lock()
	device.LastProxyCheck = time.Now()
	result := map[string]interface{}{
		"username":    req.Username,
		"checked_at":  device.LastProxyCheck,
		"proxy_name":  server.getProxyName(server.getProxyIndexByString(device.UpstreamProxy)),
		"expected_ip": extractIPFromProxyString(device.UpstreamProxy),
	}
	if err != nil {
		device.ProxyCheckStatus = "failed"
		device.ConsecutiveErrors++
		server.updateDeviceHealthScore(device)
		server.mu.Unlock()
		result["status"] = "failed"
		result["error"] = err.Error()
		result["health_score"] = device.HealthScore
	} else {
		expectedIP := extractIPFromProxyString(device.UpstreamProxy)
		device.LastProxyIP = publicIP
		device.ProxyCheckCountry = country
		device.ProxyCheckCity = city
		if publicIP == expectedIP {
			device.ProxyCheckStatus = "verified"
			device.ConsecutiveErrors = 0
			result["status"] = "verified"
		} else {
			device.ProxyCheckStatus = "mismatch"
			device.ConsecutiveErrors++
			result["status"] = "mismatch"
		}
		server.updateDeviceHealthScore(device)
		server.mu.Unlock()
		result["actual_ip"] = publicIP
		result["country"] = country
		result["city"] = city
		result["health_score"] = device.HealthScore
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
package main

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
	if isProxySideError(errorMsg) {
		s.healthMu.Lock()
		defer s.healthMu.Unlock()
		health, exists := s.proxyHealth[proxyIndex]
		if !exists {
			return
		}
		health.TotalRequests++
		health.SuccessCount++
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
	if len(s.logBuffer) > 1000 {
		s.logBuffer = s.logBuffer[len(s.logBuffer)-1000:]
	}
	s.logMu.Unlock()
}

func (s *ProxyServer) addDeviceLog(level, category, message string, device *Device) {
	deviceIP := ""
	deviceName := ""
	username := ""
	if device != nil {
		deviceIP = device.IP
		deviceName = device.CustomName
		if deviceName == "" {
			deviceName = device.Name
		}
		username = device.Username
	}
	entry := LogEntry{
		Timestamp:  time.Now(),
		Level:      level,
		Message:    message,
		DeviceIP:   deviceIP,
		DeviceName: deviceName,
		Username:   username,
		Category:   category,
	}
	s.logMu.Lock()
	s.logBuffer = append(s.logBuffer, entry)
	if len(s.logBuffer) > 1000 {
		s.logBuffer = s.logBuffer[len(s.logBuffer)-1000:]
	}
	s.logMu.Unlock()
}

func (s *ProxyServer) addDeviceActivity(deviceIP string, action, details string, success bool, proxyName, targetHost string) {
	activity := DeviceActivity{
		Timestamp:  time.Now(),
		Action:     action,
		Details:    details,
		Success:    success,
		ProxyName:  proxyName,
		TargetHost: targetHost,
	}
	s.deviceActivityMu.Lock()
	if s.deviceActivity[deviceIP] == nil {
		s.deviceActivity[deviceIP] = make([]DeviceActivity, 0, 100)
	}
	s.deviceActivity[deviceIP] = append(s.deviceActivity[deviceIP], activity)
	if len(s.deviceActivity[deviceIP]) > 100 {
		s.deviceActivity[deviceIP] = s.deviceActivity[deviceIP][len(s.deviceActivity[deviceIP])-100:]
	}
	s.deviceActivityMu.Unlock()
}

func (s *ProxyServer) getDeviceActivity(deviceIP string, limit int) []DeviceActivity {
	s.deviceActivityMu.RLock()
	defer s.deviceActivityMu.RUnlock()
	activities := s.deviceActivity[deviceIP]
	if activities == nil {
		return []DeviceActivity{}
	}
	if limit <= 0 || limit > len(activities) {
		limit = len(activities)
	}
	start := len(activities) - limit
	if start < 0 {
		start = 0
	}
	result := make([]DeviceActivity, limit)
	copy(result, activities[start:])
	return result
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
// USERNAME PARSING
// ============================================================================

func parseProxyUsername(r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return ""
	}
	if !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	encoded := strings.TrimPrefix(auth, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 100 {
		return false
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' || r == ' ' {
			continue
		}
		return false
	}
	return true
}

func (s *ProxyServer) findDeviceByUsername(username string) *Device {
	for _, device := range s.devices {
		if device.Username == username {
			return device
		}
	}
	return nil
}

func (s *ProxyServer) findDeviceByIP(ip string) *Device {
	for _, device := range s.devices {
		if device.IP == ip {
			return device
		}
	}
	return nil
}

func (s *ProxyServer) findAnonymousDeviceByIP(ip string) *Device {
	for _, device := range s.devices {
		if device.IP == ip && device.Username == "" {
			return device
		}
	}
	return nil
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
	if username == "" && s.allowIPFallback {
		s.persistMu.RLock()
		if cfg, ok := s.persistentData.DeviceConfigs[clientIP]; ok && cfg.Username != "" {
			username = cfg.Username
		}
		s.persistMu.RUnlock()
	}
	if username == "" && s.requireRegister {
		s.mu.RLock()
		existingDevice := s.findDeviceByIP(clientIP)
		if existingDevice != nil && existingDevice.Username != "" {
			s.mu.RUnlock()
			return existingDevice, nil
		}
		s.mu.RUnlock()
		return nil, fmt.Errorf("registration required: no username presented")
	}
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
	if username != "" {
		if device := s.findDeviceByUsername(username); device != nil {
			if device.IP != clientIP {
				oldIP := device.IP
				device.IP = clientIP
				log.Printf("📱 Device '%s' IP changed: %s -> %s\n", username, oldIP, clientIP)
				s.addLog("info", fmt.Sprintf("Device '%s' IP changed: %s -> %s", username, oldIP, clientIP))
			}
			return device, nil
		}
	}
	if username == "" && s.allowIPFallback {
		if device := s.findDeviceByIP(clientIP); device != nil {
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
	if username == "" && s.requireRegister {
		return nil, fmt.Errorf("registration required: no username mapping found")
	}
	var deviceID, deviceName string
	if username != "" {
		deviceID = fmt.Sprintf("device-%s", username)
		deviceName = username
	} else {
		deviceID = fmt.Sprintf("device-%d", len(s.devices)+1)
		deviceName = fmt.Sprintf("Anonymous-%s", clientIP)
	}
	device := &Device{
		ID:               deviceID,
		IP:               clientIP,
		Username:         username,
		Name:             deviceName,
		CustomName:       customName,
		Group:            group,
		Notes:            notes,
		UpstreamProxy:    upstreamProxy,
		Status:           "active",
		FirstSeen:        time.Now(),
		LastSeen:         time.Now(),
		ProxyCheckStatus: "pending",
		HealthScore:      100,
	}
	if username != "" {
		s.devices[username] = device
		log.Printf("📱 New device: '%s' (%s) -> %s\n", username, clientIP, extractProxyIP(upstreamProxy))
		s.addLog("info", fmt.Sprintf("New device connected: '%s' (%s) -> Proxy %s", username, clientIP, extractProxyIP(upstreamProxy)))
	} else {
		s.devices[clientIP] = device
		log.Printf("📱 New anonymous device: %s -> %s\n", clientIP, extractProxyIP(upstreamProxy))
		s.addLog("info", fmt.Sprintf("New anonymous device: %s -> Proxy %s", clientIP, extractProxyIP(upstreamProxy)))
	}
	go s.saveDeviceConfig(device)
	return device, nil
}

func (s *ProxyServer) isDeviceSessionValid(device *Device) bool {
	s.persistMu.RLock()
	sessionTimeoutHours := s.persistentData.SystemSettings.SessionTimeout
	s.persistMu.RUnlock()
	if sessionTimeoutHours <= 0 {
		sessionTimeoutHours = 2
	}
	if !device.Confirmed {
		return false
	}
	sessionDuration := time.Duration(sessionTimeoutHours) * time.Hour
	if time.Since(device.SessionStart) > sessionDuration {
		device.Confirmed = false
		return false
	}
	return true
}

func (s *ProxyServer) confirmDeviceSession(device *Device) {
	now := time.Now()
	device.Confirmed = true
	device.ConfirmedAt = now
	device.SessionStart = now
	s.persistMu.Lock()
	if cfg, ok := s.persistentData.DeviceConfigs[device.Username]; ok {
		cfg.LastConfirmed = now
		cfg.LastSessionStart = now
		s.persistentData.DeviceConfigs[device.Username] = cfg
	} else if cfg, ok := s.persistentData.DeviceConfigs[device.IP]; ok {
		cfg.LastConfirmed = now
		cfg.LastSessionStart = now
		s.persistentData.DeviceConfigs[device.IP] = cfg
	}
	s.persistMu.Unlock()
	s.requestSave()
}

func (s *ProxyServer) saveDeviceConfig(device *Device) {
	s.mu.RLock()
	upstreamProxy := device.UpstreamProxy
	username := device.Username
	customName := device.CustomName
	group := device.Group
	notes := device.Notes
	deviceIP := device.IP
	s.mu.RUnlock()
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
	if username != "" {
		s.persistentData.DeviceConfigs[username] = cfg
		if s.allowIPFallback && deviceIP != "" {
			s.persistentData.DeviceConfigs[deviceIP] = cfg
		}
	}
	s.persistMu.Unlock()
	s.requestSave()
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
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
	case "/api/app/confirm-connection":
		handleAppConfirmConnection(w, r)
		return
	case "/api/app/device-settings":
		handleAppDeviceSettings(w, r)
		return
	case "/api/app/server-verify":
		handleAppServerVerify(w, r)
		return
	}
	username := parseProxyUsername(r)
	device, err := server.getOrCreateDevice(clientIP, username)
	if err != nil {
		server.addLog("warn", fmt.Sprintf("[BLOCKED] Unregistered device %s (user: %s) tried to connect to %s", clientIP, username, r.Host))
		server.addDeviceActivity(clientIP, "connection_blocked", "Device not registered", false, "", r.Host)
		server.addAuditLog("connection_blocked", username, clientIP, fmt.Sprintf("Tried to access %s", r.Host), "auth", false)
		http.Error(w, "Registration required: please authenticate in the app", http.StatusProxyAuthRequired)
		return
	}
	if !server.isDeviceSessionValid(device) {
		server.addDeviceLog("warn", "session", fmt.Sprintf("[BLOCKED] Session expired/unconfirmed for %s trying to access %s", device.Username, r.Host), device)
		server.addDeviceActivity(clientIP, "session_blocked", "Session expired or not confirmed", false, "", r.Host)
		http.Error(w, "Session expired or not confirmed. Please open the app and confirm your connection.", http.StatusProxyAuthRequired)
		return
	}
	server.mu.Lock()
	device.LastSeen = time.Now()
	server.mu.Unlock()
	atomic.AddInt64(&device.RequestCount, 1)
	proxyName := ""
	proxyIndex := server.getProxyIndexByString(device.UpstreamProxy)
	if proxyIndex >= 0 {
		proxyName = server.getProxyName(proxyIndex)
	}
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r, device, proxyName)
	} else {
		handleHTTP(w, r, device, proxyName)
	}
}

func handleHTTPS(w http.ResponseWriter, r *http.Request, device *Device, proxyName string) {
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
		if !isProxySideError(errMsg) {
			atomic.AddInt64(&device.ErrorCount, 1)
			server.mu.Lock()
			device.LastError = errMsg
			device.LastErrorTime = time.Now()
			device.ConsecutiveErrors++
			server.updateDeviceHealthScore(device)
			server.mu.Unlock()
			server.addDeviceLog("error", "proxy", fmt.Sprintf("[ERROR] HTTPS connection failed to %s via %s: %s", target, proxyName, errMsg), device)
			server.addDeviceActivity(device.IP, "connection_error", fmt.Sprintf("HTTPS to %s failed: %s", target, errMsg), false, proxyName, target)
		} else {
			server.addDeviceLog("warn", "proxy", fmt.Sprintf("[PROXY ERROR] %s via %s to %s: %s", device.Username, proxyName, target, errMsg), device)
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
	server.mu.Lock()
	device.ConsecutiveErrors = 0
	device.LastSuccessfulReq = time.Now()
	server.mu.Unlock()
	reqCount := atomic.LoadInt64(&device.RequestCount)
	if reqCount <= 5 || reqCount%100 == 0 {
		server.addDeviceActivity(device.IP, "https_connect", fmt.Sprintf("Connected to %s", target), true, proxyName, target)
	}
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
	responseTime := time.Since(startTime)
	if proxyIndex >= 0 {
		server.recordProxySuccess(proxyIndex, responseTime, bytesIn, bytesOut)
	}
	server.mu.Lock()
	if device.ResponseTimeCount == 0 {
		device.AvgResponseTime = responseTime.Milliseconds()
	} else {
		device.AvgResponseTime = (device.AvgResponseTime*device.ResponseTimeCount + responseTime.Milliseconds()) / (device.ResponseTimeCount + 1)
	}
	device.ResponseTimeCount++
	server.updateDeviceHealthScore(device)
	server.mu.Unlock()
}

func handleHTTP(w http.ResponseWriter, r *http.Request, device *Device, proxyName string) {
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
			device.ConsecutiveErrors++
			server.updateDeviceHealthScore(device)
			server.mu.Unlock()
			server.addDeviceLog("error", "proxy", fmt.Sprintf("[ERROR] HTTP connection failed to %s via %s: %s", host, proxyName, errMsg), device)
			server.addDeviceActivity(device.IP, "connection_error", fmt.Sprintf("HTTP to %s failed: %s", host, errMsg), false, proxyName, host)
		} else {
			server.addDeviceLog("warn", "proxy", fmt.Sprintf("[PROXY ERROR] %s via %s to %s: %s", device.Username, proxyName, host, errMsg), device)
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
			server.addDeviceLog("error", "proxy", fmt.Sprintf("[ERROR] Failed to send HTTP request to %s: %s", host, errMsg), device)
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
			server.addDeviceLog("error", "proxy", fmt.Sprintf("[ERROR] Failed to read HTTP response from %s: %s", host, errMsg), device)
		}
		http.Error(w, "Failed to read response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	server.mu.Lock()
	device.ConsecutiveErrors = 0
	device.LastSuccessfulReq = time.Now()
	server.mu.Unlock()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	atomic.AddInt64(&device.BytesIn, n)
	responseTime := time.Since(startTime)
	if proxyIndex >= 0 {
		server.recordProxySuccess(proxyIndex, responseTime, n, 0)
	}
	server.mu.Lock()
	if device.ResponseTimeCount == 0 {
		device.AvgResponseTime = responseTime.Milliseconds()
	} else {
		device.AvgResponseTime = (device.AvgResponseTime*device.ResponseTimeCount + responseTime.Milliseconds()) / (device.ResponseTimeCount + 1)
	}
	device.ResponseTimeCount++
	server.updateDeviceHealthScore(device)
	server.mu.Unlock()
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
package main

// ============================================================================
// DASHBOARD SERVER
// ============================================================================

func startDashboard() {
	http.HandleFunc("/", handleLoginPage)
	http.HandleFunc("/api/login", handleLoginAPI)
	http.HandleFunc("/api/logout", handleLogoutAPI)
	http.HandleFunc("/api/session-check", handleSessionCheckAPI)
	// Public app API
	http.HandleFunc("/api/app/proxies", handleAppProxiesAPI)
	http.HandleFunc("/api/app/register", handleAppRegisterAPI)
	http.HandleFunc("/api/app/change-proxy", handleAppChangeProxyAPI)
	http.HandleFunc("/api/app/authenticate", handleAppAuthenticateAPI)
	http.HandleFunc("/api/app/whoami", handleAppWhoAmI)
	http.HandleFunc("/api/app/check-ip", handleAppCheckIP)
	http.HandleFunc("/api/app/validate-password", handleAppValidatePassword)
	http.HandleFunc("/api/app/device-settings", handleAppDeviceSettings)
	http.HandleFunc("/api/app/server-verify", handleAppServerVerify)
	http.HandleFunc("/api/app/confirm-connection", handleAppConfirmConnection)
	// Dashboard pages
	http.HandleFunc("/dashboard", server.requireAuth(handleDashboard))
	http.HandleFunc("/health", server.requireAuth(handleHealthPage))
	http.HandleFunc("/device-health", server.requireAuth(handleDeviceHealthPage))
	http.HandleFunc("/analytics", server.requireAuth(handleAnalyticsPage))
	http.HandleFunc("/activity", server.requireAuth(handleActivityPage))
	http.HandleFunc("/settings", server.requireAuth(handleSettingsPage))
	http.HandleFunc("/monitoring", server.requireAuth(handleMonitoringPage))
	http.HandleFunc("/audit", server.requireAuth(handleAuditPage))
	// Dashboard APIs
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
	http.HandleFunc("/api/device-activity", server.requireAuth(handleDeviceActivityAPI))
	http.HandleFunc("/api/activity-log", server.requireAuth(handleActivityLogAPI))
	http.HandleFunc("/api/supervisors", server.requireAuth(handleSupervisorsAPI))
	http.HandleFunc("/api/add-supervisor", server.requireAuth(handleAddSupervisorAPI))
	http.HandleFunc("/api/update-supervisor", server.requireAuth(handleUpdateSupervisorAPI))
	http.HandleFunc("/api/delete-supervisor", server.requireAuth(handleDeleteSupervisorAPI))
	http.HandleFunc("/api/admin-password", server.requireAuth(handleAdminPasswordAPI))
	http.HandleFunc("/api/update-proxy-name", server.requireAuth(handleUpdateProxyNameAPI))
	http.HandleFunc("/api/reorder-proxies", server.requireAuth(handleReorderProxiesAPI))
	http.HandleFunc("/api/session-settings", server.requireAuth(handleSessionSettingsAPI))
	http.HandleFunc("/api/device-health", server.requireAuth(handleDeviceHealthAPI))
	http.HandleFunc("/api/device-health-stats", server.requireAuth(handleDeviceHealthStatsAPI))
	http.HandleFunc("/api/verify-device-proxy", server.requireAuth(handleVerifyDeviceProxyAPI))
	http.HandleFunc("/api/audit-logs", server.requireAuth(handleAuditLogsAPI))
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
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if !server.validateCredentials(req.Username, req.Password) {
		server.addAuditLog("login_failed", req.Username, clientIP, "Invalid credentials", "auth", false)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token := server.createSession(req.Username)
	server.addAuditLog("login_success", req.Username, clientIP, "Dashboard login", "auth", true)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600 * server.persistentData.SystemSettings.SessionTimeout,
	})
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleLogoutAPI(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		server.sessionMu.Lock()
		delete(server.sessions, cookie.Value)
		server.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Path: "/", MaxAge: -1})
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleSessionCheckAPI(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	if _, valid := server.validateSession(cookie.Value); !valid {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAuditLogsAPI(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	category := r.URL.Query().Get("category")
	logs := server.getAuditLogs(limit, category)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func handleDevicesAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	defer server.mu.RUnlock()
	devices := make([]*Device, 0, len(server.devices))
	for _, d := range server.devices {
		devices = append(devices, d)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

func handleStatsAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	totalDevices := len(server.devices)
	var activeDevices, totalRequests, totalBytesIn, totalBytesOut, totalErrors int64
	for _, d := range server.devices {
		if time.Since(d.LastSeen) < 5*time.Minute {
			activeDevices++
		}
		totalRequests += d.RequestCount
		totalBytesIn += d.BytesIn
		totalBytesOut += d.BytesOut
		totalErrors += d.ErrorCount
	}
	server.mu.RUnlock()
	stats := map[string]interface{}{
		"total_devices":   totalDevices,
		"active_devices":  activeDevices,
		"total_requests":  totalRequests,
		"total_bytes_in":  totalBytesIn,
		"total_bytes_out": totalBytesOut,
		"total_errors":    totalErrors,
		"total_proxies":   len(server.proxyPool),
		"uptime_seconds":  int(time.Since(server.startTime).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleServerIPAPI(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip": getServerIP(), "proxy_port": server.proxyPort, "dash_port": server.dashPort,
	})
}

func handleProxiesAPI(w http.ResponseWriter, r *http.Request) {
	server.poolMu.Lock()
	defer server.poolMu.Unlock()
	proxies := make([]ProxyInfo, 0, len(server.proxyPool))
	for i, p := range server.proxyPool {
		parts := strings.Split(p, ":")
		info := ProxyInfo{Index: i, Full: p, CustomName: server.getProxyName(i)}
		if len(parts) >= 2 {
			info.Host, info.Port = parts[0], parts[1]
		}
		if len(parts) >= 3 {
			info.User = parts[2]
		}
		if len(parts) >= 4 {
			info.Pass = strings.Join(parts[3:], ":")
		}
		proxies = append(proxies, info)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proxies)
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
	server.poolMu.Lock()
	if req.ProxyIndex < 0 || req.ProxyIndex >= len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "invalid proxy index", http.StatusBadRequest)
		return
	}
	newProxy := server.proxyPool[req.ProxyIndex]
	server.poolMu.Unlock()
	server.mu.Lock()
	device := server.findDeviceByIP(req.DeviceIP)
	if device == nil {
		server.mu.Unlock()
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	oldProxy := device.UpstreamProxy
	device.UpstreamProxy = newProxy
	username := device.Username
	server.mu.Unlock()
	go server.saveDeviceConfig(device)
	server.addAuditLog("proxy_change", username, req.DeviceIP,
		fmt.Sprintf("Changed from proxy %d to %d", server.getProxyIndexByString(oldProxy), req.ProxyIndex), "proxy", true)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	device := server.findDeviceByIP(req.DeviceIP)
	if device == nil {
		server.mu.Unlock()
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	device.CustomName = req.CustomName
	device.Group = req.Group
	device.Notes = req.Notes
	if req.Username != "" {
		device.Username = req.Username
		device.Name = req.Username
	}
	server.mu.Unlock()
	go server.saveDeviceConfig(device)
	server.addAuditLog("device_update", req.Username, req.DeviceIP,
		fmt.Sprintf("Updated: name=%s, group=%s", req.CustomName, req.Group), "device", true)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	server.mu.Lock()
	for _, ip := range req.DeviceIPs {
		if device := server.findDeviceByIP(ip); device != nil {
			device.UpstreamProxy = newProxy
			go server.saveDeviceConfig(device)
		}
	}
	server.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": len(req.DeviceIPs)})
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
	server.persistentData.Groups = append(server.persistentData.Groups, req.GroupName)
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleDeleteGroupAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deleteGroupRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	var filtered []string
	for _, g := range server.persistentData.Groups {
		if g != req.GroupName {
			filtered = append(filtered, g)
		}
	}
	server.persistentData.Groups = filtered
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	server.poolMu.Lock()
	server.proxyPool = append(server.proxyPool, req.ProxyString)
	newIndex := len(server.proxyPool) - 1
	server.poolMu.Unlock()
	server.healthMu.Lock()
	server.proxyHealth[newIndex] = &ProxyHealth{Index: newIndex, ProxyString: req.ProxyString, IPAddress: extractProxyIP(req.ProxyString), Status: "unknown"}
	server.healthMu.Unlock()
	saveProxyPool()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	server.proxyPool = append(server.proxyPool[:req.ProxyIndex], server.proxyPool[req.ProxyIndex+1:]...)
	server.poolMu.Unlock()
	server.healthMu.Lock()
	delete(server.proxyHealth, req.ProxyIndex)
	newHealth := make(map[int]*ProxyHealth)
	for i, p := range server.proxyPool {
		if h, ok := server.proxyHealth[i]; ok {
			h.Index = i
			newHealth[i] = h
		} else {
			newHealth[i] = &ProxyHealth{Index: i, ProxyString: p, IPAddress: extractProxyIP(p), Status: "unknown"}
		}
	}
	server.proxyHealth = newHealth
	server.healthMu.Unlock()
	saveProxyPool()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleDeleteDeviceAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deleteDeviceRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.mu.Lock()
	var deviceToDelete *Device
	var deleteKey string
	if req.Username != "" {
		deviceToDelete = server.findDeviceByUsername(req.Username)
		deleteKey = req.Username
	} else if req.DeviceIP != "" {
		deviceToDelete = server.findDeviceByIP(req.DeviceIP)
		deleteKey = req.DeviceIP
	}
	if deviceToDelete != nil {
		delete(server.devices, deleteKey)
		if deviceToDelete.Username != "" {
			delete(server.devices, deviceToDelete.Username)
		}
		if deviceToDelete.IP != "" {
			delete(server.devices, deviceToDelete.IP)
		}
	}
	server.mu.Unlock()
	server.persistMu.Lock()
	if req.Username != "" {
		delete(server.persistentData.DeviceConfigs, req.Username)
	}
	if req.DeviceIP != "" {
		delete(server.persistentData.DeviceConfigs, req.DeviceIP)
	}
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleExportAPI(w http.ResponseWriter, r *http.Request) {
	server.mu.RLock()
	defer server.mu.RUnlock()
	var sb strings.Builder
	sb.WriteString("Username,IP,CustomName,Group,Proxy,Status,FirstSeen,LastSeen,Requests,BytesIn,BytesOut,Errors,HealthScore\n")
	for _, d := range server.devices {
		proxyName := server.getProxyName(server.getProxyIndexByString(d.UpstreamProxy))
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%d\n",
			d.Username, d.IP, d.CustomName, d.Group, proxyName, d.Status,
			d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339),
			d.RequestCount, d.BytesIn, d.BytesOut, d.ErrorCount, d.HealthScore))
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=devices_export.csv")
	w.Write([]byte(sb.String()))
}

func handleBulkImportProxiesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	lines := strings.Split(string(body), "\n")
	count := 0
	server.poolMu.Lock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			server.proxyPool = append(server.proxyPool, line)
			idx := len(server.proxyPool) - 1
			server.healthMu.Lock()
			server.proxyHealth[idx] = &ProxyHealth{Index: idx, ProxyString: line, IPAddress: extractProxyIP(line), Status: "unknown"}
			server.healthMu.Unlock()
			count++
		}
	}
	server.poolMu.Unlock()
	saveProxyPool()
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "imported": count})
}

func handleProxyHealthAPI(w http.ResponseWriter, r *http.Request) {
	server.healthMu.RLock()
	defer server.healthMu.RUnlock()
	health := make([]*ProxyHealth, 0, len(server.proxyHealth))
	for _, h := range server.proxyHealth {
		h.IPAddress = extractProxyIP(h.ProxyString)
		health = append(health, h)
	}
	sort.Slice(health, func(i, j int) bool { return health[i].Index < health[j].Index })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func handleTrafficHistoryAPI(w http.ResponseWriter, r *http.Request) {
	server.persistMu.RLock()
	history := server.persistentData.TrafficHistory
	server.persistMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func handleChangePasswordAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req changePasswordRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	defer server.persistMu.Unlock()
	for i, user := range server.persistentData.Users {
		if user.Username == "admin" {
			if hashPassword(req.OldPassword, user.Salt) != user.PasswordHash {
				http.Error(w, "incorrect old password", http.StatusUnauthorized)
				return
			}
			newSalt := generateSalt()
			server.persistentData.Users[i].Salt = newSalt
			server.persistentData.Users[i].PasswordHash = hashPassword(req.NewPassword, newSalt)
			server.requestSave()
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
	}
	http.Error(w, "admin user not found", http.StatusNotFound)
}

func handleSystemStatsAPI(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	server.cpuMu.RLock()
	cpu := server.cpuUsage
	server.cpuMu.RUnlock()
	stats := map[string]interface{}{
		"cpu_percent":    cpu,
		"memory_alloc":   m.Alloc,
		"memory_sys":     m.Sys,
		"goroutines":     runtime.NumGoroutine(),
		"uptime_seconds": int(time.Since(server.startTime).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	logs := server.getLogs(limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func handleDeviceActivityAPI(w http.ResponseWriter, r *http.Request) {
	deviceIP := r.URL.Query().Get("device_ip")
	if deviceIP == "" {
		http.Error(w, "device_ip required", http.StatusBadRequest)
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	activities := server.getDeviceActivity(deviceIP, limit)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activities)
}

func handleActivityLogAPI(w http.ResponseWriter, r *http.Request) {
	server.logMu.RLock()
	defer server.logMu.RUnlock()
	category := r.URL.Query().Get("category")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	var filtered []LogEntry
	for _, log := range server.logBuffer {
		if category == "" || log.Category == category {
			filtered = append(filtered, log)
		}
	}
	start := len(filtered) - limit
	if start < 0 {
		start = 0
	}
	result := filtered[start:]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func saveProxyPool() {
	server.poolMu.Lock()
	defer server.poolMu.Unlock()
	var sb strings.Builder
	for _, p := range server.proxyPool {
		sb.WriteString(p + "\n")
	}
	os.WriteFile("proxies.txt", []byte(sb.String()), 0644)
}

func handleSupervisorsAPI(w http.ResponseWriter, r *http.Request) {
	server.persistMu.RLock()
	supervisors := server.persistentData.Supervisors
	server.persistMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(supervisors)
}

func handleAddSupervisorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var sup Supervisor
	if json.NewDecoder(r.Body).Decode(&sup) != nil || sup.Name == "" || sup.Password == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	server.persistentData.Supervisors = append(server.persistentData.Supervisors, sup)
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	for i, s := range server.persistentData.Supervisors {
		if s.Name == req.OldName {
			server.persistentData.Supervisors[i].Name = req.Name
			server.persistentData.Supervisors[i].Password = req.Password
			break
		}
	}
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleDeleteSupervisorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Name string `json:"name"` }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	var filtered []Supervisor
	for _, s := range server.persistentData.Supervisors {
		if s.Name != req.Name {
			filtered = append(filtered, s)
		}
	}
	server.persistentData.Supervisors = filtered
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAdminPasswordAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		server.persistMu.RLock()
		pw := server.persistentData.AdminPassword
		server.persistMu.RUnlock()
		json.NewEncoder(w).Encode(map[string]string{"password": pw})
		return
	}
	if r.Method == http.MethodPost {
		var req struct{ Password string `json:"password"` }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Password == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		server.persistMu.Lock()
		server.persistentData.AdminPassword = req.Password
		server.persistMu.Unlock()
		server.requestSave()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func handleUpdateProxyNameAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProxyIndex int    `json:"proxy_index"`
		Name       string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.persistMu.Lock()
	if server.persistentData.ProxyNames == nil {
		server.persistentData.ProxyNames = make(map[int]string)
	}
	server.persistentData.ProxyNames[req.ProxyIndex] = req.Name
	server.persistMu.Unlock()
	server.requestSave()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleReorderProxiesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Order []int `json:"order"` }
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.poolMu.Lock()
	if len(req.Order) != len(server.proxyPool) {
		server.poolMu.Unlock()
		http.Error(w, "order length mismatch", http.StatusBadRequest)
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
	server.proxyPool = newPool
	server.poolMu.Unlock()
	saveProxyPool()
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleSessionSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		server.persistMu.RLock()
		settings := server.persistentData.SystemSettings
		server.persistMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(settings)
		return
	}
	if r.Method == http.MethodPost {
		var settings SystemSettings
		if json.NewDecoder(r.Body).Decode(&settings) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		server.persistMu.Lock()
		server.persistentData.SystemSettings = settings
		server.persistMu.Unlock()
		server.requestSave()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func handleAppConfirmConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Username string `json:"username"` }
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Username == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	server.mu.Lock()
	device := server.findDeviceByUsername(req.Username)
	if device == nil {
		server.mu.Unlock()
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	server.confirmDeviceSession(device)
	server.mu.Unlock()
	server.persistMu.RLock()
	sessionTimeout := server.persistentData.SystemSettings.SessionTimeout
	server.persistMu.RUnlock()
	expiresAt := device.SessionStart.Add(time.Duration(sessionTimeout) * time.Hour)
	server.addAuditLog("session_confirm", req.Username, device.IP, "Session confirmed", "session", true)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "session_start": device.SessionStart, "session_expires": expiresAt})
}

func handleAppDeviceSettings(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	server.mu.RLock()
	device := server.findDeviceByUsername(username)
	server.mu.RUnlock()
	if device == nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	proxyIndex := server.getProxyIndexByString(device.UpstreamProxy)
	server.persistMu.RLock()
	sessionTimeout := server.persistentData.SystemSettings.SessionTimeout
	server.persistMu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": username, "custom_name": device.CustomName, "group": device.Group,
		"proxy_index": proxyIndex, "proxy_name": server.getProxyName(proxyIndex),
		"session_timeout": sessionTimeout, "health_score": device.HealthScore, "health_status": getDeviceHealthStatus(device),
	})
}

func handleAppServerVerify(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	server.mu.RLock()
	device := server.findDeviceByUsername(username)
	if device == nil {
		server.mu.RUnlock()
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	upstreamProxy := device.UpstreamProxy
	server.mu.RUnlock()
	publicIP, country, city, err := fetchPublicIPAndGeoThroughProxy(upstreamProxy)
	proxyIndex := server.getProxyIndexByString(upstreamProxy)
	proxyName := server.getProxyName(proxyIndex)
	expectedIP := extractIPFromProxyString(upstreamProxy)
	if err != nil {
		server.mu.Lock()
		device.LastProxyCheck = time.Now()
		device.ProxyCheckStatus = "failed"
		device.ConsecutiveErrors++
		server.updateDeviceHealthScore(device)
		server.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"verified": false, "error": err.Error(), "proxy_name": proxyName,
			"expected_ip": expectedIP, "health_score": device.HealthScore,
		})
		return
	}
	verified := publicIP == expectedIP
	server.mu.Lock()
	device.LastProxyCheck = time.Now()
	device.LastProxyIP = publicIP
	device.ProxyCheckCountry = country
	device.ProxyCheckCity = city
	if verified {
		device.ProxyCheckStatus = "verified"
		device.ConsecutiveErrors = 0
	} else {
		device.ProxyCheckStatus = "mismatch"
		device.ConsecutiveErrors++
	}
	server.updateDeviceHealthScore(device)
	healthScore := device.HealthScore
	server.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"verified": verified, "public_ip": publicIP, "expected_ip": expectedIP,
		"proxy_name": proxyName, "country": country, "city": city, "health_score": healthScore,
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func fetchPublicIPAndGeoThroughProxy(proxyStr string) (ip, country, city string, err error) {
	if proxyStr == "" {
		return "", "", "", fmt.Errorf("no proxy configured")
	}
	parts := strings.Split(proxyStr, ":")
	if len(parts) < 4 {
		return "", "", "", fmt.Errorf("invalid proxy format")
	}
	auth := &proxy.Auth{User: parts[2], Password: strings.Join(parts[3:], ":")}
	dialer, err := proxy.SOCKS5("tcp", parts[0]+":"+parts[1], auth, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}
	transport := &http.Transport{Dial: dialer.Dial, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch IP: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read response: %v", err)
	}
	var result struct {
		Query   string `json:"query"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", "", fmt.Errorf("failed to parse response: %v", err)
	}
	return result.Query, result.Country, result.City, nil
}

func extractIPFromProxyString(proxyStr string) string {
	if idx := strings.Index(proxyStr, "-ip-"); idx != -1 {
		rest := proxyStr[idx+4:]
		endIdx := strings.IndexAny(rest, ":-")
		if endIdx != -1 {
			return rest[:endIdx]
		}
		return rest
	}
	ipRegex := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	matches := ipRegex.FindStringSubmatch(proxyStr)
	if len(matches) > 1 {
		return matches[1]
	}
	parts := strings.Split(proxyStr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
