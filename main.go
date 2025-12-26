package main

import (
	"bufio"
	"compress/gzip"
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
	LastActive    time.Time `json:"last_active"`
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

// DeviceConnection tracks a recent connection made by a device
type DeviceConnection struct {
	Timestamp time.Time `json:"timestamp"`
	Host      string    `json:"host"`
	Protocol  string    `json:"protocol"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Success   bool      `json:"success"`
}

type ProxyHealth struct {
	Index           int               `json:"index"`
	ProxyString     string            `json:"proxy_string"`
	IPAddress       string            `json:"ip_address"`
	TotalRequests   int64             `json:"total_requests"`
	SuccessCount    int64             `json:"success_count"`
	FailureCount    int64             `json:"failure_count"`
	SuccessRate     float64           `json:"success_rate"`
	LastSuccess     time.Time         `json:"last_success"`
	LastFailure     time.Time         `json:"last_failure"`
	LastError       string            `json:"last_error"`
	AvgResponseTime int64             `json:"avg_response_time_ms"`
	Status          string            `json:"status"`
	BytesIn         int64             `json:"bytes_in"`
	BytesOut        int64             `json:"bytes_out"`
	ActiveDevices   int               `json:"active_devices"`
	UniqueDevices   map[string]bool   `json:"-"`
	DeviceCount     int               `json:"device_count"`
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
	// Access Point data
	APConfig  APConfig              `json:"ap_config"`
	APDevices map[string]*APDevice  `json:"ap_devices"` // keyed by MAC address
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
// ACCESS POINT DATA STRUCTURES
// ============================================================================

// APDevice represents a device connected via the WiFi access point
type APDevice struct {
	MAC           string    `json:"mac"`            // Primary identifier
	IP            string    `json:"ip"`             // Current IP from DHCP
	Hostname      string    `json:"hostname"`       // Hostname from DHCP lease
	UpstreamProxy string    `json:"upstream_proxy"` // Assigned proxy string
	ProxyIndex    int       `json:"proxy_index"`    // Index in proxy pool
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`        // online/offline
	Confirmed     bool      `json:"confirmed"`     // Must be true to access internet
	ConfirmedAt   time.Time `json:"confirmed_at"`  // When device was approved
	ConfirmedBy   string    `json:"confirmed_by"`  // Who approved the device
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	RequestCount  int64     `json:"request_count"`
	Group         string    `json:"group"`
	CustomName    string    `json:"custom_name"`
	Notes         string    `json:"notes"`
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error"`
	LastErrorTime time.Time `json:"last_error_time"`
}

// APConfig stores access point network configuration
type APConfig struct {
	Enabled      bool   `json:"enabled"`
	Interface    string `json:"interface"`     // eth0 (TP-Link UE300)
	WANInterface string `json:"wan_interface"` // Internet interface
	IPAddress    string `json:"ip_address"`    // 10.10.10.1
	Netmask      string `json:"netmask"`       // 255.255.255.0
	DHCPStart    string `json:"dhcp_start"`    // 10.10.10.100
	DHCPEnd      string `json:"dhcp_end"`      // 10.10.10.200
	LeaseFile    string `json:"lease_file"`    // /var/lib/lumier/dnsmasq.leases
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

// isValidUsername checks if a username contains only valid characters
// This prevents corrupted/garbled usernames from being registered
func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 100 {
		return false
	}

	// Check each character is printable ASCII or common unicode letters/numbers
	for _, r := range username {
		// Allow: a-z, A-Z, 0-9, underscore, hyphen, dot, space
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' || r == ' ' {
			continue
		}
		// Reject any other characters (including non-ASCII, control chars, etc.)
		return false
	}
	return true
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
	sessionMu       sync.RWMutex
	startTime        time.Time
	logBuffer        []LogEntry
	logMu            sync.RWMutex
	cpuUsage         float64
	cpuMu              sync.RWMutex
	deviceActivity     map[string][]DeviceActivity // keyed by device IP
	deviceActivityMu   sync.RWMutex
	deviceConnections  map[string][]DeviceConnection // keyed by device IP - recent connections
	deviceConnectionMu sync.RWMutex
	// Access Point fields
	apDevices      map[string]*APDevice // keyed by MAC address (runtime copy)
	apMu           sync.RWMutex
	apConfig       APConfig
	apPoolIndex    int // For round-robin proxy assignment to new AP devices
}

type LogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	DeviceIP   string    `json:"device_ip,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	Username   string    `json:"username,omitempty"`
	Category   string    `json:"category,omitempty"` // connection, auth, proxy, error, session, config
}

// DeviceActivity stores detailed activity for a specific device
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

// ============================================================================
// WEBRTC LEAK PREVENTION
// ============================================================================

// Known STUN/TURN server patterns that can cause WebRTC IP leaks
var webrtcBlockedPatterns = []string{
	"stun.l.google.com",
	"stun1.l.google.com",
	"stun2.l.google.com",
	"stun3.l.google.com",
	"stun4.l.google.com",
	"stun.services.mozilla.com",
	"turn.l.google.com",
	"turn.twilio.com",
	"global.stun.twilio.com",
	"stun.stunprotocol.org",
	"stun.voip.eutelia.it",
	"stun.sipgate.net",
	"stun.ekiga.net",
	"stun.ideasip.com",
	"stun.schlund.de",
	"stun.voipbuster.com",
	"stun.voipstunt.com",
	"stun.counterpath.com",
	"stun.1und1.de",
	"stun.gmx.net",
	"stun.callwithus.com",
	"stun.counterpath.net",
	"stun.internetcalls.com",
}

// STUN/TURN ports to block
var webrtcBlockedPorts = []string{"3478", "5349", "19302", "19305"}

// isWebRTCLeakHost checks if a host:port is a STUN/TURN server that could cause WebRTC leaks
func isWebRTCLeakHost(hostPort string) bool {
	host := hostPort
	port := ""

	// Extract host and port
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		host = hostPort[:idx]
		port = hostPort[idx+1:]
	}

	hostLower := strings.ToLower(host)

	// Check against known STUN/TURN server patterns
	for _, pattern := range webrtcBlockedPatterns {
		if strings.Contains(hostLower, pattern) || hostLower == pattern {
			return true
		}
	}

	// Check for generic STUN/TURN patterns in hostname
	if strings.Contains(hostLower, "stun.") || strings.Contains(hostLower, ".stun.") ||
		strings.HasPrefix(hostLower, "stun") ||
		strings.Contains(hostLower, "turn.") || strings.Contains(hostLower, ".turn.") ||
		strings.HasPrefix(hostLower, "turn") ||
		strings.Contains(hostLower, "webrtc") {
		return true
	}

	// Check for STUN/TURN ports
	for _, blockedPort := range webrtcBlockedPorts {
		if port == blockedPort {
			return true
		}
	}

	return false
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
	Username string `json:"username"` // Preferred - delete by username for accuracy
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
		startTime:         time.Now(),
		logBuffer:         make([]LogEntry, 0, 1000),
		deviceActivity:    make(map[string][]DeviceActivity),
		deviceConnections: make(map[string][]DeviceConnection),
		// Access Point initialization
		apDevices: make(map[string]*APDevice),
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
	server.restoreDevicesFromConfig() // Restore devices so IP-based lookup works after restart
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

	go cleanupInactiveDevices()
	go autoSaveData()
	go collectTrafficSnapshots()
	go cleanupExpiredSessions()
	go proxyHealthChecker()
	go cpuMonitor()
	go server.monitorDHCPLeases() // Monitor for AP device connections
	go startDashboard()

	serverIP := getServerIP()
	log.Printf("Proxy server starting on port %d\n", server.proxyPort)
	log.Printf("Dashboard: http://%s:%d\n", serverIP, server.dashPort)
	log.Println("Default login: admin / admin123")
	log.Printf("Access Point: Devices on 10.10.10.x network will be proxied\n")

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
			// Always refresh ProxyString and IPAddress from current proxy pool
			s.proxyHealth[i].ProxyString = proxyStr
			s.proxyHealth[i].IPAddress = extractProxyIP(proxyStr)
			// Ensure UniqueDevices map is initialized
			if s.proxyHealth[i].UniqueDevices == nil {
				s.proxyHealth[i].UniqueDevices = make(map[string]bool)
			}
		} else {
			s.proxyHealth[i] = &ProxyHealth{
				Index:         i,
				ProxyString:   proxyStr,
				IPAddress:     extractProxyIP(proxyStr),
				Status:        "unknown",
				UniqueDevices: make(map[string]bool),
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

// trackDeviceRegistration tracks a device being assigned to a proxy
func (s *ProxyServer) trackDeviceRegistration(proxyIndex int, deviceUsername string) {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if health, ok := s.proxyHealth[proxyIndex]; ok {
		if health.UniqueDevices == nil {
			health.UniqueDevices = make(map[string]bool)
		}
		if !health.UniqueDevices[deviceUsername] {
			health.UniqueDevices[deviceUsername] = true
			health.DeviceCount = len(health.UniqueDevices)
		}
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
		log.Printf("Restored %d registered devices from config\n", count)
	}
}

// restoreAPDevices restores AP devices from persistent data on startup
func (s *ProxyServer) restoreAPDevices() {
	s.persistMu.RLock()
	defer s.persistMu.RUnlock()

	if s.persistentData.APDevices == nil {
		return
	}

	count := 0
	for mac, device := range s.persistentData.APDevices {
		// Ensure proxy assignment is valid
		s.poolMu.Lock()
		if device.ProxyIndex >= 0 && device.ProxyIndex < len(s.proxyPool) {
			device.UpstreamProxy = s.proxyPool[device.ProxyIndex]
		} else if len(s.proxyPool) > 0 {
			device.ProxyIndex = 0
			device.UpstreamProxy = s.proxyPool[0]
		}
		s.poolMu.Unlock()

		// Mark as offline initially (will be updated by DHCP monitoring)
		device.Status = "offline"

		s.apMu.Lock()
		s.apDevices[mac] = device
		s.apMu.Unlock()
		count++
	}

	if count > 0 {
		log.Printf("Restored %d AP devices from config\n", count)
	}

	// Also restore AP config if set
	if s.persistentData.APConfig.Interface != "" {
		s.apConfig = s.persistentData.APConfig
	}
}

func (s *ProxyServer) savePersistentData() {
	s.persistMu.Lock() // Use write lock since we modify ProxyHealthData
	s.healthMu.RLock()
	s.persistentData.ProxyHealthData = make(map[int]*ProxyHealth)
	for k, v := range s.proxyHealth {
		s.persistentData.ProxyHealthData[k] = v
	}
	s.healthMu.RUnlock()

	// Save AP devices and config
	s.apMu.RLock()
	s.persistentData.APDevices = make(map[string]*APDevice)
	for mac, device := range s.apDevices {
		s.persistentData.APDevices[mac] = device
	}
	s.persistentData.APConfig = s.apConfig
	s.apMu.RUnlock()

	data, _ := json.MarshalIndent(s.persistentData, "", "  ")
	s.persistMu.Unlock()
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
	// Keep only last 1000 entries
	if len(s.logBuffer) > 1000 {
		s.logBuffer = s.logBuffer[len(s.logBuffer)-1000:]
	}
	s.logMu.Unlock()
}

// addDeviceLog adds a detailed log entry with device information
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

// addDeviceActivity adds an activity entry for a specific device
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
	// Keep only last 100 activities per device
	if len(s.deviceActivity[deviceIP]) > 100 {
		s.deviceActivity[deviceIP] = s.deviceActivity[deviceIP][len(s.deviceActivity[deviceIP])-100:]
	}
	s.deviceActivityMu.Unlock()
}

// getDeviceActivity returns activity log for a specific device
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

// trackDeviceConnection records a connection for real-time monitoring
func (s *ProxyServer) trackDeviceConnection(deviceIP string, host string, protocol string, bytesIn, bytesOut int64, success bool) {
	conn := DeviceConnection{
		Timestamp: time.Now(),
		Host:      host,
		Protocol:  protocol,
		BytesIn:   bytesIn,
		BytesOut:  bytesOut,
		Success:   success,
	}

	s.deviceConnectionMu.Lock()
	if s.deviceConnections[deviceIP] == nil {
		s.deviceConnections[deviceIP] = make([]DeviceConnection, 0, 50)
	}
	s.deviceConnections[deviceIP] = append(s.deviceConnections[deviceIP], conn)
	// Keep only last 50 connections per device for real-time view
	if len(s.deviceConnections[deviceIP]) > 50 {
		s.deviceConnections[deviceIP] = s.deviceConnections[deviceIP][len(s.deviceConnections[deviceIP])-50:]
	}
	s.deviceConnectionMu.Unlock()

	// Update device's LastActive on successful connections
	if success {
		s.mu.Lock()
		if device, ok := s.devices[deviceIP]; ok {
			device.LastActive = time.Now()
		}
		// Also try by username
		for _, device := range s.devices {
			if device.IP == deviceIP {
				device.LastActive = time.Now()
				break
			}
		}
		s.mu.Unlock()
	}
}

// getDeviceConnections returns recent connections for a device
func (s *ProxyServer) getDeviceConnections(deviceIP string) []DeviceConnection {
	s.deviceConnectionMu.RLock()
	defer s.deviceConnectionMu.RUnlock()

	conns := s.deviceConnections[deviceIP]
	if conns == nil {
		return []DeviceConnection{}
	}
	// Return in reverse order (most recent first)
	result := make([]DeviceConnection, len(conns))
	for i, c := range conns {
		result[len(conns)-1-i] = c
	}
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
			// Note: LastSeen is updated AFTER session validation in handleProxy()
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
			// Note: LastSeen is updated AFTER session validation in handleProxy()
			return device, nil
		}
	}

	// For requests without username, optionally allow IP-based reuse for
	// backwards compatibility when explicitly enabled.
	if username == "" && s.allowIPFallback {
		if device := s.findDeviceByIP(clientIP); device != nil {
			// Note: LastSeen is updated AFTER session validation in handleProxy()
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

// isDeviceSessionValid checks if a device has a valid confirmed session
func (s *ProxyServer) isDeviceSessionValid(device *Device) bool {
	// Get session timeout in hours
	s.persistMu.RLock()
	sessionTimeoutHours := s.persistentData.SystemSettings.SessionTimeout
	s.persistMu.RUnlock()

	if sessionTimeoutHours <= 0 {
		sessionTimeoutHours = 2 // Default to 2 hours if not set
	}

	// Device must be confirmed
	if !device.Confirmed {
		return false
	}

	// Check if session has expired
	sessionDuration := time.Duration(sessionTimeoutHours) * time.Hour
	if time.Since(device.SessionStart) > sessionDuration {
		// Session expired - require re-confirmation
		device.Confirmed = false
		return false
	}

	return true
}

// confirmDeviceSession marks a device as confirmed and starts a new session
func (s *ProxyServer) confirmDeviceSession(device *Device) {
	now := time.Now()
	device.Confirmed = true
	device.ConfirmedAt = now
	device.SessionStart = now

	// Save to persistent config
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

	go s.savePersistentData()
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

	// Check if client is from AP network (10.10.10.x)
	if server.isAPClient(clientIP) {
		apDevice := server.getAPDeviceByIP(clientIP)
		if apDevice == nil {
			// Unknown AP client - should have been detected by DHCP monitoring
			server.addLog("warn", fmt.Sprintf("[BLOCKED] Unknown AP client %s tried to connect to %s", clientIP, r.Host))
			http.Error(w, "Device not recognized. Please reconnect to the access point.", http.StatusForbidden)
			return
		}

		// Check if device is confirmed (approved in dashboard)
		if !apDevice.Confirmed {
			server.addLog("info", fmt.Sprintf("[BLOCKED] Unconfirmed AP device %s (%s) tried to access %s", apDevice.Hostname, apDevice.MAC, r.Host))
			http.Error(w, "Device pending approval. Please contact administrator.", http.StatusForbidden)
			return
		}

		// Update device activity
		server.apMu.Lock()
		apDevice.LastSeen = time.Now()
		apDevice.Status = "online"
		atomic.AddInt64(&apDevice.RequestCount, 1)
		server.apMu.Unlock()

		// Get proxy name for logging
		proxyName := server.getProxyName(apDevice.ProxyIndex)

		if r.Method == http.MethodConnect {
			handleAPHTTPS(w, r, apDevice, proxyName)
		} else {
			handleAPHTTP(w, r, apDevice, proxyName)
		}
		return
	}

	// Legacy device handling (username-based auth)
	username := parseProxyUsername(r)
	device, err := server.getOrCreateDevice(clientIP, username)
	if err != nil {
		// Log unregistered connection attempt
		server.addLog("warn", fmt.Sprintf("[BLOCKED] Unregistered device %s (user: %s) tried to connect to %s", clientIP, username, r.Host))
		server.addDeviceActivity(clientIP, "connection_blocked", "Device not registered", false, "", r.Host)
		http.Error(w, "Registration required", http.StatusProxyAuthRequired)
		return
	}

	// Check if device session is confirmed and valid
	if !server.isDeviceSessionValid(device) {
		// Log session invalid attempt
		server.addDeviceLog("warn", "session", fmt.Sprintf("[BLOCKED] Session expired/unconfirmed for %s trying to access %s", device.Username, r.Host), device)
		server.addDeviceActivity(clientIP, "session_blocked", "Session expired or not confirmed", false, "", r.Host)
		http.Error(w, "Session expired or not confirmed.", http.StatusProxyAuthRequired)
		return
	}

	// Update LastSeen only AFTER session validation passes
	// This prevents blocked/expired devices from appearing "active" in the dashboard
	server.mu.Lock()
	device.LastSeen = time.Now()
	server.mu.Unlock()

	atomic.AddInt64(&device.RequestCount, 1)

	// Get proxy name for logging
	proxyName := ""
	proxyIndex := server.getProxyIndexByString(device.UpstreamProxy)
	if proxyIndex >= 0 {
		server.persistMu.RLock()
		if name, ok := server.persistentData.ProxyNames[proxyIndex]; ok {
			proxyName = name
		} else {
			proxyName = fmt.Sprintf("Proxy #%d", proxyIndex+1)
		}
		server.persistMu.RUnlock()
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

	// Block WebRTC leak sources (STUN/TURN servers)
	if isWebRTCLeakHost(target) {
		// Silently block to prevent WebRTC IP leaks - return connection refused
		http.Error(w, "Connection refused", http.StatusForbidden)
		return
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
			server.addDeviceLog("error", "proxy", fmt.Sprintf("[ERROR] HTTPS connection failed to %s via %s: %s", target, proxyName, errMsg), device)
			server.addDeviceActivity(device.IP, "connection_error", fmt.Sprintf("HTTPS to %s failed: %s", target, errMsg), false, proxyName, target)
		}
		// Skip logging proxy-side errors (ruleset blocks, etc) - they're normal behavior
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

	// Log successful connection (only for first few requests to avoid spam)
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
	if proxyIndex >= 0 {
		server.recordProxySuccess(proxyIndex, time.Since(startTime), bytesIn, bytesOut)
	}
	// Track connection for real-time monitoring
	server.trackDeviceConnection(device.IP, target, "HTTPS", bytesIn, bytesOut, true)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, device *Device, proxyName string) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	// Block WebRTC leak sources (STUN/TURN servers)
	if isWebRTCLeakHost(host) {
		// Silently block to prevent WebRTC IP leaks
		http.Error(w, "Connection refused", http.StatusForbidden)
		return
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
			server.addDeviceLog("error", "proxy", fmt.Sprintf("[ERROR] HTTP connection failed to %s via %s: %s", host, proxyName, errMsg), device)
			server.addDeviceActivity(device.IP, "connection_error", fmt.Sprintf("HTTP to %s failed: %s", host, errMsg), false, proxyName, host)
		}
		// Skip logging proxy-side errors (ruleset blocks, etc) - they're normal behavior
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
	// Track connection for real-time monitoring
	server.trackDeviceConnection(device.IP, host, "HTTP", n, 0, true)
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

	// WPAD/PAC file for proxy auto-configuration (no auth required - devices need this)
	http.HandleFunc("/wpad.dat", handleWPAD)
	http.HandleFunc("/proxy.pac", handleWPAD) // Alternative PAC file name

	// Access Point management API
	http.HandleFunc("/access-point", server.requireAuth(handleAccessPointPage))
	http.HandleFunc("/api/ap/status", server.requireAuth(handleAPStatusAPI))
	http.HandleFunc("/api/ap/devices", server.requireAuth(handleAPDevicesAPI))
	http.HandleFunc("/api/ap/device/confirm", server.requireAuth(handleAPDeviceConfirmAPI))
	http.HandleFunc("/api/ap/device/proxy", server.requireAuth(handleAPDeviceProxyAPI))
	http.HandleFunc("/api/ap/device/update", server.requireAuth(handleAPDeviceUpdateAPI))
	http.HandleFunc("/api/ap/device/delete", server.requireAuth(handleAPDeviceDeleteAPI))

	http.HandleFunc("/dashboard", server.requireAuth(handleDashboard))
	http.HandleFunc("/health", server.requireAuth(handleHealthPage))
	http.HandleFunc("/diagnostics", server.requireAuth(handleDiagnosticsPage))
	http.HandleFunc("/analytics", server.requireAuth(handleAnalyticsPage))
	http.HandleFunc("/activity", server.requireAuth(handleActivityPage))
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
	http.HandleFunc("/api/diagnostics", server.requireAuth(handleDiagnosticsAPI))
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
	http.HandleFunc("/api/check-blacklist", server.requireAuth(handleCheckBlacklistAPI))
	http.HandleFunc("/api/device-connections", server.requireAuth(handleDeviceConnectionsAPI))
	http.HandleFunc("/api/network-overview", server.requireAuth(handleNetworkOverviewAPI))

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
// ACCESS POINT API
// ============================================================================

// isAPClient checks if an IP is from the AP network (10.10.10.x)
func (s *ProxyServer) isAPClient(ip string) bool {
	return strings.HasPrefix(ip, "10.10.10.")
}

// getAPDeviceByIP finds an AP device by its current IP address
func (s *ProxyServer) getAPDeviceByIP(ip string) *APDevice {
	s.apMu.RLock()
	defer s.apMu.RUnlock()
	for _, device := range s.apDevices {
		if device.IP == ip {
			return device
		}
	}
	return nil
}

// getAPDeviceByMAC finds an AP device by its MAC address
func (s *ProxyServer) getAPDeviceByMAC(mac string) *APDevice {
	s.apMu.RLock()
	defer s.apMu.RUnlock()
	return s.apDevices[strings.ToLower(mac)]
}

// assignProxyToAPDevice assigns the next available proxy to a new AP device
func (s *ProxyServer) assignProxyToAPDevice(device *APDevice) {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()

	if len(s.proxyPool) == 0 {
		return
	}

	device.ProxyIndex = s.apPoolIndex
	device.UpstreamProxy = s.proxyPool[s.apPoolIndex]
	s.apPoolIndex = (s.apPoolIndex + 1) % len(s.proxyPool)
}

// monitorDHCPLeases monitors the DHCP lease file for connected devices
func (s *ProxyServer) monitorDHCPLeases() {
	leaseFile := s.apConfig.LeaseFile
	if leaseFile == "" {
		leaseFile = "/var/lib/lumier/dnsmasq.leases"
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.parseDHCPLeases(leaseFile)
		s.updateAPDeviceStatus()
	}
}

// parseDHCPLeases reads and parses the dnsmasq lease file
func (s *ProxyServer) parseDHCPLeases(leaseFile string) {
	file, err := os.Open(leaseFile)
	if err != nil {
		// File might not exist yet, that's OK
		return
	}
	defer file.Close()

	currentLeases := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		// Format: timestamp mac ip hostname [client-id]
		mac := strings.ToLower(parts[1])
		ip := parts[2]
		hostname := parts[3]
		if hostname == "*" {
			hostname = ""
		}

		currentLeases[mac] = true

		s.apMu.Lock()
		if device, exists := s.apDevices[mac]; exists {
			// Update existing device
			device.IP = ip
			device.Hostname = hostname
			device.LastSeen = time.Now()
			device.Status = "online"
		} else {
			// New device detected
			now := time.Now()
			newDevice := &APDevice{
				MAC:       mac,
				IP:        ip,
				Hostname:  hostname,
				FirstSeen: now,
				LastSeen:  now,
				Status:    "online",
				Confirmed: false, // Must be confirmed in dashboard!
			}
			s.assignProxyToAPDevice(newDevice)
			s.apDevices[mac] = newDevice

			// Also save to persistent data
			s.persistMu.Lock()
			if s.persistentData.APDevices == nil {
				s.persistentData.APDevices = make(map[string]*APDevice)
			}
			s.persistentData.APDevices[mac] = newDevice
			s.persistMu.Unlock()

			s.addLog("info", fmt.Sprintf("[AP] New device detected: %s (%s) - %s - awaiting approval", hostname, mac, ip))
		}
		s.apMu.Unlock()
	}

	// Mark devices not in current leases as offline
	s.apMu.Lock()
	for mac, device := range s.apDevices {
		if !currentLeases[mac] && device.Status == "online" {
			// Check if device was seen recently (within 2 minutes)
			if time.Since(device.LastSeen) > 2*time.Minute {
				device.Status = "offline"
			}
		}
	}
	s.apMu.Unlock()
}

// updateAPDeviceStatus marks devices as offline if not seen recently
func (s *ProxyServer) updateAPDeviceStatus() {
	s.apMu.Lock()
	defer s.apMu.Unlock()

	for _, device := range s.apDevices {
		if device.Status == "online" && time.Since(device.LastSeen) > 5*time.Minute {
			device.Status = "offline"
		}
	}
}

// handleAPHTTPS handles HTTPS traffic for AP devices
func handleAPHTTPS(w http.ResponseWriter, r *http.Request, device *APDevice, proxyName string) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	// Block WebRTC leak sources
	if isWebRTCLeakHost(target) {
		http.Error(w, "Connection refused", http.StatusForbidden)
		return
	}

	startTime := time.Now()

	upstream, err := dialThroughSOCKS5(device.UpstreamProxy, target)
	if err != nil {
		server.apMu.Lock()
		atomic.AddInt64(&device.ErrorCount, 1)
		device.LastError = err.Error()
		device.LastErrorTime = time.Now()
		server.apMu.Unlock()
		http.Error(w, "Failed to connect to upstream proxy", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy
	var bytesIn, bytesOut int64
	done := make(chan bool, 2)

	go func() {
		n, _ := io.Copy(upstream, clientConn)
		bytesOut = n
		done <- true
	}()

	go func() {
		n, _ := io.Copy(clientConn, upstream)
		bytesIn = n
		done <- true
	}()

	<-done
	<-done

	// Update stats
	server.apMu.Lock()
	atomic.AddInt64(&device.BytesIn, bytesIn)
	atomic.AddInt64(&device.BytesOut, bytesOut)
	server.apMu.Unlock()

	// Update proxy health
	duration := time.Since(startTime)
	server.recordProxySuccess(device.ProxyIndex, duration, bytesIn, bytesOut)

	// Log connection
	server.addLog("debug", fmt.Sprintf("[AP] HTTPS %s -> %s via %s (%d bytes)", device.Hostname, target, proxyName, bytesIn+bytesOut))
}

// handleAPHTTP handles HTTP traffic for AP devices
func handleAPHTTP(w http.ResponseWriter, r *http.Request, device *APDevice, proxyName string) {
	// Block WebRTC leak sources
	if isWebRTCLeakHost(r.Host) {
		http.Error(w, "Connection refused", http.StatusForbidden)
		return
	}

	startTime := time.Now()

	// Connect through SOCKS5 proxy
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	upstream, err := dialThroughSOCKS5(device.UpstreamProxy, target)
	if err != nil {
		server.apMu.Lock()
		atomic.AddInt64(&device.ErrorCount, 1)
		device.LastError = err.Error()
		device.LastErrorTime = time.Now()
		server.apMu.Unlock()
		http.Error(w, "Failed to connect to upstream proxy", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Forward the request
	if err := r.Write(upstream); err != nil {
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(upstream), r)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	bytesOut, _ := io.Copy(w, resp.Body)

	// Update stats
	server.apMu.Lock()
	atomic.AddInt64(&device.BytesOut, bytesOut)
	server.apMu.Unlock()

	// Update proxy health
	duration := time.Since(startTime)
	server.recordProxySuccess(device.ProxyIndex, duration, 0, bytesOut)

	server.addLog("debug", fmt.Sprintf("[AP] HTTP %s -> %s via %s (%d bytes)", device.Hostname, r.Host, proxyName, bytesOut))
}

// handleWPAD serves the WPAD/PAC file for automatic proxy configuration
// This allows devices on the AP network to automatically configure proxy settings
func handleWPAD(w http.ResponseWriter, r *http.Request) {
	// Get the client IP to check if it's from the AP network
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Log the PAC file request
	server.addLog("info", fmt.Sprintf("[WPAD] PAC file requested by %s", clientIP))

	// Get gateway IP from config, default to 10.10.10.1
	gatewayIP := server.apConfig.IPAddress
	if gatewayIP == "" {
		gatewayIP = "10.10.10.1"
	}

	// Proxy port (default 8888)
	proxyPort := 8888

	// Generate PAC file content
	// This JavaScript function tells browsers/apps how to route traffic
	pacContent := fmt.Sprintf(`function FindProxyForURL(url, host) {
    // Don't proxy local addresses
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }

    // Route all other traffic through the proxy
    return "PROXY %s:%d";
}
`, gatewayIP, proxyPort)

	// Set appropriate headers for PAC file
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Content-Disposition", "inline; filename=\"wpad.dat\"")
	w.Header().Set("Cache-Control", "max-age=3600") // Cache for 1 hour

	w.Write([]byte(pacContent))
}

// handleAccessPointPage serves the Access Point management page
func handleAccessPointPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, accessPointPageHTML)
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

	// Collect device health summary
	server.mu.RLock()
	var activeDevices, inactiveDevices, errorDevices int
	var totalDeviceRequests, totalDeviceErrors int64
	deviceHealthSummary := make([]map[string]interface{}, 0)

	for _, device := range server.devices {
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
		proxyIdx := server.getProxyIndexByString(device.UpstreamProxy)
		proxyName := server.getProxyName(proxyIdx)

		// Calculate device error rate
		var errorRate float64
		if device.RequestCount > 0 {
			errorRate = float64(device.ErrorCount) / float64(device.RequestCount) * 100
		}

		deviceHealthSummary = append(deviceHealthSummary, map[string]interface{}{
			"username":      device.Username,
			"name":          device.CustomName,
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
	server.mu.RUnlock()

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
	if json.NewDecoder(r.Body).Decode(&req) != nil || (req.DeviceIP == "" && req.Username == "") {
		http.Error(w, "invalid request - need device_ip or username", http.StatusBadRequest)
		return
	}

	// Find device - prefer username lookup for accuracy
	server.mu.Lock()
	var device *Device
	var deviceKey string

	if req.Username != "" {
		// Try by username first (most accurate)
		device = server.findDeviceByUsername(req.Username)
		if device != nil {
			deviceKey = req.Username
		}
	}

	if device == nil && req.DeviceIP != "" {
		// Fall back to IP lookup
		device = server.findDeviceByIP(req.DeviceIP)
		if device != nil {
			if device.Username != "" {
				deviceKey = device.Username
			} else {
				deviceKey = device.IP
			}
		}
	}

	exists := device != nil
	if device != nil {
		delete(server.devices, deviceKey)
	}
	server.mu.Unlock()

	// Delete from persistent data
	server.persistMu.Lock()
	if req.Username != "" {
		delete(server.persistentData.DeviceConfigs, req.Username)
	} else if device != nil && device.Username != "" {
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

	// Build a set of registered device usernames/IPs for filtering
	registeredDevices := make(map[string]bool)
	if registeredOnly {
		server.mu.RLock()
		for key, device := range server.devices {
			registeredDevices[key] = true
			registeredDevices[device.IP] = true
			if device.Username != "" {
				registeredDevices[device.Username] = true
			}
		}
		server.mu.RUnlock()
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

// TrustScoreResult contains the fraud score and risk assessment for an IP from a single source
type TrustScoreResult struct {
	Score     int    `json:"score"`     // 0-100, lower is better (less risky)
	Risk      string `json:"risk"`      // "low", "medium", "high", "very high"
	Available bool   `json:"available"` // Whether score could be fetched
	Error     string `json:"error"`     // Error message if fetch failed
}

// CombinedTrustScore contains fraud scores from multiple sources
type CombinedTrustScore struct {
	Scamalytics    TrustScoreResult `json:"scamalytics"`
	IPQualityScore TrustScoreResult `json:"ipqualityscore"`
}

// createBrowserRequest creates an HTTP request with realistic browser headers
func createBrowserRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set comprehensive browser headers to avoid bot detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	return req, nil
}

// getRiskLevel returns the risk level string based on score (0-100, lower is better)
func getRiskLevel(score int) string {
	switch {
	case score <= 25:
		return "low"
	case score <= 50:
		return "medium"
	case score <= 75:
		return "high"
	default:
		return "very high"
	}
}

// getScamalyticsScore fetches the fraud score from Scamalytics for an IP
func getScamalyticsScore(ip string) TrustScoreResult {
	// Validate IP format
	if net.ParseIP(ip) == nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "invalid IP"}
	}

	// Create HTTP client with timeout and follow redirects
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Fetch the Scamalytics page
	url := "https://scamalytics.com/ip/" + ip
	req, err := createBrowserRequest(url)
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

	// Try to find score using various patterns from Scamalytics HTML
	patterns := []string{
		`(?i)fraud\s*score[:\s]*(\d+)`,
		`class="score"[^>]*>(\d+)<`,
		`data-score="(\d+)"`,
		`<div[^>]*score[^>]*>(\d+)</div>`,
		`>(\d+)</div>\s*<div[^>]*class="[^"]*score`,
		`(?i)score[^>]*>\s*(\d+)\s*<`,
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
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "parse error"}
	}

	return TrustScoreResult{Score: score, Risk: getRiskLevel(score), Available: true}
}

// getIPQualityScore fetches the fraud score from IPQualityScore for an IP
func getIPQualityScore(ip string) TrustScoreResult {
	// Validate IP format
	if net.ParseIP(ip) == nil {
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "invalid IP"}
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Fetch the IPQualityScore page
	url := "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/" + ip
	req, err := createBrowserRequest(url)
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

	// Try to find fraud score from IPQualityScore HTML
	// They typically show "Fraud Score: XX" or similar
	patterns := []string{
		`(?i)fraud\s*score[:\s]*(\d+)`,
		`(?i)risk\s*score[:\s]*(\d+)`,
		`"fraud_score"[:\s]*(\d+)`,
		`data-fraud-score="(\d+)"`,
		`>(\d+)%</span>\s*(?i)fraud`,
		`(?i)score[^>]*>(\d+)%<`,
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
		return TrustScoreResult{Score: -1, Risk: "unknown", Available: false, Error: "parse error"}
	}

	return TrustScoreResult{Score: score, Risk: getRiskLevel(score), Available: true}
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

	server.mu.RLock()
	defer server.mu.RUnlock()

	// Gather active devices with their current activity
	activeDevices := make([]map[string]interface{}, 0)
	now := time.Now()

	for _, device := range server.devices {
		timeSinceActive := now.Sub(device.LastActive).Minutes()
		timeSinceSeen := now.Sub(device.LastSeen).Minutes()

		// Only include devices seen in last 30 minutes
		if timeSinceSeen > 30 {
			continue
		}

		// Get session expiration time
		sessionHours := server.persistentData.SystemSettings.SessionTimeout
		if sessionHours == 0 {
			sessionHours = 2
		}
		sessionExpiry := device.SessionStart.Add(time.Duration(sessionHours) * time.Hour)
		timeUntilExpiry := sessionExpiry.Sub(now)
		expiryStr := ""
		if timeUntilExpiry > 0 {
			if timeUntilExpiry.Hours() >= 1 {
				expiryStr = fmt.Sprintf("%.0fh %.0fm", timeUntilExpiry.Hours(), float64(int(timeUntilExpiry.Minutes())%60))
			} else {
				expiryStr = fmt.Sprintf("%.0fm", timeUntilExpiry.Minutes())
			}
		} else {
			expiryStr = "Expired"
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

		// Calculate current data rate (bytes per minute over last activity)
		dataRate := int64(0)
		if timeSinceActive < 5 && timeSinceActive > 0 {
			dataRate = int64(float64(device.BytesIn+device.BytesOut) / timeSinceActive)
		}

		name := device.CustomName
		if name == "" {
			name = device.Username
		}
		if name == "" {
			name = device.IP
		}

		activeDevices = append(activeDevices, map[string]interface{}{
			"ip":              device.IP,
			"username":        device.Username,
			"name":            name,
			"group":           device.Group,
			"is_active":       timeSinceActive < 5,
			"last_active_min": timeSinceActive,
			"last_seen_min":   timeSinceSeen,
			"session_expiry":  expiryStr,
			"bytes_in":        device.BytesIn,
			"bytes_out":       device.BytesOut,
			"data_rate":       dataRate,
			"request_count":   device.RequestCount,
			"error_count":     device.ErrorCount,
			"recent_hosts":    recentHosts,
			"confirmed":       device.Confirmed,
		})
	}

	// Sort by activity (most active first)
	sort.Slice(activeDevices, func(i, j int) bool {
		iActive := activeDevices[i]["last_active_min"].(float64)
		jActive := activeDevices[j]["last_active_min"].(float64)
		return iActive < jActive
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

const loginPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Login</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-container{background:rgba(255,255,255,0.95);padding:40px;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.3);width:100%;max-width:400px}.logo{text-align:center;margin-bottom:30px}.logo h1{color:#4a9eff;font-size:2em;margin-bottom:5px}.logo p{color:#666;font-size:0.9em}.form-group{margin-bottom:20px}.form-group label{display:block;font-weight:600;color:#e0e0e0;margin-bottom:8px}.form-group input{width:100%;padding:14px 16px;border:2px solid #e0e0e0;border-radius:10px;font-size:1em}.form-group input:focus{outline:none;border-color:#4a9eff}.login-btn{width:100%;padding:14px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:10px;font-size:1.1em;font-weight:600;cursor:pointer}.login-btn:hover{opacity:0.9}.login-btn:disabled{opacity:0.5;cursor:not-allowed}.error-msg{background:#ffebee;color:#c62828;padding:12px;border-radius:8px;margin-bottom:20px;display:none}.error-msg.show{display:block}</style></head>
<body><div class="login-container"><div class="logo"><h1>🌐 Lumier Dynamics</h1><p>Enterprise Proxy Management v3.0</p></div><div class="error-msg" id="errorMsg"></div><form onsubmit="return handleLogin(event)"><div class="form-group"><label>Username</label><input type="text" id="username" placeholder="Enter username" required autofocus></div><div class="form-group"><label>Password</label><input type="password" id="password" placeholder="Enter password" required></div><button type="submit" class="login-btn" id="loginBtn">Sign In</button></form></div>
<script>async function handleLogin(e){e.preventDefault();const btn=document.getElementById('loginBtn'),err=document.getElementById('errorMsg');btn.disabled=true;btn.textContent='Signing in...';err.classList.remove('show');try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});if(r.ok)window.location.href='/dashboard';else{err.textContent='Invalid username or password';err.classList.add('show');btn.disabled=false;btn.textContent='Sign In';}}catch(e){err.textContent='Connection error';err.classList.add('show');btn.disabled=false;btn.textContent='Sign In';}return false;}</script></body></html>`

const navHTML = `<aside class="sidebar" id="sidebar"><div class="sidebar-header"><span class="logo-icon">🌐</span><span class="logo-text">LUMIER</span></div><nav class="sidebar-nav"><a href="/dashboard" class="nav-item" id="nav-dashboard"><span class="nav-icon">📱</span><span class="nav-text">Devices</span></a><a href="/browsers" class="nav-item" id="nav-browsers"><span class="nav-icon">🌐</span><span class="nav-text">Browsers</span></a><a href="/health" class="nav-item" id="nav-health"><span class="nav-icon">💚</span><span class="nav-text">Health</span></a><a href="/analytics" class="nav-item" id="nav-analytics"><span class="nav-icon">📊</span><span class="nav-text">Analytics</span></a><a href="/activity" class="nav-item" id="nav-activity"><span class="nav-icon">📋</span><span class="nav-text">Activity</span></a><a href="/settings" class="nav-item" id="nav-settings"><span class="nav-icon">⚙️</span><span class="nav-text">Settings</span></a></nav><div class="sidebar-footer"><div class="user-info"><span class="user-icon">👤</span><span class="user-name" id="currentUser">Admin</span></div><button class="logout-btn" onclick="logout()">Logout</button></div></aside>`

const baseStyles = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0a0a;min-height:100vh;color:#e0e0e0}.sidebar{position:fixed;left:0;top:0;bottom:0;width:200px;background:#121212;display:flex;flex-direction:column;border-right:1px solid #2a2a2a;z-index:100}.sidebar-header{padding:20px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #2a2a2a}.logo-icon{font-size:1.5em}.logo-text{font-size:1.2em;font-weight:bold;color:#4a9eff;letter-spacing:2px}.sidebar-nav{flex:1;padding:15px 10px;display:flex;flex-direction:column;gap:5px}.nav-item{display:flex;align-items:center;gap:12px;padding:12px 15px;color:#888;text-decoration:none;border-radius:8px;transition:all 0.2s}.nav-item:hover{background:#1e1e1e;color:#e0e0e0}.nav-item.active{background:#1e1e1e;color:#4a9eff}.nav-icon{font-size:1.1em;width:24px;text-align:center}.nav-text{font-weight:500;font-size:0.95em}.sidebar-footer{padding:15px;border-top:1px solid #2a2a2a}.user-info{display:flex;align-items:center;gap:10px;padding:10px;margin-bottom:10px}.user-icon{font-size:1.2em}.user-name{color:#888;font-size:0.9em}.logout-btn{width:100%;padding:10px;background:#1e1e1e;color:#888;border:1px solid #2a2a2a;border-radius:6px;cursor:pointer;font-weight:500;transition:all 0.2s}.logout-btn:hover{background:#2a2a2a;color:#e0e0e0}.main-content{margin-left:200px;min-height:100vh;padding:25px}.page-header{margin-bottom:25px}.page-header h1{color:#e0e0e0;font-size:1.8em;margin-bottom:5px}.page-header p{color:#888}.card{background:#1a1a1a;border-radius:12px;padding:25px;border:1px solid #2a2a2a;margin-bottom:20px}.card h2{color:#e0e0e0;font-size:1.3em;margin-bottom:15px;padding-bottom:10px;border-bottom:1px solid #2a2a2a}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:20px;margin-bottom:25px}.stat-card{background:#1a1a1a;padding:20px;border-radius:12px;border:1px solid #2a2a2a;text-align:center;cursor:pointer;transition:all 0.2s}.stat-card:hover{border-color:#4a9eff;transform:translateY(-2px)}.stat-value{font-size:2.2em;font-weight:bold;color:#4a9eff;margin-bottom:5px}.stat-label{color:#888;font-size:0.85em;text-transform:uppercase;letter-spacing:1px}.btn{padding:10px 18px;border:none;border-radius:8px;cursor:pointer;font-size:0.95em;font-weight:600;transition:all 0.2s}.btn-primary{background:#4a9eff;color:#fff}.btn-primary:hover{background:#3a8eef}.btn-secondary{background:#1e1e1e;color:#e0e0e0;border:1px solid #2a2a2a}.btn-secondary:hover{background:#2a2a2a}.toast{position:fixed;bottom:30px;right:30px;background:#1a1a1a;color:#e0e0e0;padding:15px 25px;border-radius:10px;border:1px solid #2a2a2a;z-index:1001;animation:slideIn 0.3s ease}.toast.success{background:#1a3d1a;border-color:#4caf50;color:#4caf50}.toast.error{background:#3d1a1a;border-color:#f44336;color:#f44336}@keyframes slideIn{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}.loading{text-align:center;padding:40px;color:#888}`

const baseJS = `async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/';}function showToast(msg,type=''){const t=document.createElement('div');t.className='toast '+type;t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}function formatBytes(b){if(!b)return"0 B";const k=1024,s=["B","KB","MB","GB","TB"];const i=Math.floor(Math.log(b)/Math.log(k));return(b/Math.pow(k,i)).toFixed(1)+" "+s[i];}function formatNumber(n){if(!n)return"0";if(n>=1e6)return(n/1e6).toFixed(1)+"M";if(n>=1e3)return(n/1e3).toFixed(1)+"K";return n.toString();}fetch('/api/session-check').then(r=>r.json()).then(d=>{if(!d.valid)window.location.href='/';else if(document.getElementById('currentUser'))document.getElementById('currentUser').textContent=d.username;});`

const dashboardPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Devices</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.toolbar{background:#1a1a1a;padding:15px 20px;border-radius:12px;margin-bottom:20px;border:1px solid #2a2a2a;display:flex;flex-wrap:wrap;gap:15px;align-items:center}.search-box{flex:1;min-width:200px;position:relative}.search-box input{width:100%;padding:10px 15px 10px 40px;border:1px solid #2a2a2a;border-radius:8px;font-size:1em;background:#121212;color:#e0e0e0}.search-box input:focus{outline:none;border-color:#4a9eff}.search-box::before{content:"🔍";position:absolute;left:12px;top:50%;transform:translateY(-50%)}.filter-group{display:flex;gap:10px;align-items:center}.filter-group label{font-weight:600;color:#888;font-size:0.9em}.filter-group select{padding:8px 12px;border:1px solid #2a2a2a;border-radius:8px;background:#121212;color:#e0e0e0}.device-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}.device-card{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:12px;padding:18px;transition:all 0.2s;position:relative}.device-card:hover{border-color:#4a9eff}.device-card.selected{border-color:#4a9eff;background:#1e2a3a}.device-card.pending-ap{border-color:#ff9800;background:#2a2010}.device-card.ap-device{border-left:4px solid #4a9eff}.device-checkbox{position:absolute;top:15px;right:15px;width:20px;height:20px;cursor:pointer}.device-name{font-size:1.15em;font-weight:bold;color:#e0e0e0;margin-bottom:5px;padding-right:30px;cursor:pointer}.device-name:hover{color:#4a9eff}.device-group{display:inline-block;background:#1a3d1a;color:#4caf50;padding:3px 10px;border-radius:12px;font-size:0.8em;font-weight:600;margin-bottom:10px}.device-type-badge{display:inline-block;padding:3px 8px;border-radius:10px;font-size:0.75em;font-weight:600;margin-left:8px}.type-ap{background:#1a2a3a;color:#4a9eff}.type-legacy{background:#2a1a3a;color:#9c7aff}.device-info{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:0.9em}.info-row{display:flex;justify-content:space-between;padding:3px 0}.info-label{color:#666}.status-badge{padding:3px 10px;border-radius:12px;font-size:0.85em;font-weight:600}.status-active{background:#1a3d1a;color:#4caf50}.status-inactive{background:#3d1a1a;color:#f44336}.status-pending{background:#3d2a1a;color:#ff9800}.proxy-selector{margin-top:12px;padding-top:12px;border-top:1px solid #2a2a2a;grid-column:1/-1}.proxy-selector label{display:block;font-size:0.85em;color:#888;margin-bottom:6px}.proxy-selector select{width:100%;padding:8px;border:1px solid #2a2a2a;border-radius:6px;margin-bottom:8px;background:#121212;color:#e0e0e0}.current-proxy{font-size:0.85em;color:#4a9eff;font-weight:600}.change-btn{width:100%;padding:8px;background:#4a9eff;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600}.change-btn:hover{background:#3a8eef}.approve-btn{background:#4caf50;margin-bottom:8px}.approve-btn:hover{background:#43a047}.pagination{display:flex;justify-content:center;align-items:center;gap:10px;margin-top:20px}.pagination button{padding:8px 16px;border:1px solid #2a2a2a;background:#1a1a1a;color:#e0e0e0;border-radius:6px;cursor:pointer;font-weight:600}.pagination button:hover:not(:disabled){border-color:#4a9eff;color:#4a9eff}.pagination button:disabled{opacity:0.5;cursor:not-allowed}.bulk-actions{display:flex;gap:10px;align-items:center}.selected-count{background:#4a9eff;color:white;padding:5px 12px;border-radius:20px;font-size:0.85em;font-weight:600}.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;z-index:1000}.modal{background:#1a1a1a;border:1px solid #2a2a2a;border-radius:15px;padding:25px;width:90%;max-width:450px}.modal h3{margin-bottom:20px;color:#e0e0e0}.modal-field{margin-bottom:15px}.modal-field label{display:block;font-weight:600;color:#888;margin-bottom:5px}.modal-field input,.modal-field select,.modal-field textarea{width:100%;padding:10px;border:1px solid #2a2a2a;border-radius:8px;font-size:1em;background:#121212;color:#e0e0e0}.modal-field textarea{resize:vertical;min-height:80px}.modal-buttons{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}.setup-box{background:#1a2a3a;padding:12px 20px;border-radius:10px;margin-bottom:20px;border-left:4px solid #4a9eff}.setup-box code{background:#121212;padding:2px 6px;border-radius:4px;font-family:monospace;color:#4a9eff;font-weight:bold}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>📱 Device Management</h1><p>Monitor and manage all connected devices (AP + Legacy)</p></div><div class="setup-box">📡 <strong>AP Network:</strong> Connect to the WiFi access point. New devices appear as "Pending" and require approval.<br>📱 <strong>Manual Setup:</strong> Wi-Fi → Proxy Manual → Host: <code id="serverIP">...</code> Port: <code>8888</code> Username: <code>your-device-name</code></div><div class="stats-grid"><div class="stat-card" onclick="filterByStatus('all')"><div class="stat-value" id="totalDevices">-</div><div class="stat-label">Total</div></div><div class="stat-card" onclick="filterByStatus('pending')"><div class="stat-value" id="pendingDevices" style="color:#ff9800">-</div><div class="stat-label">Pending</div></div><div class="stat-card" onclick="filterByStatus('active')"><div class="stat-value" id="activeDevices">-</div><div class="stat-label">Active</div></div><div class="stat-card" onclick="filterByStatus('inactive')"><div class="stat-value" id="inactiveDevices">-</div><div class="stat-label">Inactive</div></div><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Proxies</div></div><div class="stat-card"><div class="stat-value" id="totalRequests">-</div><div class="stat-label">Requests</div></div></div><div class="toolbar"><div class="search-box"><input type="text" id="searchInput" placeholder="Search devices..." oninput="applyFilters()"></div><div class="filter-group"><label>Type:</label><select id="typeFilter" onchange="applyFilters()"><option value="">All</option><option value="ap">AP Devices</option><option value="legacy">Legacy</option><option value="pending">Pending Approval</option></select></div><div class="filter-group"><label>Group:</label><select id="groupFilter" onchange="applyFilters()"><option value="">All</option></select></div><div class="filter-group"><label>Sort:</label><select id="sortBy" onchange="applyFilters()"><option value="name">Name</option><option value="ip">IP</option><option value="lastSeen" selected>Last Seen</option><option value="requests">Requests</option></select></div><div class="filter-group"><label><input type="checkbox" id="showOffline" onchange="loadData()" style="margin-right:5px">Show Offline</label></div><button class="btn btn-secondary" onclick="loadData()">🔄 Refresh</button><button class="btn btn-secondary" onclick="location.href='/api/export'">📤 Export</button><div class="bulk-actions" id="bulkActions" style="display:none"><span class="selected-count"><span id="selectedCount">0</span> selected</span><select id="bulkProxySelect"></select><button class="btn btn-primary" onclick="bulkChangeProxy()">Change</button><button class="btn btn-secondary" onclick="clearSelection()">Clear</button></div></div><div class="card"><h2>Connected Devices</h2><div id="devicesList" class="device-grid"><div class="loading">Loading...</div></div><div class="pagination" id="pagination"></div></div></div><div class="modal-overlay" id="editModal" style="display:none"><div class="modal"><h3>✏️ Edit Device</h3><div class="modal-field"><label>Username (Device ID)</label><input type="text" id="editUsername" placeholder="e.g., phone1, samsung-s23"></div><div class="modal-field"><label>Custom Name</label><input type="text" id="editName" placeholder="e.g., Samsung S23"></div><div class="modal-field"><label>Group</label><select id="editGroup"></select></div><div class="modal-field"><label>Notes</label><textarea id="editNotes" placeholder="Optional notes..."></textarea></div><input type="hidden" id="editDeviceIP"><input type="hidden" id="editDeviceType"><div class="modal-buttons"><button class="btn btn-secondary" onclick="closeEditModal()">Cancel</button><button class="btn btn-primary" onclick="saveDeviceEdit()">Save</button></div></div></div><div class="modal-overlay" id="approveModal" style="display:none"><div class="modal"><h3>✓ Approve Device</h3><p style="color:#666;margin-bottom:20px">This device is waiting for approval. Set a name and assign a proxy to grant internet access.</p><div class="modal-field"><label>Device Name</label><input type="text" id="approveName" placeholder="e.g., John's iPhone"></div><div class="modal-field"><label>Assign Proxy</label><select id="approveProxy"></select></div><div class="modal-field"><label>Group</label><select id="approveGroup"></select></div><input type="hidden" id="approveMAC"><div class="modal-buttons"><button class="btn btn-secondary" onclick="closeApproveModal()">Cancel</button><button class="btn btn-primary" style="background:#4caf50" onclick="confirmApprove()">✓ Approve & Grant Access</button></div></div></div><script>` + baseJS + `document.getElementById('nav-dashboard').classList.add('active');fetch("/api/server-ip").then(r=>r.text()).then(ip=>document.getElementById("serverIP").textContent=ip);let allDevices=[],allProxies=[],allGroups=[],filteredDevices=[],selectedDevices=new Set(),currentPage=1,statusFilter='all';const PER_PAGE=20;function getDisplayName(d){return d.custom_name||d.name||d.hostname||'Unknown';}function isActive(d){return(Date.now()-new Date(d.last_seen))/60000<5;}function proxyLabel(p,i){let ip=p.user&&p.user.includes('ip-')?p.user.split('ip-')[1]:'unknown';return'#'+(i+1)+' – '+ip;}function filterByStatus(s){statusFilter=s;if(s==='pending')document.getElementById('typeFilter').value='pending';applyFilters();}function applyFilters(){const search=document.getElementById('searchInput').value.toLowerCase();const group=document.getElementById('groupFilter').value;const type=document.getElementById('typeFilter').value;const sort=document.getElementById('sortBy').value;filteredDevices=allDevices.filter(d=>{if(statusFilter==='pending'&&!(d.device_type==='ap'&&!d.confirmed))return false;if(statusFilter==='active'&&!isActive(d))return false;if(statusFilter==='inactive'&&isActive(d))return false;if(type==='ap'&&d.device_type!=='ap')return false;if(type==='legacy'&&d.device_type!=='legacy')return false;if(type==='pending'&&!(d.device_type==='ap'&&!d.confirmed))return false;if(group&&d.group!==group)return false;if(search&&!getDisplayName(d).toLowerCase().includes(search)&&!d.ip.includes(search)&&!(d.username&&d.username.toLowerCase().includes(search))&&!(d.mac&&d.mac.toLowerCase().includes(search)))return false;return true;});filteredDevices.sort((a,b)=>{const aPending=a.device_type==='ap'&&!a.confirmed;const bPending=b.device_type==='ap'&&!b.confirmed;if(aPending&&!bPending)return -1;if(!aPending&&bPending)return 1;if(sort==='name')return getDisplayName(a).localeCompare(getDisplayName(b));if(sort==='ip')return a.ip.localeCompare(b.ip);if(sort==='lastSeen')return new Date(b.last_seen)-new Date(a.last_seen);if(sort==='requests')return(b.request_count||0)-(a.request_count||0);return 0;});currentPage=1;renderDevices();}function renderDevices(){const c=document.getElementById('devicesList');if(!filteredDevices.length){c.innerHTML='<div class="loading">No devices found</div>';document.getElementById('pagination').innerHTML='';return;}const pages=Math.ceil(filteredDevices.length/PER_PAGE);const start=(currentPage-1)*PER_PAGE;const pageDevices=filteredDevices.slice(start,start+PER_PAGE);c.innerHTML=pageDevices.map(d=>{const mins=Math.floor((Date.now()-new Date(d.last_seen))/60000);const active=mins<5;const sel=selectedDevices.has(d.ip);const isAP=d.device_type==='ap';const isPending=isAP&&!d.confirmed;const pIdx=isAP?d.proxy_index:allProxies.findIndex(p=>p.full===d.upstream_proxy);const opts=allProxies.map((p,i)=>'<option value="'+i+'" '+(i===pIdx?'selected':'')+'>'+proxyLabel(p,i)+'</option>').join('');const pLabel=pIdx>=0?proxyLabel(allProxies[pIdx],pIdx):'N/A';const cardClass='device-card'+(sel?' selected':'')+(isPending?' pending-ap':'')+(isAP?' ap-device':'');const typeBadge=isAP?'<span class="device-type-badge type-ap">📡 AP</span>':'<span class="device-type-badge type-legacy">📱 Legacy</span>';const statusClass=isPending?'status-pending':(active?'status-active':'status-inactive');const statusText=isPending?'⏳ Pending':(active?'● Active':'○ Inactive');const userDisplay=isAP?(d.mac||''):(d.username||'<em>anonymous</em>');return'<div class="'+cardClass+'"><input type="checkbox" class="device-checkbox" '+(sel?'checked':'')+' onchange="toggleSel(\''+d.ip+'\',this.checked)"><div class="device-name" onclick="'+(isPending?'openApproveModal':'openEditModal')+'(\''+escapeHtml(isAP?d.mac:d.ip)+'\',\''+d.device_type+'\')">'+escapeHtml(getDisplayName(d))+' '+(isPending?'':'✏️')+'</div>'+typeBadge+'<div class="device-group">'+escapeHtml(d.group||'Default')+'</div><div class="device-info"><div class="info-row"><span class="info-label">Status:</span><span class="status-badge '+statusClass+'">'+statusText+'</span></div><div class="info-row"><span class="info-label">IP:</span><span><strong>'+d.ip+'</strong></span></div><div class="info-row"><span class="info-label">'+(isAP?'MAC':'User')+':</span><span style="font-weight:600;color:#4a9eff;font-size:0.85em">'+userDisplay+'</span></div><div class="info-row"><span class="info-label">Requests:</span><span>'+formatNumber(d.request_count)+'</span></div><div class="info-row"><span class="info-label">Errors:</span><span style="color:'+(d.error_count>0?'#c62828':'#666')+'">'+(d.error_count||0)+'</span></div><div class="info-row"><span class="info-label">Data:</span><span>↓'+formatBytes(d.bytes_in)+'</span></div><div class="info-row"><span class="info-label">Last seen:</span><span>'+(mins<1?'Now':mins+' min')+'</span></div><div class="proxy-selector">'+(isPending?'<button class="change-btn approve-btn" onclick="openApproveModal(\''+escapeHtml(d.mac)+'\',\'ap\')">✓ Approve Device</button>':'<label>Proxy: <span class="current-proxy">'+pLabel+'</span></label><select id="proxy-'+(isAP?d.mac.replace(/:/g,''):d.ip)+'">'+opts+'</select><button class="change-btn" onclick="changeProxy(\''+escapeHtml(isAP?d.mac:d.ip)+'\',\''+d.device_type+'\')">Change Proxy</button>')+'<button class="change-btn" style="background:#ef5350;margin-top:8px" onclick="deleteDevice(\''+escapeHtml(isAP?d.mac:d.ip)+'\',\''+escapeHtml(isAP?'':d.username||'')+'\',\''+d.device_type+'\')">Delete Device</button></div></div></div>';}).join('');const pag=document.getElementById('pagination');pag.innerHTML=pages>1?'<button onclick="goPage('+(currentPage-1)+')" '+(currentPage===1?'disabled':'')+'>← Prev</button><span>Page '+currentPage+' of '+pages+'</span><button onclick="goPage('+(currentPage+1)+')" '+(currentPage===pages?'disabled':'')+'>Next →</button>':'<span>'+filteredDevices.length+' devices</span>';updateBulk();}function goPage(p){const pages=Math.ceil(filteredDevices.length/PER_PAGE);if(p>=1&&p<=pages){currentPage=p;renderDevices();}}function escapeHtml(t){if(!t)return'';const d=document.createElement('div');d.textContent=t;return d.innerHTML;}function toggleSel(ip,checked){checked?selectedDevices.add(ip):selectedDevices.delete(ip);updateBulk();renderDevices();}function clearSelection(){selectedDevices.clear();updateBulk();renderDevices();}function updateBulk(){const b=document.getElementById('bulkActions');b.style.display=selectedDevices.size>0?'flex':'none';document.getElementById('selectedCount').textContent=selectedDevices.size;}function changeProxy(id,type){const selId=type==='ap'?'proxy-'+id.replace(/:/g,''):'proxy-'+id;const idx=parseInt(document.getElementById(selId).value);if(type==='ap'){fetch('/api/ap/device/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:id,proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.success){showToast('Proxy changed','success');loadData();}});}else{fetch('/api/change-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:id,proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxy changed','success');loadData();}});}}function bulkChangeProxy(){const idx=parseInt(document.getElementById('bulkProxySelect').value);fetch('/api/bulk-change-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ips:Array.from(selectedDevices),proxy_index:idx})}).then(r=>r.json()).then(d=>{if(d.ok){showToast(d.updated+' devices updated','success');selectedDevices.clear();loadData();}});}function openEditModal(id,type){const d=allDevices.find(x=>type==='ap'?x.mac===id:x.ip===id);if(!d)return;document.getElementById('editDeviceIP').value=id;document.getElementById('editDeviceType').value=type;document.getElementById('editUsername').value=type==='ap'?d.mac:(d.username||'');document.getElementById('editName').value=d.custom_name||'';document.getElementById('editNotes').value=d.notes||'';document.getElementById('editGroup').innerHTML=allGroups.map(g=>'<option value="'+g+'" '+(g===d.group?'selected':'')+'>'+g+'</option>').join('');document.getElementById('editModal').style.display='flex';}function closeEditModal(){document.getElementById('editModal').style.display='none';}function saveDeviceEdit(){const id=document.getElementById('editDeviceIP').value;const type=document.getElementById('editDeviceType').value;if(type==='ap'){fetch('/api/ap/device/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:id,custom_name:document.getElementById('editName').value,group:document.getElementById('editGroup').value,notes:document.getElementById('editNotes').value})}).then(r=>r.json()).then(d=>{if(d.success){showToast('Device updated','success');closeEditModal();loadData();}});}else{fetch('/api/update-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:id,username:document.getElementById('editUsername').value,custom_name:document.getElementById('editName').value,group:document.getElementById('editGroup').value,notes:document.getElementById('editNotes').value})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Device updated','success');closeEditModal();loadData();}});}}function openApproveModal(mac){const d=allDevices.find(x=>x.mac===mac);if(!d)return;document.getElementById('approveMAC').value=mac;document.getElementById('approveName').value=d.hostname||'';document.getElementById('approveProxy').innerHTML=allProxies.map((p,i)=>'<option value="'+i+'">'+proxyLabel(p,i)+'</option>').join('');document.getElementById('approveGroup').innerHTML=allGroups.map(g=>'<option value="'+g+'">'+g+'</option>').join('');document.getElementById('approveModal').style.display='flex';}function closeApproveModal(){document.getElementById('approveModal').style.display='none';}function confirmApprove(){const mac=document.getElementById('approveMAC').value;const name=document.getElementById('approveName').value;const proxyIdx=parseInt(document.getElementById('approveProxy').value);const group=document.getElementById('approveGroup').value;fetch('/api/ap/device/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:mac,confirmed:true,custom_name:name,proxy_index:proxyIdx,group:group})}).then(r=>r.json()).then(d=>{if(d.success){showToast('Device approved! Internet access granted.','success');closeApproveModal();loadData();}else{showToast('Failed to approve: '+(d.error||'Unknown error'),'error');}});}function loadGroups(){return fetch('/api/groups').then(r=>r.json()).then(g=>{allGroups=g;document.getElementById('groupFilter').innerHTML='<option value="">All</option>'+g.map(x=>'<option value="'+x+'">'+x+'</option>').join('');});}function loadData(){const showOffline=document.getElementById('showOffline').checked;Promise.all([fetch('/api/stats').then(r=>r.json()),fetch('/api/devices'+(showOffline?'?include_offline=true':'')).then(r=>r.json()),fetch('/api/proxies').then(r=>r.json()),fetch('/api/ap/devices').then(r=>r.json()).catch(()=>[]),loadGroups()]).then(([stats,devices,proxies,apDevices])=>{const pendingAP=(apDevices||[]).filter(d=>!d.confirmed).length;const totalAP=(apDevices||[]).length;document.getElementById('totalDevices').textContent=(stats.total_devices||0)+totalAP;document.getElementById('pendingDevices').textContent=pendingAP;document.getElementById('activeDevices').textContent=stats.active_devices||0;document.getElementById('inactiveDevices').textContent=(stats.total_devices-stats.active_devices)||0;document.getElementById('totalProxies').textContent=stats.total_proxies||0;document.getElementById('totalRequests').textContent=formatNumber(stats.total_requests||0);const legacyDevices=(devices||[]).map(d=>({...d,device_type:'legacy'}));const apMapped=(apDevices||[]).map(d=>({ip:d.ip,mac:d.mac,hostname:d.hostname,name:d.hostname||'Unknown Device',custom_name:d.custom_name||'',group:d.group||'AP',upstream_proxy:d.upstream_proxy,status:d.status,first_seen:d.first_seen,last_seen:d.last_seen,request_count:d.request_count||0,bytes_in:d.bytes_in||0,bytes_out:d.bytes_out||0,notes:d.notes||'',error_count:d.error_count||0,confirmed:d.confirmed,proxy_index:d.proxy_index,device_type:'ap'}));allDevices=[...legacyDevices,...apMapped];allProxies=proxies||[];document.getElementById('bulkProxySelect').innerHTML=allProxies.map((p,i)=>'<option value="'+i+'">'+proxyLabel(p,i)+'</option>').join('');applyFilters();});}function deleteDevice(id,username,type){const name=username||id;if(!confirm('Delete device "'+name+'"? This will remove all saved settings.')){return;}if(type==='ap'){fetch('/api/ap/device/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:id})}).then(r=>r.json()).then(d=>{if(d.success){showToast('Device deleted','success');loadData();}});}else{fetch('/api/delete-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({device_ip:id,username:username})}).then(r=>{if(r.ok)return r.json();throw new Error('Failed');}).then(d=>{if(d.ok){showToast('Device deleted','success');loadData();}}).catch(()=>showToast('Failed to delete device','error'));}}loadData();setInterval(loadData,15000);</script></body></html>`

const healthPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Proxy Health</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.health-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:20px}.proxy-card{background:#1a1a1a;border-radius:12px;padding:20px;border:1px solid #2a2a2a;border-left:4px solid #444}.proxy-card.healthy{border-left-color:#4caf50}.proxy-card.degraded{border-left-color:#ff9800}.proxy-card.unhealthy{border-left-color:#f44336}.proxy-card.unknown{border-left-color:#666}.proxy-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.proxy-name{font-size:1.2em;font-weight:bold;color:#e0e0e0}.proxy-status{padding:5px 12px;border-radius:20px;font-size:0.85em;font-weight:600}.proxy-status.healthy{background:#1a3d1a;color:#4caf50}.proxy-status.degraded{background:#3d2a1a;color:#ff9800}.proxy-status.unhealthy{background:#3d1a1a;color:#f44336}.proxy-status.unknown{background:#2a2a2a;color:#888}.proxy-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px}.proxy-stat{padding:10px;background:#121212;border-radius:8px}.proxy-stat-value{font-size:1.3em;font-weight:bold;color:#4a9eff}.proxy-stat-label{font-size:0.8em;color:#888;text-transform:uppercase}.progress-bar{height:8px;background:#2a2a2a;border-radius:4px;overflow:hidden;margin-top:10px}.progress-fill{height:100%;border-radius:4px;transition:width 0.3s}.progress-fill.good{background:#4caf50}.progress-fill.warning{background:#ff9800}.progress-fill.bad{background:#f44336}.last-error{margin-top:10px;padding:10px;background:#3d1a1a;border-radius:8px;font-size:0.85em;color:#f44336;word-break:break-all}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>💚 Proxy Health Monitor</h1><p>Real-time health status of all upstream proxies</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Total Proxies</div></div><div class="stat-card"><div class="stat-value" id="healthyProxies" style="color:#4caf50">-</div><div class="stat-label">Healthy</div></div><div class="stat-card"><div class="stat-value" id="degradedProxies" style="color:#ff9800">-</div><div class="stat-label">Degraded</div></div><div class="stat-card"><div class="stat-value" id="unhealthyProxies" style="color:#f44336">-</div><div class="stat-label">Unhealthy</div></div><div class="stat-card"><div class="stat-value" id="avgSuccessRate">-</div><div class="stat-label">Avg Success</div></div></div><div class="card"><h2>Proxy Status</h2><button class="btn btn-secondary" onclick="loadHealth()" style="float:right;margin-top:-45px">🔄 Refresh</button><div id="healthGrid" class="health-grid"><div class="loading">Loading...</div></div></div></div><script>` + baseJS + `document.getElementById('nav-health').classList.add('active');function loadHealth(){fetch('/api/proxy-health').then(r=>r.json()).then(data=>{let healthy=0,degraded=0,unhealthy=0,totalRate=0;data.forEach(p=>{if(p.status==='healthy')healthy++;else if(p.status==='degraded')degraded++;else if(p.status==='unhealthy')unhealthy++;totalRate+=p.success_rate||0;});document.getElementById('totalProxies').textContent=data.length;document.getElementById('healthyProxies').textContent=healthy;document.getElementById('degradedProxies').textContent=degraded;document.getElementById('unhealthyProxies').textContent=unhealthy;document.getElementById('avgSuccessRate').textContent=data.length?(totalRate/data.length).toFixed(1)+'%':'-';document.getElementById('healthGrid').innerHTML=data.map(p=>{const rate=p.success_rate||0;const rateClass=rate>=95?'good':rate>=80?'warning':'bad';return'<div class="proxy-card '+p.status+'"><div class="proxy-header"><span class="proxy-name">#'+(p.index+1)+' – '+p.ip_address+'</span><span class="proxy-status '+p.status+'">'+p.status.toUpperCase()+'</span></div><div class="proxy-stats"><div class="proxy-stat"><div class="proxy-stat-value">'+formatNumber(p.total_requests)+'</div><div class="proxy-stat-label">Requests</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+rate.toFixed(1)+'%</div><div class="proxy-stat-label">Success Rate</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+formatNumber(p.success_count)+'</div><div class="proxy-stat-label">Success</div></div><div class="proxy-stat"><div class="proxy-stat-value" style="color:#c62828">'+formatNumber(p.failure_count)+'</div><div class="proxy-stat-label">Failures</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+(p.device_count||0)+'</div><div class="proxy-stat-label">Registered</div></div><div class="proxy-stat"><div class="proxy-stat-value">'+p.active_devices+'</div><div class="proxy-stat-label">Active</div></div></div><div class="progress-bar"><div class="progress-fill '+rateClass+'" style="width:'+rate+'%"></div></div>'+(p.last_error?'<div class="last-error">Last error: '+p.last_error+'</div>':'')+'</div>';}).join('');});}loadHealth();setInterval(loadHealth,30000);</script></body></html>`

const diagnosticsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Diagnostics</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.diag-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px}.diag-card{background:#1a1a1a;border-radius:12px;padding:20px;border:1px solid #2a2a2a;border-left:4px solid #ccc}.diag-card.healthy{border-left-color:#4caf50}.diag-card.degraded{border-left-color:#ff9800}.diag-card.broken{border-left-color:#f44336}.diag-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.diag-name{font-size:1.1em;font-weight:bold;color:#e0e0e0}.diag-badge{padding:4px 10px;border-radius:15px;font-size:0.75em;font-weight:600;text-transform:uppercase}.diag-badge.healthy{background:#e8f5e9;color:#2e7d32}.diag-badge.degraded{background:#fff3e0;color:#e65100}.diag-badge.broken{background:#ffebee;color:#c62828}.diag-stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:10px}.diag-stat{padding:8px;background:#121212;border-radius:6px;text-align:center}.diag-stat-value{font-size:1.1em;font-weight:bold;color:#4a9eff}.diag-stat-label{font-size:0.7em;color:#888;text-transform:uppercase}.diag-issue{padding:10px;background:#fff3e0;border-radius:8px;font-size:0.85em;color:#e65100;margin-top:10px}.diag-issue.broken{background:#ffebee;color:#c62828}.device-table{width:100%;border-collapse:collapse}.device-table th,.device-table td{padding:12px;text-align:left;border-bottom:1px solid #2a2a2a}.device-table th{background:#1e1e1e;font-weight:600;color:#888;font-size:0.85em;text-transform:uppercase}.device-table tr:hover{background:#f8f9ff}.usage-bar{height:20px;background:#e0e0e0;border-radius:10px;overflow:hidden;position:relative}.usage-bar-fill{height:100%;border-radius:10px;transition:width 0.3s}.usage-bar-label{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);font-size:0.75em;font-weight:600;color:#e0e0e0}.tabs{display:flex;gap:5px;margin-bottom:20px}.tab{padding:10px 20px;background:#1e1e1e;border:none;border-radius:8px 8px 0 0;cursor:pointer;font-weight:600;color:#666}.tab.active{background:#1a1a1a;color:#4a9eff;box-shadow:0 -2px 10px rgba(0,0,0,0.05)}.tab-content{display:none}.tab-content.active{display:block}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>🔬 Diagnostics</h1><p>Proxy usage statistics and device health overview</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalProxies">-</div><div class="stat-label">Total Proxies</div></div><div class="stat-card"><div class="stat-value" id="healthyCount" style="color:#4caf50">-</div><div class="stat-label">Healthy</div></div><div class="stat-card"><div class="stat-value" id="degradedCount" style="color:#ff9800">-</div><div class="stat-label">Degraded</div></div><div class="stat-card"><div class="stat-value" id="brokenCount" style="color:#f44336">-</div><div class="stat-label">Broken</div></div><div class="stat-card"><div class="stat-value" id="successRate">-</div><div class="stat-label">Success Rate</div></div></div><div class="tabs"><button class="tab active" onclick="showTab('proxies')">🌐 Proxy Status</button><button class="tab" onclick="showTab('usage')">📊 Usage Stats</button><button class="tab" onclick="showTab('devices')">📱 Device Health</button><button class="tab" onclick="showTab('trustscore')">🛡️ IP Trust Score</button></div><div class="card"><button class="btn btn-secondary" onclick="loadDiagnostics()" style="float:right;margin-top:-10px;margin-bottom:10px">🔄 Refresh</button><div id="proxies" class="tab-content active"><h2>Proxy Status</h2><p style="color:#666;margin-bottom:15px">Proxy health based on success rates</p><div id="diagGrid" class="diag-grid"><div class="loading">Loading...</div></div></div><div id="usage" class="tab-content"><h2>Proxy Usage Statistics</h2><p style="color:#666;margin-bottom:15px">Request distribution across all proxies</p><div id="usageStats"><div class="loading">Loading...</div></div></div><div id="devices" class="tab-content"><h2>Device Health Summary</h2><p style="color:#666;margin-bottom:15px">Top devices by activity with error rates</p><div id="deviceHealth"><div class="loading">Loading...</div></div></div><div id="trustscore" class="tab-content"><h2>IP Trust Score</h2><p style="color:#666;margin-bottom:15px">Check proxy IP fraud scores from Scamalytics and IPQualityScore. Lower scores indicate more trustworthy IPs (0-100 scale).</p><div style="margin-bottom:20px"><button class="btn btn-primary" id="checkTrustBtn" onclick="checkTrustScore()">🔍 Check All Proxy IPs</button><span id="trustStatus" style="margin-left:15px;color:#666"></span></div><div id="trustSummary" style="display:none;margin-bottom:20px"><div style="display:grid;grid-template-columns:1fr 1fr;gap:20px"><div style="background:#121212;padding:15px;border-radius:10px"><h4 style="margin:0 0 10px;color:#4a9eff">📊 Scamalytics</h4><div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;text-align:center"><div><div style="font-size:1.3em;font-weight:bold;color:#4a9eff" id="scamAvg">-</div><div style="font-size:0.75em;color:#888">Avg Score</div></div><div><div style="font-size:1.3em;font-weight:bold;color:#4caf50" id="scamLow">-</div><div style="font-size:0.75em;color:#888">Low Risk</div></div><div><div style="font-size:1.3em;font-weight:bold;color:#ff9800" id="scamMed">-</div><div style="font-size:0.75em;color:#888">Medium</div></div><div><div style="font-size:1.3em;font-weight:bold;color:#f44336" id="scamHigh">-</div><div style="font-size:0.75em;color:#888">High Risk</div></div></div></div><div style="background:#121212;padding:15px;border-radius:10px"><h4 style="margin:0 0 10px;color:#9c27b0">📊 IPQualityScore</h4><div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;text-align:center"><div><div style="font-size:1.3em;font-weight:bold;color:#9c27b0" id="ipqsAvg">-</div><div style="font-size:0.75em;color:#888">Avg Score</div></div><div><div style="font-size:1.3em;font-weight:bold;color:#4caf50" id="ipqsLow">-</div><div style="font-size:0.75em;color:#888">Low Risk</div></div><div><div style="font-size:1.3em;font-weight:bold;color:#ff9800" id="ipqsMed">-</div><div style="font-size:0.75em;color:#888">Medium</div></div><div><div style="font-size:1.3em;font-weight:bold;color:#f44336" id="ipqsHigh">-</div><div style="font-size:0.75em;color:#888">High Risk</div></div></div></div></div><div style="text-align:center;margin-top:10px;font-size:0.9em;color:#666"><span id="trustTotal">0</span> proxies checked</div></div><div id="trustResults"><div style="padding:30px;text-align:center;color:#888">Click the button above to check trust scores for all proxy IPs.</div></div></div></div></div><script>` + baseJS + `document.getElementById('nav-diagnostics').classList.add('active');function checkTrustScore(){const btn=document.getElementById('checkTrustBtn');const status=document.getElementById('trustStatus');btn.disabled=true;btn.textContent='Checking...';status.textContent='Fetching scores from Scamalytics and IPQualityScore...';fetch('/api/check-blacklist').then(r=>r.json()).then(data=>{btn.disabled=false;btn.textContent='🔍 Check All Proxy IPs';status.textContent='Last checked: '+new Date().toLocaleTimeString();document.getElementById('trustSummary').style.display='block';document.getElementById('trustTotal').textContent=data.total_checked;const scam=data.scamalytics||{};const ipqs=data.ipqualityscore||{};document.getElementById('scamAvg').textContent=scam.average_score>=0?scam.average_score:'-';document.getElementById('scamLow').textContent=scam.low_risk_count||0;document.getElementById('scamMed').textContent=scam.medium_risk_count||0;document.getElementById('scamHigh').textContent=scam.high_risk_count||0;document.getElementById('ipqsAvg').textContent=ipqs.average_score>=0?ipqs.average_score:'-';document.getElementById('ipqsLow').textContent=ipqs.low_risk_count||0;document.getElementById('ipqsMed').textContent=ipqs.medium_risk_count||0;document.getElementById('ipqsHigh').textContent=ipqs.high_risk_count||0;if(!data.results||!data.results.length){document.getElementById('trustResults').innerHTML='<div style="padding:30px;text-align:center;color:#888">No proxy IPs to check.</div>';return;}function getScoreDisplay(src){if(!src||!src.available)return{score:'-',color:'#666',badge:'background:#1e1e1e;color:#666',risk:'N/A',error:src?src.error:''};const score=src.score;const risk=src.risk||'unknown';const color=risk==='low'?'#4caf50':risk==='medium'?'#ff9800':risk==='high'||risk==='very high'?'#c62828':'#666';const badge=risk==='low'?'background:#e8f5e9;color:#2e7d32':risk==='medium'?'background:#fff3e0;color:#e65100':risk==='high'||risk==='very high'?'background:#ffebee;color:#c62828':'background:#1e1e1e;color:#666';return{score:score,color:color,badge:badge,risk:risk.toUpperCase(),error:''};}document.getElementById('trustResults').innerHTML='<table class="device-table"><thead><tr><th>Proxy</th><th>IP Address</th><th style="text-align:center">Scamalytics</th><th style="text-align:center">IPQualityScore</th></tr></thead><tbody>'+data.results.map(r=>{const s=getScoreDisplay(r.scamalytics);const i=getScoreDisplay(r.ipqualityscore);return'<tr><td><strong>'+r.name+'</strong></td><td style="font-family:monospace">'+r.ip_address+'</td><td style="text-align:center"><div style="font-weight:bold;font-size:1.3em;color:'+s.color+'">'+s.score+'</div><span style="padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:600;'+s.badge+'">'+s.risk+'</span>'+(r.scamalytics&&r.scamalytics.error?' <div style="color:#999;font-size:0.7em;margin-top:3px">'+r.scamalytics.error+'</div>':'')+'</td><td style="text-align:center"><div style="font-weight:bold;font-size:1.3em;color:'+i.color+'">'+i.score+'</div><span style="padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:600;'+i.badge+'">'+i.risk+'</span>'+(r.ipqualityscore&&r.ipqualityscore.error?' <div style="color:#999;font-size:0.7em;margin-top:3px">'+r.ipqualityscore.error+'</div>':'')+'</td></tr>';}).join('')+'</tbody></table><p style="margin-top:15px;color:#888;font-size:0.85em">Scores: 0-25 Low Risk | 26-50 Medium | 51-75 High | 76-100 Very High (lower is better)</p>';}).catch(e=>{btn.disabled=false;btn.textContent='🔍 Check All Proxy IPs';status.textContent='Error: '+e.message;});}function showTab(id){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));document.getElementById(id).classList.add('active');event.target.classList.add('active');}function loadDiagnostics(){fetch('/api/diagnostics').then(r=>r.json()).then(data=>{const s=data.summary;document.getElementById('totalProxies').textContent=s.total_proxies;document.getElementById('healthyCount').textContent=s.healthy_proxies;document.getElementById('degradedCount').textContent=s.degraded_proxies;document.getElementById('brokenCount').textContent=s.broken_proxies;document.getElementById('successRate').textContent=s.overall_success_rate.toFixed(1)+'%';const diagGrid=document.getElementById('diagGrid');if(!data.proxies.length){diagGrid.innerHTML='<div class="loading">No proxy data available yet.</div>';return;}diagGrid.innerHTML=data.proxies.map(p=>{const issueClass=p.issue_type==='none'?'healthy':p.issue_type;const badgeText=p.issue_type==='none'?'Healthy':p.issue_type.charAt(0).toUpperCase()+p.issue_type.slice(1);return'<div class="diag-card '+issueClass+'"><div class="diag-header"><span class="diag-name">'+(p.name||'Proxy #'+(p.index+1))+'</span><span class="diag-badge '+issueClass+'">'+badgeText+'</span></div><div style="color:#888;font-size:0.85em;margin-bottom:10px">'+p.ip_address+'</div><div class="diag-stats"><div class="diag-stat"><div class="diag-stat-value">'+formatNumber(p.total_requests)+'</div><div class="diag-stat-label">Requests</div></div><div class="diag-stat"><div class="diag-stat-value">'+p.success_rate.toFixed(1)+'%</div><div class="diag-stat-label">Success</div></div><div class="diag-stat"><div class="diag-stat-value">'+(p.device_count||0)+'</div><div class="diag-stat-label">Registered</div></div></div>'+(p.issue_details?'<div class="diag-issue '+(p.issue_type==='broken'?'broken':'')+'">'+p.issue_details+'</div>':'')+'</div>';}).join('');const maxReqs=Math.max(...data.proxies.map(p=>p.total_requests));document.getElementById('usageStats').innerHTML='<table class="device-table"><thead><tr><th>Proxy</th><th>Requests</th><th>Usage</th><th>Data In</th><th>Data Out</th></tr></thead><tbody>'+data.proxies.map(p=>{const pct=maxReqs>0?(p.total_requests/maxReqs*100):0;const color=pct>66?'#4caf50':pct>33?'#ff9800':'#f44336';return'<tr><td><strong>'+(p.name||'Proxy #'+(p.index+1))+'</strong><br><span style="color:#888;font-size:0.85em">'+p.ip_address+'</span></td><td>'+formatNumber(p.total_requests)+'</td><td style="width:200px"><div class="usage-bar"><div class="usage-bar-fill" style="width:'+pct+'%;background:'+color+'"></div><div class="usage-bar-label">'+pct.toFixed(0)+'%</div></div></td><td>'+formatBytes(p.bytes_in)+'</td><td>'+formatBytes(p.bytes_out)+'</td></tr>';}).join('')+'</tbody></table>';const devices=data.devices.slice(0,20);document.getElementById('deviceHealth').innerHTML=devices.length?'<table class="device-table"><thead><tr><th>Device</th><th>Proxy</th><th>Requests</th><th>Errors</th><th>Error Rate</th><th>Data</th><th>Status</th></tr></thead><tbody>'+devices.map(d=>{const name=d.name||d.username||d.ip;const errColor=d.error_rate>5?'#c62828':d.error_rate>1?'#e65100':'#666';return'<tr><td><strong>'+name+'</strong><br><span style="color:#888;font-size:0.85em">'+d.ip+'</span></td><td>'+(d.proxy_name||'-')+'</td><td>'+formatNumber(d.request_count)+'</td><td style="color:'+errColor+'">'+formatNumber(d.error_count)+'</td><td style="color:'+errColor+'">'+d.error_rate.toFixed(2)+'%</td><td>↓'+formatBytes(d.bytes_in)+' ↑'+formatBytes(d.bytes_out)+'</td><td><span style="color:'+(d.is_active?'#4caf50':'#999')+'">'+(d.is_active?'● Active':'○ Inactive')+'</span></td></tr>';}).join('')+'</tbody></table>':'<div class="loading">No device data available.</div>';});}loadDiagnostics();setInterval(loadDiagnostics,30000);</script></body></html>`

const analyticsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Analytics</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.chart-container{background:#1a1a1a;border-radius:12px;padding:25px;border:1px solid #2a2a2a;margin-bottom:20px;overflow:visible}.chart-container h2{margin-bottom:20px}.chart{width:100%;position:relative}.chart-bars{display:flex;align-items:flex-end;height:200px;gap:2px;padding:0 10px;border-bottom:2px solid #e0e0e0}.chart-bar{flex:1;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);border-radius:4px 4px 0 0;min-width:2px;max-width:40px;position:relative;transition:height 0.3s}.chart-bar:hover{opacity:0.8}.chart-bar .tooltip{position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#333;color:white;padding:5px 10px;border-radius:4px;font-size:0.8em;white-space:nowrap;opacity:0;transition:opacity 0.2s;pointer-events:none;z-index:10}.chart-bar:hover .tooltip{opacity:1}.chart-labels{display:flex;padding:15px 10px 5px;justify-content:space-between}.chart-label{font-size:0.85em;color:#888;font-weight:500}.time-range{text-align:center;color:#888;font-size:0.9em;margin-top:5px}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>📊 Traffic Analytics</h1><p>Historical traffic data and trends</p></div><div class="stats-grid"><div class="stat-card"><div class="stat-value" id="totalData">-</div><div class="stat-label">Total Data</div></div><div class="stat-card"><div class="stat-value" id="totalReqs">-</div><div class="stat-label">Total Requests</div></div><div class="stat-card"><div class="stat-value" id="peakDevices">-</div><div class="stat-label">Peak Devices</div></div><div class="stat-card"><div class="stat-value" id="errorRate">-</div><div class="stat-label">Error Rate</div></div></div><div class="chart-container"><h2>📈 Traffic Over Time</h2><button class="btn btn-secondary" onclick="loadAnalytics()" style="float:right;margin-top:-45px">🔄 Refresh</button><div class="chart"><div class="chart-bars" id="trafficBars"></div><div class="chart-labels" id="trafficLabels"></div><div class="time-range" id="trafficRange"></div></div></div><div class="chart-container"><h2>📊 Active Devices Over Time</h2><div class="chart"><div class="chart-bars" id="deviceBars"></div><div class="chart-labels" id="deviceLabels"></div><div class="time-range" id="deviceRange"></div></div></div></div><script>` + baseJS + `document.getElementById('nav-analytics').classList.add('active');function formatDateTime(d){const date=new Date(d);const day=date.getDate();const month=date.toLocaleString('default',{month:'short'});const time=date.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});return month+' '+day+', '+time;}function loadAnalytics(){fetch('/api/traffic-history').then(r=>r.json()).then(data=>{if(!data||!data.length){document.getElementById('trafficBars').innerHTML='<div class="loading">No data yet. Traffic data is collected every 5 minutes.</div>';return;}const totalBytes=data.reduce((a,d)=>a+(d.total_bytes_in||0)+(d.total_bytes_out||0),0);const totalReqs=data.length>0?data[data.length-1].total_requests:0;const peakDevices=Math.max(...data.map(d=>d.active_devices||0));const totalErrors=data.length>0?data[data.length-1].error_count:0;const errorRate=totalReqs>0?((totalErrors/totalReqs)*100).toFixed(2)+'%':'0%';document.getElementById('totalData').textContent=formatBytes(totalBytes);document.getElementById('totalReqs').textContent=formatNumber(totalReqs);document.getElementById('peakDevices').textContent=peakDevices;document.getElementById('errorRate').textContent=errorRate;const maxBytes=Math.max(...data.map(d=>(d.total_bytes_in||0)+(d.total_bytes_out||0)));const maxDevices=Math.max(...data.map(d=>d.active_devices||0));document.getElementById('trafficBars').innerHTML=data.map(d=>{const bytes=(d.total_bytes_in||0)+(d.total_bytes_out||0);const h=maxBytes>0?(bytes/maxBytes*180):5;return'<div class="chart-bar" style="height:'+h+'px"><span class="tooltip">'+formatDateTime(d.timestamp)+'<br>'+formatBytes(bytes)+'</span></div>';}).join('');const first=new Date(data[0].timestamp);const last=new Date(data[data.length-1].timestamp);document.getElementById('trafficLabels').innerHTML='<span class="chart-label">'+formatDateTime(first)+'</span><span class="chart-label">'+formatDateTime(last)+'</span>';document.getElementById('trafficRange').textContent='Showing '+data.length+' data points over '+(Math.round((last-first)/(1000*60*60)))+' hours';document.getElementById('deviceBars').innerHTML=data.map(d=>{const h=maxDevices>0?(d.active_devices/maxDevices*180):5;return'<div class="chart-bar" style="height:'+h+'px;background:linear-gradient(135deg,#4caf50 0%,#2e7d32 100%)"><span class="tooltip">'+formatDateTime(d.timestamp)+'<br>'+d.active_devices+' devices</span></div>';}).join('');document.getElementById('deviceLabels').innerHTML='<span class="chart-label">'+formatDateTime(first)+'</span><span class="chart-label">'+formatDateTime(last)+'</span>';document.getElementById('deviceRange').textContent='Peak: '+peakDevices+' devices';});}loadAnalytics();setInterval(loadAnalytics,60000);</script></body></html>`

const activityPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Activity Log</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.activity-container{background:#1a1a1a;border-radius:12px;border:1px solid #2a2a2a;overflow:hidden}.activity-header{background:#333;color:white;padding:15px 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}.activity-header h2{margin:0;font-size:1.1em}.filters{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.filters select,.filters input{padding:8px 12px;border:none;border-radius:6px;font-size:0.9em;background:rgba(255,255,255,0.9)}.activity-content{height:600px;overflow-y:auto;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;font-size:0.85em}.log-entry{padding:10px 20px;border-bottom:1px solid #f0f0f0;display:grid;grid-template-columns:140px 80px 120px 120px 1fr;gap:15px;align-items:center}.log-entry:nth-child(odd){background:#fafafa}.log-entry:hover{background:#f0f5ff}.log-time{color:#888;white-space:nowrap;font-size:0.9em}.log-level{font-weight:600;text-transform:uppercase;font-size:0.75em;padding:3px 8px;border-radius:4px;text-align:center}.log-level.info{background:#e3f2fd;color:#1976d2}.log-level.error{background:#ffebee;color:#c62828}.log-level.warn,.log-level.warning{background:#fff3e0;color:#e65100}.log-category{font-size:0.8em;color:#666;background:#1e1e1e;padding:3px 8px;border-radius:4px;text-align:center}.log-device{font-size:0.85em;color:#4a9eff;font-weight:500}.log-msg{color:#e0e0e0;word-break:break-word}.auto-refresh{display:flex;align-items:center;gap:8px;font-size:0.9em;color:white}.auto-refresh input{width:18px;height:18px;cursor:pointer}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>📋 Activity Log</h1><p>Detailed device and system activity log with filtering</p></div><div class="stats-grid"><div class="stat-card" onclick="filterLevel('')" style="cursor:pointer"><div class="stat-value" id="totalLogs">-</div><div class="stat-label">Total Logs</div></div><div class="stat-card" onclick="filterLevel('info')" style="cursor:pointer"><div class="stat-value" id="infoLogs" style="color:#1976d2">-</div><div class="stat-label">Info</div></div><div class="stat-card" onclick="filterLevel('warn')" style="cursor:pointer"><div class="stat-value" id="warnLogs" style="color:#e65100">-</div><div class="stat-label">Warnings</div></div><div class="stat-card" onclick="filterLevel('error')" style="cursor:pointer"><div class="stat-value" id="errorLogs" style="color:#c62828">-</div><div class="stat-label">Errors</div></div></div><div class="activity-container"><div class="activity-header"><h2>📋 Live Activity Feed</h2><div class="filters"><select id="filterCategory" onchange="loadActivity()"><option value="">All Categories</option><option value="connection">Connection</option><option value="session">Session</option><option value="config">Config</option><option value="proxy">Proxy</option><option value="auth">Auth</option><option value="error">Error</option></select><select id="filterLevelSelect" onchange="loadActivity()"><option value="">All Levels</option><option value="info">Info</option><option value="warn">Warning</option><option value="error">Error</option></select><input type="text" id="filterDevice" placeholder="Filter by device/user..." style="width:180px" onkeyup="debounceLoad()"><button class="btn btn-secondary" onclick="loadActivity()" style="padding:8px 15px;font-size:0.85em">🔄 Refresh</button></div><label class="auto-refresh" style="margin-right:10px"><input type="checkbox" id="registeredOnly" onchange="loadActivity()"> Registered only</label><label class="auto-refresh"><input type="checkbox" id="autoRefresh" checked> Auto-refresh</label></div><div class="activity-content" id="activityContent"><div class="loading">Loading activity log...</div></div></div></div><script>` + baseJS + `document.getElementById('nav-activity').classList.add('active');let debounceTimer;function debounceLoad(){clearTimeout(debounceTimer);debounceTimer=setTimeout(loadActivity,300);}function filterLevel(level){document.getElementById('filterLevelSelect').value=level;loadActivity();}function loadActivity(){const category=document.getElementById('filterCategory').value;const level=document.getElementById('filterLevelSelect').value;const device=document.getElementById('filterDevice').value.trim();const registeredOnly=document.getElementById('registeredOnly').checked;let url='/api/activity-log?limit=500';if(category)url+='&category='+encodeURIComponent(category);if(level)url+='&level='+encodeURIComponent(level);if(device)url+='&device='+encodeURIComponent(device);if(registeredOnly)url+='&registered_only=true';fetch(url).then(r=>r.json()).then(data=>{document.getElementById('totalLogs').textContent=data.total_count||0;document.getElementById('infoLogs').textContent=data.info_count||0;document.getElementById('warnLogs').textContent=data.warn_count||0;document.getElementById('errorLogs').textContent=data.error_count||0;const container=document.getElementById('activityContent');if(!data.logs||!data.logs.length){container.innerHTML='<div style="padding:40px;text-align:center;color:#666">No activity logs yet. Device activity will appear here.</div>';return;}container.innerHTML=data.logs.slice().reverse().map(log=>{const time=new Date(log.timestamp).toLocaleString();const deviceInfo=log.username||log.device_name||log.device_ip||'-';const category=log.category||'-';return'<div class="log-entry"><span class="log-time">'+time+'</span><span class="log-level '+log.level+'">'+log.level+'</span><span class="log-category">'+category+'</span><span class="log-device" title="'+(log.device_ip||'')+'">'+deviceInfo+'</span><span class="log-msg">'+escapeHtml(log.message)+'</span></div>';}).join('');if(document.getElementById('autoRefresh').checked){container.scrollTop=0;}});}function escapeHtml(t){if(!t)return'';const d=document.createElement('div');d.textContent=t;return d.innerHTML;}loadActivity();setInterval(()=>{if(document.getElementById('autoRefresh').checked)loadActivity();},5000);</script></body></html>`

const settingsPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Settings</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.settings-section{background:#1a1a1a;border-radius:12px;padding:25px;border:1px solid #2a2a2a;margin-bottom:20px}.settings-section h2{margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #f0f0f0}.form-group{margin-bottom:20px}.form-group label{display:block;font-weight:600;color:#e0e0e0;margin-bottom:8px}.form-group input{width:100%;max-width:400px;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:1em}.form-group input:focus{outline:none;border-color:#4a9eff}.form-group small{display:block;color:#666;margin-top:5px;font-size:0.85em}.success-msg{background:#e8f5e9;color:#2e7d32;padding:12px;border-radius:8px;margin-bottom:20px;display:none}.success-msg.show{display:block}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>⚙️ Settings</h1><p>Configure your Lumier Dynamics system</p></div><div class="settings-section"><h2>🔐 Change Password</h2><div class="success-msg" id="pwSuccess">Password changed successfully!</div><form onsubmit="return changePassword(event)"><div class="form-group"><label>Current Password</label><input type="password" id="oldPassword" required></div><div class="form-group"><label>New Password</label><input type="password" id="newPassword" required><small>Choose a strong password with at least 8 characters</small></div><div class="form-group"><label>Confirm New Password</label><input type="password" id="confirmPassword" required></div><button type="submit" class="btn btn-primary">Change Password</button></form></div><div class="settings-section"><h2>📱 Device Groups</h2><p style="margin-bottom:15px;color:#666">Manage device groups for better organization</p><div id="groupsList" style="margin-bottom:15px"></div><div style="display:flex;gap:10px"><input type="text" id="newGroupName" placeholder="New group name..." style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;flex:1;max-width:300px"><button class="btn btn-primary" onclick="addGroup()">Add Group</button></div></div><div class="settings-section"><h2>🌐 Proxy Management</h2><p style="margin-bottom:15px;color:#666">Manage and organize upstream SOCKS5 proxies</p><table id="proxyTable" style="width:100%;border-collapse:collapse;margin-bottom:20px"><thead><tr style="background:#1e1e1e"><th style="padding:12px;text-align:left;border-bottom:2px solid #e0e0e0">#</th><th style="padding:12px;text-align:left;border-bottom:2px solid #e0e0e0">Name</th><th style="padding:12px;text-align:left;border-bottom:2px solid #e0e0e0">IP Address</th><th style="padding:12px;text-align:center;border-bottom:2px solid #e0e0e0">Order</th><th style="padding:12px;text-align:center;border-bottom:2px solid #e0e0e0">Actions</th></tr></thead><tbody id="proxyTableBody"></tbody></table><div style="display:flex;gap:10px;flex-wrap:wrap"><input type="text" id="newProxyString" placeholder="host:port:username:password" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;flex:1;min-width:300px;max-width:500px"><button class="btn btn-primary" onclick="addProxy()">Add Proxy</button></div><p style="margin-top:10px;color:#888;font-size:0.85em">Format: host:port:username:password (e.g., proxy.example.com:1080:user:pass)</p><div style="margin-top:20px;padding-top:20px;border-top:1px solid #eee"><h3 style="margin-bottom:15px;font-size:1.1em">📥 Bulk Import Proxies</h3><p style="margin-bottom:10px;color:#666;font-size:0.9em">Paste multiple proxies (one per line) in format: host:port:username:password</p><textarea id="bulkProxies" placeholder="brd.superproxy.io:22228:brd-customer-xxx-ip-1.2.3.4:password&#10;brd.superproxy.io:22228:brd-customer-xxx-ip-5.6.7.8:password&#10;..." style="width:100%;height:150px;padding:10px;border:2px solid #e0e0e0;border-radius:8px;font-family:monospace;font-size:0.9em"></textarea><div style="margin-top:10px;display:flex;gap:10px;align-items:center"><button class="btn btn-primary" onclick="bulkImportProxies()">Import Proxies</button><span id="bulkImportResult" style="color:#666;font-size:0.9em"></span></div></div></div><div class="settings-section"><h2>👤 Supervisor Management</h2><p style="margin-bottom:15px;color:#666">Manage supervisor accounts for the Android app (used for Change Proxy authentication)</p><div style="margin-bottom:20px"><h3 style="font-size:1em;margin-bottom:10px">🔐 Admin Password (for Register Device)</h3><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><input type="password" id="adminPassword" placeholder="Admin password" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:250px"><button class="btn btn-primary" onclick="updateAdminPassword()">Update Admin Password</button><button class="btn btn-secondary" onclick="togglePasswordVisibility('adminPassword')" style="padding:10px">👁️</button></div></div><div style="margin-bottom:15px"><h3 style="font-size:1em;margin-bottom:10px">👥 Supervisors (for Change Proxy)</h3><div id="supervisorsList" style="margin-bottom:15px"></div><div style="display:flex;gap:10px;flex-wrap:wrap"><input type="text" id="newSupervisorName" placeholder="Name" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:150px"><input type="password" id="newSupervisorPassword" placeholder="Password" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:200px"><button class="btn btn-primary" onclick="addSupervisor()">Add Supervisor</button></div></div></div><div class="settings-section"><h2>⏱️ Session Settings</h2><p style="margin-bottom:15px;color:#666">Configure session timeout for device connections. Devices must re-confirm their connection after the timeout expires.</p><div style="display:flex;gap:15px;align-items:center;flex-wrap:wrap;margin-bottom:15px"><div style="display:flex;align-items:center;gap:10px"><label style="font-weight:600;color:#e0e0e0">Session Timeout:</label><input type="number" id="sessionTimeout" min="1" max="48" value="2" style="padding:10px;border:2px solid #e0e0e0;border-radius:8px;width:80px;text-align:center;font-weight:600"><span style="color:#666">hours</span></div><button class="btn btn-primary" onclick="saveSessionSettings()">Save Settings</button></div><p style="color:#888;font-size:0.85em">Range: 1-48 hours. Default: 2 hours. Devices will need to confirm their proxy connection again after this time.</p></div><div class="settings-section"><h2>ℹ️ System Information</h2><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px"><div style="background:#121212;padding:15px;border-radius:8px"><strong>Version:</strong> 3.0.0</div><div style="background:#121212;padding:15px;border-radius:8px"><strong>Server IP:</strong> <span id="sysServerIP">...</span></div><div style="background:#121212;padding:15px;border-radius:8px"><strong>Proxy Port:</strong> 8888</div><div style="background:#121212;padding:15px;border-radius:8px"><strong>Dashboard Port:</strong> 8080</div></div></div></div><script>` + baseJS + `document.getElementById('nav-settings').classList.add('active');fetch('/api/server-ip').then(r=>r.text()).then(ip=>document.getElementById('sysServerIP').textContent=ip);function loadGroups(){fetch('/api/groups').then(r=>r.json()).then(groups=>{document.getElementById('groupsList').innerHTML=groups.map(g=>{const isDefault=g==='Default';return'<span style="display:inline-flex;align-items:center;gap:8px;background:#e3f2fd;color:#1976d2;padding:8px 15px;border-radius:20px;margin:5px;font-weight:500">'+g+(isDefault?'':' <button onclick="deleteGroup(\''+g+'\')" style="background:#ef5350;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:14px;line-height:1;display:flex;align-items:center;justify-content:center" title="Delete group">&times;</button>')+'</span>';}).join('');});}loadGroups();function deleteGroup(name){if(!confirm('Delete group "'+name+'"? Devices in this group will be moved to Default.')){return;}fetch('/api/delete-group',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_name:name})}).then(r=>{if(r.ok)return r.json();throw new Error('Failed to delete');}).then(d=>{if(d.ok){showToast('Group deleted','success');loadGroups();}}).catch(()=>showToast('Failed to delete group','error'));}function addGroup(){const name=document.getElementById('newGroupName').value.trim();if(!name){showToast('Please enter a group name','error');return;}fetch('/api/add-group',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast(d.added?'Group added':'Group already exists',d.added?'success':'');document.getElementById('newGroupName').value='';loadGroups();}});}function changePassword(e){e.preventDefault();const oldPw=document.getElementById('oldPassword').value;const newPw=document.getElementById('newPassword').value;const confirmPw=document.getElementById('confirmPassword').value;if(newPw!==confirmPw){showToast('Passwords do not match','error');return false;}if(newPw.length<6){showToast('Password must be at least 6 characters','error');return false;}fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_password:oldPw,new_password:newPw})}).then(r=>{if(r.ok){document.getElementById('pwSuccess').classList.add('show');document.getElementById('oldPassword').value='';document.getElementById('newPassword').value='';document.getElementById('confirmPassword').value='';setTimeout(()=>document.getElementById('pwSuccess').classList.remove('show'),3000);}else{showToast('Current password is incorrect','error');}});return false;}let allProxies=[];function loadProxies(){fetch('/api/proxies').then(r=>r.json()).then(proxies=>{allProxies=proxies;const tbody=document.getElementById('proxyTableBody');if(!proxies.length){tbody.innerHTML='<tr><td colspan="5" style="padding:20px;text-align:center;color:#666">No proxies configured. Add your first proxy below.</td></tr>';return;}tbody.innerHTML=proxies.map((p,i)=>{let ip=p.user&&p.user.includes('ip-')?p.user.split('ip-')[1]:p.host;const name=p.custom_name||'SG'+String(i+1).padStart(2,'0');return'<tr style="border-bottom:1px solid #2a2a2a"><td style="padding:12px;font-weight:600;color:#4a9eff">'+(i+1)+'</td><td style="padding:12px"><input type="text" value="'+escapeAttr(name)+'" style="padding:8px 12px;border:2px solid #e0e0e0;border-radius:6px;font-weight:600;width:100px" onchange="updateProxyName('+i+',this.value)" placeholder="SG'+String(i+1).padStart(2,'0')+'"></td><td style="padding:12px;font-family:monospace;color:#e0e0e0">'+ip+'</td><td style="padding:12px;text-align:center"><button onclick="moveProxy('+i+',-1)" style="background:#e3f2fd;border:none;border-radius:4px;padding:6px 10px;cursor:pointer;margin-right:5px" '+(i===0?'disabled':'')+' title="Move Up">↑</button><button onclick="moveProxy('+i+',1)" style="background:#e3f2fd;border:none;border-radius:4px;padding:6px 10px;cursor:pointer" '+(i===proxies.length-1?'disabled':'')+' title="Move Down">↓</button></td><td style="padding:12px;text-align:center"><button onclick="deleteProxy('+i+')" style="background:#ef5350;color:white;border:none;border-radius:6px;padding:6px 12px;cursor:pointer" title="Delete">🗑️</button></td></tr>';}).join('');});}function escapeAttr(s){return s.replace(/"/g,'&quot;');}function updateProxyName(idx,name){fetch('/api/update-proxy-name',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({index:idx,name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxy renamed to '+name,'success');}else{showToast('Failed to rename','error');}});}function moveProxy(idx,dir){const newOrder=allProxies.map((_,i)=>i);const targetIdx=idx+dir;if(targetIdx<0||targetIdx>=allProxies.length)return;[newOrder[idx],newOrder[targetIdx]]=[newOrder[targetIdx],newOrder[idx]];fetch('/api/reorder-proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:newOrder})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Proxies reordered','success');loadProxies();}else{showToast('Failed to reorder','error');}});}loadProxies();function addProxy(){const proxy=document.getElementById('newProxyString').value.trim();if(!proxy){showToast('Please enter a proxy string','error');return;}fetch('/api/add-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxy_string:proxy})}).then(r=>{if(!r.ok)return r.text().then(t=>{throw new Error(t);});return r.json();}).then(d=>{if(d.ok){showToast(d.added?'Proxy added':'Proxy already exists',d.added?'success':'');document.getElementById('newProxyString').value='';loadProxies();}}).catch(e=>showToast(e.message||'Failed to add proxy','error'));}function deleteProxy(idx){if(!confirm('Delete this proxy? Make sure no devices are using it.')){return;}fetch('/api/delete-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxy_index:idx})}).then(r=>{if(!r.ok)return r.text().then(t=>{throw new Error(t);});return r.json();}).then(d=>{if(d.ok){showToast('Proxy deleted','success');loadProxies();}}).catch(e=>showToast(e.message||'Failed to delete proxy','error'));}function bulkImportProxies(){const proxies=document.getElementById('bulkProxies').value.trim();if(!proxies){showToast('Please paste proxy strings','error');return;}document.getElementById('bulkImportResult').textContent='Importing...';fetch('/api/bulk-import-proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxies:proxies})}).then(r=>r.json()).then(d=>{if(d.success){const msg='Added '+d.added+' proxies'+(d.skipped>0?', skipped '+d.skipped:'');document.getElementById('bulkImportResult').innerHTML='<span style="color:#4caf50">✓ '+msg+'</span>';showToast(msg,'success');document.getElementById('bulkProxies').value='';loadProxies();}else{document.getElementById('bulkImportResult').innerHTML='<span style="color:#c62828">✗ Import failed</span>';showToast('Import failed','error');}}).catch(e=>{document.getElementById('bulkImportResult').innerHTML='<span style="color:#c62828">✗ Error</span>';showToast('Import error','error');});}function loadSupervisors(){fetch('/api/supervisors').then(r=>r.json()).then(data=>{document.getElementById('adminPassword').value=data.admin_password||'';const list=document.getElementById('supervisorsList');if(!data.supervisors||!data.supervisors.length){list.innerHTML='<p style="color:#666">No supervisors configured.</p>';return;}list.innerHTML=data.supervisors.map(s=>'<div style="display:inline-flex;align-items:center;gap:8px;background:#e8f5e9;color:#2e7d32;padding:8px 15px;border-radius:20px;margin:5px;font-weight:500">'+s.name+' <button onclick="editSupervisor(\''+s.name+'\',\''+s.password+'\')" style="background:#1976d2;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:12px" title="Edit">✎</button> <button onclick="deleteSupervisor(\''+s.name+'\')" style="background:#ef5350;color:white;border:none;border-radius:50%;width:20px;height:20px;cursor:pointer;font-size:14px;line-height:1" title="Delete">&times;</button></div>').join('');});}loadSupervisors();function togglePasswordVisibility(id){const input=document.getElementById(id);input.type=input.type==='password'?'text':'password';}function updateAdminPassword(){const pw=document.getElementById('adminPassword').value.trim();if(!pw){showToast('Please enter a password','error');return;}fetch('/api/admin-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Admin password updated','success');}else{showToast('Failed to update','error');}});}function addSupervisor(){const name=document.getElementById('newSupervisorName').value.trim();const pw=document.getElementById('newSupervisorPassword').value.trim();if(!name||!pw){showToast('Name and password required','error');return;}fetch('/api/add-supervisor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,password:pw})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Supervisor added','success');document.getElementById('newSupervisorName').value='';document.getElementById('newSupervisorPassword').value='';loadSupervisors();}else{showToast(d.message||'Failed to add','error');}});}function editSupervisor(name,pw){const newName=prompt('Supervisor name:',name);if(!newName)return;const newPw=prompt('Password:',pw);if(!newPw)return;fetch('/api/update-supervisor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_name:name,name:newName,password:newPw})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Supervisor updated','success');loadSupervisors();}else{showToast(d.message||'Failed to update','error');}});}function deleteSupervisor(name){if(!confirm('Delete supervisor "'+name+'"?'))return;fetch('/api/delete-supervisor',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Supervisor deleted','success');loadSupervisors();}else{showToast(d.message||'Failed to delete','error');}});}function loadSessionSettings(){fetch('/api/session-settings').then(r=>r.json()).then(d=>{document.getElementById('sessionTimeout').value=d.session_timeout_hours||2;});}loadSessionSettings();function saveSessionSettings(){const timeout=parseInt(document.getElementById('sessionTimeout').value)||2;fetch('/api/session-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_timeout_hours:timeout})}).then(r=>r.json()).then(d=>{if(d.ok){showToast('Session settings saved','success');loadSessionSettings();}else{showToast('Failed to save settings','error');}});}</script></body></html>`

const monitoringPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Network Monitor</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.monitor-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin-bottom:25px}.monitor-stat{background:#1a1a1a;padding:20px;border-radius:12px;border:1px solid #2a2a2a;text-align:center}.monitor-stat .value{font-size:2em;font-weight:bold}.monitor-stat .label{color:#666;font-size:0.85em;text-transform:uppercase;margin-top:5px}.devices-section{background:#1a1a1a;border-radius:12px;border:1px solid #2a2a2a;overflow:hidden;margin-bottom:20px}.devices-header{background:#667eea;color:white;padding:15px 20px;display:flex;justify-content:space-between;align-items:center}.devices-header h2{margin:0;font-size:1.1em}.device-card{padding:15px 20px;border-bottom:1px solid #f0f0f0;display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:15px;align-items:center;cursor:pointer;transition:background 0.2s}.device-card:hover{background:#f8f9ff}.device-card.active{border-left:4px solid #4caf50}.device-card.inactive{border-left:4px solid #ccc}.device-info{display:flex;flex-direction:column;gap:3px}.device-name{font-weight:600;color:#e0e0e0}.device-ip{font-size:0.85em;color:#888;font-family:monospace}.device-status{display:flex;flex-direction:column;gap:3px}.status-indicator{font-size:0.85em;display:flex;align-items:center;gap:6px}.status-dot{width:8px;height:8px;border-radius:50%}.device-data{text-align:right}.data-value{font-weight:600;color:#4a9eff}.data-label{font-size:0.75em;color:#888}.device-expiry{text-align:right}.expiry-time{font-weight:600;font-size:1.1em}.expiry-label{font-size:0.75em;color:#888}.connections-modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:1000;align-items:center;justify-content:center}.connections-modal.show{display:flex}.modal-content{background:#1a1a1a;border-radius:12px;width:90%;max-width:700px;max-height:80vh;overflow:hidden}.modal-header{background:#333;color:white;padding:15px 20px;display:flex;justify-content:space-between;align-items:center}.modal-header h3{margin:0}.modal-close{background:none;border:none;color:white;font-size:1.5em;cursor:pointer;padding:0 10px}.modal-body{padding:20px;max-height:60vh;overflow-y:auto}.conn-table{width:100%;border-collapse:collapse}.conn-table th,.conn-table td{padding:10px;text-align:left;border-bottom:1px solid #2a2a2a}.conn-table th{background:#1e1e1e;font-weight:600;color:#888;font-size:0.85em}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>🖥️ Network Monitor</h1><p>Real-time network activity and device overview</p></div><div class="monitor-stats"><div class="monitor-stat"><div class="value" style="color:#4a9eff" id="totalDevices">-</div><div class="label">Online Devices</div></div><div class="monitor-stat"><div class="value" style="color:#4caf50" id="activeNow">-</div><div class="label">Active Now</div></div><div class="monitor-stat"><div class="value" style="color:#2196F3" id="totalDataIn">-</div><div class="label">Data In</div></div><div class="monitor-stat"><div class="value" style="color:#9c27b0" id="totalDataOut">-</div><div class="label">Data Out</div></div><div class="monitor-stat"><div class="value" style="color:#ff9800" id="uptimeValue">-</div><div class="label">Uptime</div></div></div><div class="devices-section"><div class="devices-header"><h2>📱 Device Activity (Last 30 min)</h2><button class="btn btn-secondary" onclick="loadOverview()" style="padding:6px 12px;font-size:0.85em">🔄 Refresh</button></div><div id="devicesList"><div style="padding:40px;text-align:center;color:#666">Loading devices...</div></div></div></div><div class="connections-modal" id="connModal" onclick="if(event.target===this)closeModal()"><div class="modal-content"><div class="modal-header"><h3 id="modalTitle">Device Connections</h3><button class="modal-close" onclick="closeModal()">&times;</button></div><div class="modal-body"><div id="connList">Loading...</div></div></div></div><script>` + baseJS + `document.getElementById('nav-monitoring').classList.add('active');function loadOverview(){fetch('/api/network-overview').then(r=>r.json()).then(data=>{document.getElementById('totalDevices').textContent=data.total_devices;document.getElementById('activeNow').textContent=data.active_count;document.getElementById('totalDataIn').textContent=formatBytes(data.total_bytes_in);document.getElementById('totalDataOut').textContent=formatBytes(data.total_bytes_out);const list=document.getElementById('devicesList');if(!data.devices||!data.devices.length){list.innerHTML='<div style="padding:40px;text-align:center;color:#666">No active devices in the last 30 minutes.</div>';return;}list.innerHTML=data.devices.map(d=>{const statusClass=d.is_active?'active':'inactive';const statusColor=d.is_active?'#4caf50':'#999';const statusText=d.is_active?'Active':'Idle';const expiryColor=d.session_expiry==='Expired'?'#c62828':d.session_expiry.includes('m')&&!d.session_expiry.includes('h')?'#ff9800':'#333';const hosts=d.recent_hosts&&d.recent_hosts.length?d.recent_hosts.slice(0,3).join(', '):'No recent activity';return'<div class="device-card '+statusClass+'" onclick="showConnections(\''+d.ip+'\',\''+d.name+'\')"><div class="device-info"><span class="device-name">'+d.name+'</span><span class="device-ip">'+d.ip+'</span><span style="font-size:0.8em;color:#888;margin-top:3px">'+hosts+'</span></div><div class="device-status"><span class="status-indicator"><span class="status-dot" style="background:'+statusColor+'"></span>'+statusText+'</span><span style="font-size:0.85em;color:#888">'+(d.is_active?'Active now':Math.round(d.last_active_min)+' min ago')+'</span></div><div class="device-data"><div class="data-value">'+formatBytes(d.bytes_in+d.bytes_out)+'</div><div class="data-label">Total Data</div><div style="font-size:0.85em;color:#888;margin-top:5px">'+formatNumber(d.request_count)+' reqs</div></div><div class="device-expiry"><div class="expiry-time" style="color:'+expiryColor+'">'+d.session_expiry+'</div><div class="expiry-label">Session Expiry</div></div></div>';}).join('');});fetch('/api/system-stats').then(r=>r.json()).then(d=>{document.getElementById('uptimeValue').textContent=d.uptime_formatted;});}function showConnections(ip,name){document.getElementById('modalTitle').textContent=name+' - Recent Connections';document.getElementById('connList').innerHTML='<div style="text-align:center;padding:20px">Loading...</div>';document.getElementById('connModal').classList.add('show');fetch('/api/device-connections?device_ip='+encodeURIComponent(ip)).then(r=>r.json()).then(conns=>{if(!conns||!conns.length){document.getElementById('connList').innerHTML='<div style="text-align:center;color:#666;padding:20px">No recent connections recorded.</div>';return;}document.getElementById('connList').innerHTML='<table class="conn-table"><thead><tr><th>Time</th><th>Host</th><th>Protocol</th><th>Data</th></tr></thead><tbody>'+conns.map(c=>{const time=new Date(c.timestamp).toLocaleTimeString();return'<tr><td>'+time+'</td><td style="font-family:monospace">'+c.host+'</td><td>'+c.protocol+'</td><td>↓'+formatBytes(c.bytes_in)+' ↑'+formatBytes(c.bytes_out)+'</td></tr>';}).join('')+'</tbody></table>';});}function closeModal(){document.getElementById('connModal').classList.remove('show');}loadOverview();setInterval(loadOverview,5000);</script></body></html>`

const accessPointPageHTML = `<!DOCTYPE html><html><head><title>Lumier Dynamics - Access Point</title><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + baseStyles + `.ap-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-bottom:25px}.ap-stat{background:#1a1a1a;padding:20px;border-radius:12px;border:1px solid #2a2a2a;text-align:center}.ap-stat .value{font-size:2em;font-weight:bold}.ap-stat .label{color:#666;font-size:0.85em;text-transform:uppercase;margin-top:5px}.devices-section{background:#1a1a1a;border-radius:12px;border:1px solid #2a2a2a;overflow:hidden;margin-bottom:20px}.devices-header{background:#667eea;color:white;padding:15px 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}.devices-header h2{margin:0;font-size:1.1em}.device-row{padding:15px 20px;border-bottom:1px solid #f0f0f0;display:grid;grid-template-columns:auto 1fr 1fr 1fr auto;gap:15px;align-items:center}.device-row:hover{background:#f8f9ff}.device-row.pending{background:#fff3e0;border-left:4px solid #ff9800}.device-row.confirmed{border-left:4px solid #4caf50}.device-row.offline{opacity:0.6}.device-status{width:12px;height:12px;border-radius:50%}.device-info{display:flex;flex-direction:column;gap:3px}.device-name{font-weight:600;color:#e0e0e0}.device-mac{font-size:0.8em;color:#888;font-family:monospace}.device-ip{font-size:0.85em;color:#666;font-family:monospace}.device-proxy{text-align:center}.proxy-badge{background:#e3f2fd;color:#1976d2;padding:5px 12px;border-radius:15px;font-size:0.85em;font-weight:500}.device-data{text-align:right;font-size:0.85em;color:#666}.device-actions{display:flex;gap:8px}.btn-approve{background:#4caf50;color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:500}.btn-approve:hover{background:#43a047}.btn-revoke{background:#ff9800;color:white;border:none;padding:8px 12px;border-radius:6px;cursor:pointer}.btn-delete{background:#f44336;color:white;border:none;padding:8px 12px;border-radius:6px;cursor:pointer}.filter-tabs{display:flex;gap:5px;flex-wrap:wrap}.filter-tab{background:rgba(255,255,255,0.2);color:white;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:500}.filter-tab.active{background:#1a1a1a;color:#4a9eff}</style></head><body>` + navHTML + `<div class="main-content"><div class="page-header"><h1>📡 Access Point Devices</h1><p>Manage devices connected via the WiFi access point</p></div><div class="ap-stats"><div class="ap-stat"><div class="value" style="color:#ff9800" id="pendingCount">-</div><div class="label">Pending Approval</div></div><div class="ap-stat"><div class="value" style="color:#4caf50" id="confirmedCount">-</div><div class="label">Approved</div></div><div class="ap-stat"><div class="value" style="color:#2196F3" id="onlineCount">-</div><div class="label">Online Now</div></div><div class="ap-stat"><div class="value" style="color:#4a9eff" id="totalCount">-</div><div class="label">Total Devices</div></div></div><div class="devices-section"><div class="devices-header"><h2>Connected Devices</h2><div class="filter-tabs"><button class="filter-tab active" onclick="setFilter('all')">All</button><button class="filter-tab" onclick="setFilter('pending')">Pending</button><button class="filter-tab" onclick="setFilter('confirmed')">Approved</button><button class="filter-tab" onclick="setFilter('online')">Online</button></div><button class="btn btn-secondary" onclick="loadDevices()" style="padding:6px 12px;font-size:0.85em">🔄 Refresh</button></div><div id="devicesList"><div style="padding:40px;text-align:center;color:#666">Loading devices...</div></div></div><div class="card"><h2>ℹ️ Access Point Network</h2><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-top:15px"><div style="background:#121212;padding:15px;border-radius:8px"><strong>Network:</strong> 10.10.10.0/24</div><div style="background:#121212;padding:15px;border-radius:8px"><strong>Gateway:</strong> 10.10.10.1</div><div style="background:#121212;padding:15px;border-radius:8px"><strong>DHCP Range:</strong> 10.10.10.100-200</div><div style="background:#121212;padding:15px;border-radius:8px"><strong>Proxy Port:</strong> 8888</div></div><p style="margin-top:15px;color:#666;font-size:0.9em"><strong>Security:</strong> New devices are blocked until approved. All traffic must go through the proxy.</p></div></div><script>` + baseJS + `document.getElementById('nav-ap').classList.add('active');let currentFilter='all';let allDevices=[];function setFilter(f){currentFilter=f;document.querySelectorAll('.filter-tab').forEach(t=>t.classList.remove('active'));event.target.classList.add('active');renderDevices();}function loadDevices(){fetch('/api/ap/status').then(r=>r.json()).then(s=>{document.getElementById('pendingCount').textContent=s.pending_devices;document.getElementById('confirmedCount').textContent=s.confirmed_devices;document.getElementById('onlineCount').textContent=s.online_devices;document.getElementById('totalCount').textContent=s.total_devices;});fetch('/api/ap/devices').then(r=>r.json()).then(devices=>{allDevices=devices;renderDevices();});}function renderDevices(){const list=document.getElementById('devicesList');let filtered=allDevices;if(currentFilter==='pending')filtered=allDevices.filter(d=>!d.confirmed);else if(currentFilter==='confirmed')filtered=allDevices.filter(d=>d.confirmed);else if(currentFilter==='online')filtered=allDevices.filter(d=>d.status==='online');if(!filtered.length){list.innerHTML='<div style="padding:40px;text-align:center;color:#666">No devices found.</div>';return;}list.innerHTML=filtered.map(d=>{const statusColor=d.status==='online'?'#4caf50':'#ccc';const rowClass=(d.confirmed?'confirmed':'pending')+' '+(d.status==='offline'?'offline':'');const name=d.custom_name||d.hostname||'Unknown Device';return'<div class="device-row '+rowClass+'"><div class="device-status" style="background:'+statusColor+'" title="'+d.status+'"></div><div class="device-info"><span class="device-name">'+name+'</span><span class="device-mac">'+d.mac+'</span><span class="device-ip">'+d.ip+'</span></div><div class="device-proxy"><span class="proxy-badge">'+d.proxy_name+'</span><select onchange="changeProxy(\''+d.mac+'\',this.value)" style="margin-top:8px;padding:5px;border:1px solid #ddd;border-radius:4px;font-size:0.85em" id="proxy-'+d.mac.replace(/:/g,'')+'"></select></div><div class="device-data"><div>'+formatBytes(d.bytes_in+d.bytes_out)+' total</div><div>'+formatNumber(d.request_count)+' requests</div><div style="margin-top:5px;color:#888">'+d.group+'</div></div><div class="device-actions">'+(d.confirmed?'<button class="btn-revoke" onclick="toggleConfirm(\''+d.mac+'\',false)" title="Revoke access">⛔</button>':'<button class="btn-approve" onclick="toggleConfirm(\''+d.mac+'\',true)">✓ Approve</button>')+'<button class="btn-delete" onclick="deleteDevice(\''+d.mac+'\')" title="Delete">🗑️</button></div></div>';}).join('');loadProxyOptions();}function loadProxyOptions(){fetch('/api/proxies').then(r=>r.json()).then(proxies=>{allDevices.forEach(d=>{const sel=document.getElementById('proxy-'+d.mac.replace(/:/g,''));if(sel){sel.innerHTML=proxies.map((p,i)=>'<option value="'+i+'"'+(i===d.proxy_index?' selected':'')+'>'+p.custom_name+'</option>').join('');}});});}function toggleConfirm(mac,confirmed){fetch('/api/ap/device/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:mac,confirmed:confirmed})}).then(r=>r.json()).then(d=>{if(d.success){showToast(confirmed?'Device approved':'Access revoked','success');loadDevices();}else{showToast('Failed','error');}});}function changeProxy(mac,idx){fetch('/api/ap/device/proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:mac,proxy_index:parseInt(idx)})}).then(r=>r.json()).then(d=>{if(d.success){showToast('Proxy changed to '+d.proxy_name,'success');loadDevices();}});}function deleteDevice(mac){if(!confirm('Delete this device? It will reappear if it reconnects.'))return;fetch('/api/ap/device/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac:mac})}).then(r=>r.json()).then(d=>{if(d.success){showToast('Device deleted','success');loadDevices();}});}loadDevices();setInterval(loadDevices,10000);</script></body></html>`
