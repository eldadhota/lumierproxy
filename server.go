package main

import (
	"strings"
	"sync"
	"time"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

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
	Index           int             `json:"index"`
	ProxyString     string          `json:"proxy_string"`
	IPAddress       string          `json:"ip_address"`
	TotalRequests   int64           `json:"total_requests"`
	SuccessCount    int64           `json:"success_count"`
	FailureCount    int64           `json:"failure_count"`
	SuccessRate     float64         `json:"success_rate"`
	LastSuccess     time.Time       `json:"last_success"`
	LastFailure     time.Time       `json:"last_failure"`
	LastError       string          `json:"last_error"`
	AvgResponseTime int64           `json:"avg_response_time_ms"`
	Status          string          `json:"status"`
	BytesIn         int64           `json:"bytes_in"`
	BytesOut        int64           `json:"bytes_out"`
	ActiveDevices   int             `json:"active_devices"`
	UniqueDevices   map[string]bool `json:"-"`
	DeviceCount     int             `json:"device_count"`
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

// loginAttemptInfo tracks failed login attempts for rate limiting
type loginAttemptInfo struct {
	Count       int
	LastAttempt time.Time
	LockedUntil time.Time
}

type PersistentData struct {
	DeviceConfigs   map[string]DeviceConfig  `json:"device_configs"`
	Groups          []string                 `json:"groups"`
	Users           []UserCredentials        `json:"users"`
	TrafficHistory  []TrafficSnapshot        `json:"traffic_history"`
	ProxyHealthData map[int]*ProxyHealth     `json:"proxy_health_data"`
	SystemSettings  SystemSettings           `json:"system_settings"`
	Supervisors     []Supervisor             `json:"supervisors"`
	AdminPassword   string                   `json:"admin_password"`
	ProxyNames      map[int]string           `json:"proxy_names"`
	APConfig        APConfig                 `json:"ap_config"`
	APDevices       map[string]*APDevice     `json:"ap_devices"`
	BrowserProfiles map[string]*BrowserProfile `json:"browser_profiles"`
	BrowserSessions []BrowserSession         `json:"browser_sessions"`
}

type Supervisor struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type SystemSettings struct {
	SessionTimeout         int  `json:"session_timeout_hours"`
	TrafficRetentionDays   int  `json:"traffic_retention_days"`
	DeviceTimeoutMinutes   int  `json:"device_timeout_minutes"`
	SecureCookies          bool `json:"secure_cookies"`
	PrunePendingAfterHours int  `json:"prune_pending_after_hours"`
	PruneOfflineAfterDays  int  `json:"prune_offline_after_days"`
}

// ============================================================================
// ACCESS POINT DATA STRUCTURES
// ============================================================================

// APDevice represents a device connected via the WiFi access point
type APDevice struct {
	MAC           string    `json:"mac"`
	IP            string    `json:"ip"`
	Hostname      string    `json:"hostname"`
	UpstreamProxy string    `json:"upstream_proxy"`
	ProxyIndex    int       `json:"proxy_index"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
	Confirmed     bool      `json:"confirmed"`
	ConfirmedAt   time.Time `json:"confirmed_at"`
	ConfirmedBy   string    `json:"confirmed_by"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	RequestCount  int64     `json:"request_count"`
	Group         string    `json:"group"`
	CustomName    string    `json:"custom_name"`
	Notes         string    `json:"notes"`
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error"`
	LastErrorTime time.Time `json:"last_error_time"`
	GoogleBypass  bool      `json:"google_bypass"` // Allow direct access to Google services
}

// APConfig stores access point network configuration
type APConfig struct {
	Enabled      bool   `json:"enabled"`
	Interface    string `json:"interface"`
	WANInterface string `json:"wan_interface"`
	IPAddress    string `json:"ip_address"`
	Netmask      string `json:"netmask"`
	DHCPStart    string `json:"dhcp_start"`
	DHCPEnd      string `json:"dhcp_end"`
	LeaseFile    string `json:"lease_file"`
}

// BrowserProfile represents a browser profile for isolated proxy sessions
type BrowserProfile struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	ProxyIndex    int       `json:"proxy_index"`
	UpstreamProxy string    `json:"upstream_proxy"`
	ProxyName     string    `json:"proxy_name"`
	Color         string    `json:"color"`
	Notes         string    `json:"notes"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
	LastUsedAt    time.Time `json:"last_used_at"`
	LastUsedBy    string    `json:"last_used_by"`
	SessionCount  int64     `json:"session_count"`
}

// BrowserSession logs when a profile is used
type BrowserSession struct {
	ID         string    `json:"id"`
	ProfileID  string    `json:"profile_id"`
	DeviceName string    `json:"device_name"`
	ProxyName  string    `json:"proxy_name"`
	Username   string    `json:"username"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	Duration   int64     `json:"duration_seconds"`
}

// ============================================================================
// SERVER STRUCT
// ============================================================================

type ProxyServer struct {
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
	startTime       time.Time
	logBuffer       []LogEntry
	logMu           sync.RWMutex
	cpuUsage        float64
	cpuMu           sync.RWMutex
	deviceActivity     map[string][]DeviceActivity
	deviceActivityMu   sync.RWMutex
	deviceConnections  map[string][]DeviceConnection
	deviceConnectionMu sync.RWMutex
	// Access Point fields
	apDevices   map[string]*APDevice
	apIPToMAC   map[string]string
	apMu        sync.RWMutex
	apConfig    APConfig
	apPoolIndex int
	// Rate limiting for login
	loginAttempts map[string]*loginAttemptInfo
	loginMu       sync.RWMutex
	// Browser Profile fields
	browserProfiles map[string]*BrowserProfile
	browserMu       sync.RWMutex
	// Screenshot fields
	screenshots          []Screenshot
	screenshotRequests   map[string]*ScreenshotRequest // device_id -> request
	screenshotDir        string
	screenshotMu         sync.RWMutex
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

// ============================================================================
// REQUEST TYPES
// ============================================================================

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

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ClientDevice represents a device available for selection in the Windows client
type ClientDevice struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProxyIndex    int    `json:"proxy_index"`
	ProxyName     string `json:"proxy_name"`
	UpstreamProxy string `json:"upstream_proxy"`
	Group         string `json:"group"`
	DeviceType    string `json:"device_type"`
}

// TrustScoreResult contains the fraud score and risk assessment for an IP
type TrustScoreResult struct {
	Score     int    `json:"score"`
	Risk      string `json:"risk"`
	Available bool   `json:"available"`
	Error     string `json:"error"`
}

// IPQSResult contains detailed fraud data from IPQualityScore API
type IPQSResult struct {
	Available      bool    `json:"available"`
	Error          string  `json:"error,omitempty"`
	FraudScore     int     `json:"fraud_score"`
	Risk           string  `json:"risk"`
	CountryCode    string  `json:"country_code"`
	City           string  `json:"city"`
	ISP            string  `json:"isp"`
	ASN            int     `json:"asn"`
	Organization   string  `json:"organization"`
	Proxy          bool    `json:"proxy"`
	VPN            bool    `json:"vpn"`
	TOR            bool    `json:"tor"`
	ActiveVPN      bool    `json:"active_vpn"`
	ActiveTOR      bool    `json:"active_tor"`
	RecentAbuse    bool    `json:"recent_abuse"`
	BotStatus      bool    `json:"bot_status"`
	ConnectionType string  `json:"connection_type"`
	AbuseVelocity  string  `json:"abuse_velocity"`
	IsCrawler      bool    `json:"is_crawler"`
	Mobile         bool    `json:"mobile"`
	Host           string  `json:"host"`
}

// CombinedTrustScore contains fraud scores from multiple sources
type CombinedTrustScore struct {
	IPQS           IPQSResult       `json:"ipqs"`
	IPQualityScore TrustScoreResult `json:"ipqualityscore"` // Legacy field for IP-API fallback
}

// Screenshot represents a captured screenshot from a client device
type Screenshot struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name"`
	Username    string    `json:"username"`
	Filename    string    `json:"filename"`
	CaptureTime time.Time `json:"capture_time"`
	Width       int       `json:"width"`
	Height      int       `json:"height"`
	SizeBytes   int64     `json:"size_bytes"`
}

// ScreenshotRequest represents a pending screenshot request for a device
type ScreenshotRequest struct {
	DeviceID    string    `json:"device_id"`
	RequestedAt time.Time `json:"requested_at"`
	RequestedBy string    `json:"requested_by"`
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
	if idx := len(hostPort) - 1; idx >= 0 {
		for i := len(hostPort) - 1; i >= 0; i-- {
			if hostPort[i] == ':' {
				host = hostPort[:i]
				port = hostPort[i+1:]
				break
			}
		}
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

// Global server instance
var server *ProxyServer
