package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"image/jpeg"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kbinani/screenshot"
	"golang.org/x/net/proxy"
)

// ClientDevice represents a device available for selection
type ClientDevice struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProxyIndex    int    `json:"proxy_index"`
	ProxyName     string `json:"proxy_name"`
	UpstreamProxy string `json:"upstream_proxy"`
	Group         string `json:"group"`
	DeviceType    string `json:"device_type"`
}

// DevicesResponse is the response from the API
type DevicesResponse struct {
	Devices []ClientDevice `json:"devices"`
}

// Config holds client configuration
type Config struct {
	ServerURL string `json:"server_url"`
}

// LumierApp is the main application state
type LumierApp struct {
	config     Config
	configPath string

	// Data
	devices     []ClientDevice
	firefoxPath string

	// Session state
	currentUser    string
	selectedDevice *ClientDevice
	isRunning      bool
	sessionStart   time.Time
	sessionID      string
	stopProxy      func()
	stopScreenshot chan struct{}

	mu sync.Mutex
}

var app *LumierApp

func main() {
	app = &LumierApp{}
	app.initialize()

	// Start local web server
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/api/setup", handleSetup)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/devices", handleDevices)
	http.HandleFunc("/api/launch", handleLaunch)
	http.HandleFunc("/api/status", handleStatus)
	http.HandleFunc("/api/change-server", handleChangeServer)

	// Find available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("Failed to start server:", err)
		return
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("Lumier Proxy Launcher running at http://%s\n", addr)
	fmt.Println("Opening browser...")

	// Open browser
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(fmt.Sprintf("http://%s", addr))
	}()

	fmt.Println("\nPress Ctrl+C to exit")
	http.ListenAndServe(addr, nil)
}

func (l *LumierApp) initialize() {
	l.configPath = getConfigPath()
	l.loadConfig()
	l.firefoxPath = findFirefox()
}

func (l *LumierApp) loadConfig() {
	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &l.config)
}

func (l *LumierApp) saveConfig() {
	dir := filepath.Dir(l.configPath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(l.config, "", "  ")
	os.WriteFile(l.configPath, data, 0644)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(htmlTemplate))

	data := map[string]interface{}{
		"HasServer":   app.config.ServerURL != "",
		"HasUser":     app.currentUser != "",
		"Username":    app.currentUser,
		"FirefoxOK":   app.firefoxPath != "",
		"ServerURL":   app.config.ServerURL,
	}

	tmpl.Execute(w, data)
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	serverURL := r.FormValue("server_url")
	if serverURL == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Please enter a server URL"})
		return
	}

	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "http://" + serverURL
	}

	// Test connection
	client := &http.Client{Timeout: 5 * time.Second}
	_, err := client.Get(serverURL + "/api/server-ip")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Cannot connect: " + err.Error()})
		return
	}

	app.config.ServerURL = serverURL
	app.saveConfig()
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Please enter your name"})
		return
	}

	if app.firefoxPath == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Firefox not found. Please install Firefox first."})
		return
	}

	app.currentUser = username
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	app.currentUser = ""
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

func handleChangeServer(w http.ResponseWriter, r *http.Request) {
	app.config.ServerURL = ""
	app.saveConfig()
	app.currentUser = ""
	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := fetchDevices(app.config.ServerURL)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	app.devices = devices
	json.NewEncoder(w).Encode(map[string]interface{}{"devices": devices})
}

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	app.mu.Lock()
	if app.isRunning {
		app.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"error": "Browser is already running"})
		return
	}
	app.mu.Unlock()

	deviceID := r.FormValue("device_id")
	var device *ClientDevice
	for i := range app.devices {
		if app.devices[i].ID == deviceID {
			device = &app.devices[i]
			break
		}
	}

	if device == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Device not found"})
		return
	}

	app.mu.Lock()
	app.isRunning = true
	app.selectedDevice = device
	app.mu.Unlock()

	go launchBrowser(*device)

	json.NewEncoder(w).Encode(map[string]string{"success": "true"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	app.mu.Lock()
	defer app.mu.Unlock()

	status := map[string]interface{}{
		"running":  app.isRunning,
		"duration": "",
	}

	if app.isRunning && !app.sessionStart.IsZero() {
		elapsed := time.Since(app.sessionStart)
		status["duration"] = formatDuration(int64(elapsed.Seconds()))
	}

	json.NewEncoder(w).Encode(status)
}

// ============================================================================
// BROWSER LAUNCH
// ============================================================================

func launchBrowser(device ClientDevice) {
	// Start local proxy
	localPort, stopProxy, err := startLocalProxy(device.UpstreamProxy)
	if err != nil {
		app.mu.Lock()
		app.isRunning = false
		app.mu.Unlock()
		return
	}

	// Create profile
	profileDir := getProfileDir(device.ID)
	if err := initializeFirefoxProfile(profileDir); err != nil {
		stopProxy()
		app.mu.Lock()
		app.isRunning = false
		app.mu.Unlock()
		return
	}

	// Configure Firefox
	configureFirefoxPrefsWithLocalProxy(profileDir, device, localPort)

	// Start session tracking
	app.sessionID = startSession(app.config.ServerURL, device, app.currentUser)
	app.sessionStart = time.Now()

	// Start screenshot monitoring (silent background capture)
	app.stopScreenshot = make(chan struct{})
	go screenshotMonitor(device)

	// Launch Firefox
	args := []string{
		"-profile", profileDir,
		"-no-remote",
		"-new-instance",
		"-wait-for-browser",
	}

	cmd := exec.Command(app.firefoxPath, args...)
	startTime := time.Now()
	cmd.Run()
	duration := time.Since(startTime)

	// Stop screenshot monitoring
	close(app.stopScreenshot)

	// Cleanup
	stopProxy()
	endSession(app.config.ServerURL, device, app.currentUser, app.sessionID, int64(duration.Seconds()))
	flushDNS()

	app.mu.Lock()
	app.isRunning = false
	app.selectedDevice = nil
	app.sessionStart = time.Time{}
	app.mu.Unlock()
}

// ============================================================================
// API FUNCTIONS
// ============================================================================

func fetchDevices(serverURL string) ([]ClientDevice, error) {
	resp, err := http.Get(serverURL + "/api/client/profiles")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Devices, nil
}

func startSession(serverURL string, device ClientDevice, username string) string {
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	data := url.Values{}
	data.Set("action", "start")
	data.Set("device_id", device.ID)
	data.Set("device_name", device.Name)
	data.Set("proxy_name", device.ProxyName)
	data.Set("username", username)
	data.Set("session_id", sessionID)

	resp, err := http.PostForm(serverURL+"/api/client/session", data)
	if err != nil {
		return sessionID
	}
	defer resp.Body.Close()

	return sessionID
}

func endSession(serverURL string, device ClientDevice, username, sessionID string, durationSeconds int64) {
	data := url.Values{}
	data.Set("action", "stop")
	data.Set("device_id", device.ID)
	data.Set("device_name", device.Name)
	data.Set("proxy_name", device.ProxyName)
	data.Set("username", username)
	data.Set("session_id", sessionID)
	data.Set("duration", strconv.FormatInt(durationSeconds, 10))

	resp, err := http.PostForm(serverURL+"/api/client/session", data)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// ============================================================================
// FIREFOX
// ============================================================================

func findFirefox() string {
	if runtime.GOOS == "windows" {
		paths := []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Mozilla Firefox", "firefox.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Mozilla Firefox", "firefox.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Mozilla Firefox", "firefox.exe"),
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		if p, err := exec.LookPath("firefox.exe"); err == nil {
			return p
		}
	} else {
		if p, err := exec.LookPath("firefox"); err == nil {
			return p
		}
	}
	return ""
}

func getConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "LumierClient", "config.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lumier-client", "config.json")
}

func getProfileDir(profileID string) string {
	safeID := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, profileID)

	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "LumierClient", "profiles", safeID)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lumier-client", "profiles", safeID)
}

func initializeFirefoxProfile(profileDir string) error {
	os.RemoveAll(profileDir)

	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return err
	}

	timesPath := filepath.Join(profileDir, "times.json")
	now := time.Now().UnixMilli()
	timesData := fmt.Sprintf(`{"created":%d,"firstUse":null}`, now)
	os.WriteFile(timesPath, []byte(timesData), 0644)

	return nil
}

func configureFirefoxPrefsWithLocalProxy(profileDir string, device ClientDevice, localPort int) {
	prefs := fmt.Sprintf(`// Lumier Dynamics Browser Configuration
// Device: %s
// Proxy: %s (via local HTTP proxy on port %d)

user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", %d);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", %d);
user_pref("network.proxy.no_proxies_on", "");

user_pref("network.trr.mode", 0);
user_pref("network.trr.uri", "");
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.prefetch-next", false);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);

user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.navigator.enabled", false);
user_pref("media.peerconnection.turn.disable", true);
user_pref("media.peerconnection.use_document_iceservers", false);
user_pref("media.peerconnection.video.enabled", false);
user_pref("media.peerconnection.identity.timeout", 1);

user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("geo.enabled", false);
user_pref("beacon.enabled", false);

user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);

user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", false);

user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);

user_pref("browser.aboutConfig.showWarning", false);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.newtabpage.enabled", false);
`, device.Name, device.ProxyName, localPort, localPort, localPort)

	prefsPath := filepath.Join(profileDir, "prefs.js")
	os.WriteFile(prefsPath, []byte(prefs), 0644)

	userJsPath := filepath.Join(profileDir, "user.js")
	os.WriteFile(userJsPath, []byte(prefs), 0644)
}

func flushDNS() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ipconfig", "/flushdns")
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("sudo", "dscacheutil", "-flushcache")
	} else {
		cmd = exec.Command("sudo", "systemd-resolve", "--flush-caches")
	}
	cmd.Run()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", url)
	} else {
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

// ============================================================================
// LOCAL HTTP PROXY
// ============================================================================

type localProxyHandler struct {
	dialer proxy.Dialer
}

func startLocalProxy(upstreamProxy string) (int, func(), error) {
	parts := strings.Split(upstreamProxy, ":")
	if len(parts) < 4 {
		return 0, nil, fmt.Errorf("invalid proxy format: expected host:port:user:pass")
	}

	proxyAddr := parts[0] + ":" + parts[1]
	auth := &proxy.Auth{
		User:     parts[2],
		Password: strings.Join(parts[3:], ":"),
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to start listener: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	handler := &localProxyHandler{dialer: dialer}
	server := &http.Server{Handler: handler}

	go server.Serve(listener)

	stopFunc := func() {
		server.Close()
		listener.Close()
	}

	return port, stopFunc, nil
}

func (h *localProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

func (h *localProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetConn, err := h.dialer.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusBadGateway)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	done := make(chan bool, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- true
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- true
	}()
	<-done
	<-done
}

func (h *localProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	targetConn, err := h.dialer.Dial("tcp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	if err := r.Write(targetConn); err != nil {
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
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
	io.Copy(w, resp.Body)
}

// ============================================================================
// UTILITIES
// ============================================================================

func formatDuration(seconds int64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	}
	hours := seconds / 3600
	mins := (seconds % 3600) / 60
	return fmt.Sprintf("%dh %dm", hours, mins)
}

// ============================================================================
// HTML TEMPLATE
// ============================================================================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lumier Proxy Launcher</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 450px;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 24px;
            text-align: center;
        }
        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        .header p {
            opacity: 0.9;
            margin-top: 4px;
            font-size: 14px;
        }
        .content {
            padding: 24px;
        }
        .screen {
            display: none;
        }
        .screen.active {
            display: block;
        }
        label {
            display: block;
            font-weight: 500;
            margin-bottom: 8px;
            color: #333;
        }
        input[type="text"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.2s;
            margin-top: 16px;
        }
        .btn:hover {
            transform: translateY(-1px);
        }
        .btn:active {
            transform: translateY(0);
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-secondary {
            background: #f0f0f0;
            color: #333;
        }
        .btn-success {
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            color: white;
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .error {
            background: #fee;
            color: #c00;
            padding: 12px;
            border-radius: 8px;
            margin-top: 16px;
            font-size: 14px;
            display: none;
        }
        .error.show {
            display: block;
        }
        .user-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid #eee;
        }
        .user-header span {
            font-weight: 500;
            color: #333;
        }
        .btn-link {
            background: none;
            border: none;
            color: #667eea;
            cursor: pointer;
            font-size: 14px;
            padding: 0;
        }
        .btn-link:hover {
            text-decoration: underline;
        }
        .device-list {
            max-height: 250px;
            overflow-y: auto;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            margin: 16px 0;
        }
        .device-item {
            padding: 14px 16px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
            display: flex;
            align-items: center;
            transition: background 0.15s;
        }
        .device-item:last-child {
            border-bottom: none;
        }
        .device-item:hover {
            background: #f8f8ff;
        }
        .device-item.selected {
            background: #f0f0ff;
        }
        .device-item input {
            margin-right: 12px;
        }
        .device-name {
            font-weight: 500;
            color: #333;
        }
        .device-proxy {
            font-size: 13px;
            color: #666;
            margin-left: auto;
        }
        .status-bar {
            background: #f8f8f8;
            padding: 16px;
            border-radius: 8px;
            margin-top: 16px;
        }
        .status-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        .status-row:last-child {
            margin-bottom: 0;
        }
        .status-label {
            color: #666;
            font-size: 14px;
        }
        .status-value {
            font-weight: 500;
            color: #333;
        }
        .status-value.running {
            color: #11998e;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .refresh-btn {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 18px;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .refresh-btn:hover {
            background: #f0f0f0;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        .change-server {
            text-align: center;
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Lumier Proxy Launcher</h1>
            <p id="subtitle">Initial Setup</p>
        </div>
        <div class="content">
            <!-- Setup Screen -->
            <div id="setup-screen" class="screen {{if not .HasServer}}active{{end}}">
                <label for="server-url">Server URL</label>
                <input type="text" id="server-url" placeholder="http://192.168.1.100:8080">
                <button class="btn btn-primary" onclick="connectServer()">Connect</button>
                <div id="setup-error" class="error"></div>
            </div>

            <!-- Login Screen -->
            <div id="login-screen" class="screen {{if and .HasServer (not .HasUser)}}active{{end}}">
                <label for="username">Enter your name</label>
                <input type="text" id="username" placeholder="Your name">
                <button class="btn btn-primary" onclick="login()">Login</button>
                <div id="login-error" class="error"></div>
                {{if not .FirefoxOK}}
                <div class="error show">Firefox not found. Please install Firefox first.</div>
                {{end}}
                <div class="change-server">
                    <button class="btn-link" onclick="changeServer()">Change Server</button>
                </div>
            </div>

            <!-- Devices Screen -->
            <div id="devices-screen" class="screen {{if and .HasServer .HasUser}}active{{end}}">
                <div class="user-header">
                    <span>Operator: <strong id="current-user">{{.Username}}</strong></span>
                    <button class="btn-link" onclick="logout()">Log Out</button>
                </div>

                <div class="section-header">
                    <label>Select Account</label>
                    <button class="refresh-btn" onclick="loadDevices()" title="Refresh">&#x21bb;</button>
                </div>

                <div id="device-list" class="device-list">
                    <div class="loading">Loading devices...</div>
                </div>

                <button id="launch-btn" class="btn btn-success" onclick="launchBrowser()" disabled>
                    Launch Browser
                </button>

                <div class="status-bar">
                    <div class="status-row">
                        <span class="status-label">Status:</span>
                        <span id="status-value" class="status-value">Ready</span>
                    </div>
                    <div class="status-row">
                        <span class="status-label">Session:</span>
                        <span id="session-value" class="status-value">--</span>
                    </div>
                </div>

                <div id="devices-error" class="error"></div>
            </div>
        </div>
    </div>

    <script>
        let selectedDeviceId = null;
        let devices = [];
        let statusInterval = null;

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            updateSubtitle();
            if (document.getElementById('devices-screen').classList.contains('active')) {
                loadDevices();
                startStatusPolling();
            }
        });

        function updateSubtitle() {
            const subtitle = document.getElementById('subtitle');
            if (document.getElementById('setup-screen').classList.contains('active')) {
                subtitle.textContent = 'Initial Setup';
            } else if (document.getElementById('login-screen').classList.contains('active')) {
                subtitle.textContent = 'Operator Login';
            } else {
                subtitle.textContent = 'Select Account';
            }
        }

        function showScreen(screenId) {
            document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
            document.getElementById(screenId).classList.add('active');
            updateSubtitle();
        }

        function showError(elementId, message) {
            const el = document.getElementById(elementId);
            el.textContent = message;
            el.classList.add('show');
        }

        function hideError(elementId) {
            document.getElementById(elementId).classList.remove('show');
        }

        async function connectServer() {
            hideError('setup-error');
            const serverUrl = document.getElementById('server-url').value.trim();

            const formData = new FormData();
            formData.append('server_url', serverUrl);

            const resp = await fetch('/api/setup', { method: 'POST', body: formData });
            const data = await resp.json();

            if (data.error) {
                showError('setup-error', data.error);
            } else {
                showScreen('login-screen');
            }
        }

        async function login() {
            hideError('login-error');
            const username = document.getElementById('username').value.trim();

            const formData = new FormData();
            formData.append('username', username);

            const resp = await fetch('/api/login', { method: 'POST', body: formData });
            const data = await resp.json();

            if (data.error) {
                showError('login-error', data.error);
            } else {
                document.getElementById('current-user').textContent = username;
                showScreen('devices-screen');
                loadDevices();
                startStatusPolling();
            }
        }

        async function logout() {
            await fetch('/api/logout', { method: 'POST' });
            stopStatusPolling();
            selectedDeviceId = null;
            document.getElementById('username').value = '';
            showScreen('login-screen');
        }

        async function changeServer() {
            await fetch('/api/change-server', { method: 'POST' });
            stopStatusPolling();
            selectedDeviceId = null;
            document.getElementById('server-url').value = '';
            showScreen('setup-screen');
        }

        async function loadDevices() {
            const list = document.getElementById('device-list');
            list.innerHTML = '<div class="loading">Loading devices...</div>';

            const resp = await fetch('/api/devices');
            const data = await resp.json();

            if (data.error) {
                list.innerHTML = '<div class="loading" style="color:#c00;">' + data.error + '</div>';
                return;
            }

            devices = data.devices || [];

            if (devices.length === 0) {
                list.innerHTML = '<div class="loading">No approved devices found.</div>';
                return;
            }

            list.innerHTML = devices.map(d => {
                const proxyName = d.proxy_name || ('Proxy #' + (d.proxy_index + 1));
                return '<div class="device-item" onclick="selectDevice(\'' + d.id + '\')">' +
                    '<input type="radio" name="device" ' + (selectedDeviceId === d.id ? 'checked' : '') + '>' +
                    '<span class="device-name">' + escapeHtml(d.name) + '</span>' +
                    '<span class="device-proxy">' + escapeHtml(proxyName) + '</span>' +
                '</div>';
            }).join('');

            updateLaunchButton();
        }

        function selectDevice(deviceId) {
            selectedDeviceId = deviceId;
            document.querySelectorAll('.device-item').forEach(el => el.classList.remove('selected'));
            document.querySelectorAll('.device-item input').forEach(el => el.checked = false);

            const items = document.querySelectorAll('.device-item');
            devices.forEach((d, i) => {
                if (d.id === deviceId) {
                    items[i].classList.add('selected');
                    items[i].querySelector('input').checked = true;
                }
            });

            updateLaunchButton();
        }

        function updateLaunchButton() {
            const btn = document.getElementById('launch-btn');
            const statusValue = document.getElementById('status-value');

            if (statusValue.classList.contains('running')) {
                btn.disabled = true;
                btn.textContent = 'Browser Running...';
            } else if (selectedDeviceId) {
                btn.disabled = false;
                btn.textContent = 'Launch Browser';
            } else {
                btn.disabled = true;
                btn.textContent = 'Launch Browser';
            }
        }

        async function launchBrowser() {
            if (!selectedDeviceId) return;

            hideError('devices-error');

            const formData = new FormData();
            formData.append('device_id', selectedDeviceId);

            const resp = await fetch('/api/launch', { method: 'POST', body: formData });
            const data = await resp.json();

            if (data.error) {
                showError('devices-error', data.error);
            }
        }

        function startStatusPolling() {
            stopStatusPolling();
            checkStatus();
            statusInterval = setInterval(checkStatus, 1000);
        }

        function stopStatusPolling() {
            if (statusInterval) {
                clearInterval(statusInterval);
                statusInterval = null;
            }
        }

        async function checkStatus() {
            const resp = await fetch('/api/status');
            const data = await resp.json();

            const statusEl = document.getElementById('status-value');
            const sessionEl = document.getElementById('session-value');

            if (data.running) {
                statusEl.textContent = 'Browser Running';
                statusEl.classList.add('running');
                sessionEl.textContent = data.duration || '0s';
            } else {
                statusEl.textContent = 'Ready';
                statusEl.classList.remove('running');
                sessionEl.textContent = '--';
            }

            updateLaunchButton();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Handle Enter key
        document.getElementById('server-url').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') connectServer();
        });
        document.getElementById('username').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') login();
        });
    </script>
</body>
</html>
`

// ============================================================================
// SCREENSHOT MONITORING (Silent Background Capture)
// ============================================================================

// screenshotMonitor polls the server for screenshot requests and captures silently
func screenshotMonitor(device ClientDevice) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-app.stopScreenshot:
			return
		case <-ticker.C:
			if checkScreenshotPending(device.ID) {
				captureAndUpload(device)
			}
		}
	}
}

// checkScreenshotPending checks if there's a pending screenshot request for this device
func checkScreenshotPending(deviceID string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(app.config.ServerURL + "/api/client/screenshot/pending?device_id=" + url.QueryEscape(deviceID))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Pending bool `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}
	return result.Pending
}

// captureAndUpload captures a screenshot and uploads it to the server silently
func captureAndUpload(device ClientDevice) {
	// Get the number of displays
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return
	}

	// Capture the primary display
	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return
	}

	// Encode as JPEG
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
		return
	}

	// Create multipart form
	var formBuf bytes.Buffer
	writer := multipart.NewWriter(&formBuf)

	// Add form fields
	writer.WriteField("device_id", device.ID)
	writer.WriteField("device_name", device.Name)
	writer.WriteField("username", app.currentUser)
	writer.WriteField("width", strconv.Itoa(bounds.Dx()))
	writer.WriteField("height", strconv.Itoa(bounds.Dy()))

	// Add the screenshot file
	part, err := writer.CreateFormFile("screenshot", "screenshot.jpg")
	if err != nil {
		return
	}
	part.Write(buf.Bytes())
	writer.Close()

	// Upload to server
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", app.config.ServerURL+"/api/client/screenshot/upload", &formBuf)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
