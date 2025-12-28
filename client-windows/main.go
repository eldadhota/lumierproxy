package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

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
	DeviceType    string `json:"device_type"` // "ap" or "legacy"
}

// DevicesResponse is the response from the API
type DevicesResponse struct {
	Devices []ClientDevice `json:"devices"`
}

// Config holds client configuration
type Config struct {
	ServerURL string `json:"server_url"`
	Username  string `json:"username"`
}

var config Config
var configPath string

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           LUMIER DYNAMICS - Device Browser Launcher        ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Load or create config
	configPath = getConfigPath()
	loadConfig()

	// Check if Firefox is installed
	firefoxPath := findFirefox()
	if firefoxPath == "" {
		fmt.Println("⚠️  Firefox not found! Please install Firefox first.")
		fmt.Println("   Download from: https://www.mozilla.org/firefox/")
		waitForEnter()
		return
	}
	fmt.Printf("✓ Firefox found: %s\n\n", firefoxPath)

	// Main loop
	for {
		if config.ServerURL == "" {
			configureServer()
			continue
		}

		if config.Username == "" {
			configureUsername()
			continue
		}

		// Fetch and display devices
		devices, err := fetchDevices()
		if err != nil {
			fmt.Printf("❌ Error fetching devices: %v\n", err)
			fmt.Println()
			fmt.Println("Options:")
			fmt.Println("  [R] Retry")
			fmt.Println("  [C] Change server URL")
			fmt.Println("  [Q] Quit")
			fmt.Print("Choice: ")
			choice := readLine()
			switch strings.ToUpper(choice) {
			case "R":
				continue
			case "C":
				config.ServerURL = ""
				saveConfig()
				continue
			case "Q":
				return
			}
			continue
		}

		if len(devices) == 0 {
			fmt.Println("No approved devices found on the server.")
			fmt.Println("Please approve devices in the dashboard first.")
			fmt.Println()
			fmt.Println("  [R] Retry")
			fmt.Println("  [Q] Quit")
			fmt.Print("Choice: ")
			choice := readLine()
			if strings.ToUpper(choice) == "Q" {
				return
			}
			continue
		}

		// Display devices
		fmt.Println("╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    Available Devices                       ║")
		fmt.Println("╠════════════════════════════════════════════════════════════╣")
		for i, d := range devices {
			proxy := d.ProxyName
			if proxy == "" {
				proxy = fmt.Sprintf("Proxy #%d", d.ProxyIndex+1)
			}
			group := d.Group
			if group == "" {
				group = "Default"
			}
			fmt.Printf("║  [%2d] %-22s │ %-12s │ %s\n", i+1, truncate(d.Name, 22), truncate(proxy, 12), truncate(group, 10))
		}
		fmt.Println("╠════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  User: %-50s ║\n", truncate(config.Username, 50))
		fmt.Println("╠════════════════════════════════════════════════════════════╣")
		fmt.Println("║  [U] Change user    [C] Change server    [R] Refresh      ║")
		fmt.Println("║  [Q] Quit                                                  ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Print("Select device number: ")

		choice := readLine()

		switch strings.ToUpper(choice) {
		case "U":
			configureUsername()
			continue
		case "C":
			config.ServerURL = ""
			saveConfig()
			continue
		case "R":
			continue
		case "Q":
			return
		}

		// Parse device selection
		num, err := strconv.Atoi(choice)
		if err != nil || num < 1 || num > len(devices) {
			fmt.Println("Invalid selection. Please enter a number from the list.")
			time.Sleep(time.Second)
			continue
		}

		device := devices[num-1]
		launchDevice(device, firefoxPath)
	}
}

func findFirefox() string {
	if runtime.GOOS == "windows" {
		// Common Firefox locations on Windows
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
		// Try PATH
		if p, err := exec.LookPath("firefox.exe"); err == nil {
			return p
		}
	} else {
		// Linux/Mac
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

func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &config)
}

func saveConfig() {
	dir := filepath.Dir(configPath)
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configPath, data, 0644)
}

func configureServer() {
	fmt.Println("Enter the Lumier server URL (e.g., http://192.168.1.100:8080):")
	fmt.Print("> ")
	serverURL := readLine()
	serverURL = strings.TrimSpace(serverURL)

	// Validate URL
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "http://" + serverURL
	}

	// Test connection
	fmt.Println("Testing connection...")
	_, err := http.Get(serverURL + "/api/server-ip")
	if err != nil {
		fmt.Printf("❌ Cannot connect to server: %v\n", err)
		fmt.Println("Please check the URL and try again.")
		time.Sleep(2 * time.Second)
		return
	}

	config.ServerURL = serverURL
	saveConfig()
	fmt.Println("✓ Server configured successfully!")
	fmt.Println()
}

func configureUsername() {
	fmt.Println("Enter your username (for session logging):")
	fmt.Print("> ")
	username := readLine()
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Username cannot be empty.")
		time.Sleep(time.Second)
		return
	}
	config.Username = username
	saveConfig()
	fmt.Printf("✓ Username set to: %s\n\n", username)
}

func fetchDevices() ([]ClientDevice, error) {
	resp, err := http.Get(config.ServerURL + "/api/client/profiles")
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

func launchDevice(device ClientDevice, firefoxPath string) {
	fmt.Println()
	fmt.Printf("🚀 Launching browser for device: %s\n", device.Name)
	fmt.Printf("   Proxy: %s\n", device.ProxyName)
	fmt.Println()

	// Start local HTTP proxy that forwards through SOCKS5 with authentication
	fmt.Println("Starting local proxy...")
	localPort, stopProxy, err := startLocalProxy(device.UpstreamProxy)
	if err != nil {
		fmt.Printf("❌ Error starting local proxy: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}
	defer stopProxy()
	fmt.Printf("✓ Local proxy started on port %d\n", localPort)

	// Create a unique profile directory for this device
	profileDir := getProfileDir(device.ID)

	// Initialize the Firefox profile properly
	if err := initializeFirefoxProfile(profileDir); err != nil {
		fmt.Printf("❌ Error creating profile: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	// Configure Firefox preferences to use local HTTP proxy
	configureFirefoxPrefsWithLocalProxy(profileDir, device, localPort)
	fmt.Println("✓ Firefox configured with proxy and leak protection")

	// Start session
	sessionID := startSession(device)

	// Launch Firefox
	fmt.Println("Starting Firefox... (close the browser to end session)")
	fmt.Println()

	args := []string{
		"-profile", profileDir,
		"-no-remote",
		"-new-instance",
		"-wait-for-browser",
	}

	cmd := exec.Command(firefoxPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("Firefox exited with error: %v\n", err)
	}

	// End session
	endSession(device, sessionID, int64(duration.Seconds()))

	fmt.Println()
	fmt.Printf("✓ Session ended. Duration: %s\n", formatDuration(int64(duration.Seconds())))
	fmt.Println()
	time.Sleep(2 * time.Second)

	// Flush DNS cache
	flushDNS()
}

func getProfileDir(profileID string) string {
	// Sanitize profile ID for filesystem
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

func cleanupProfileLocks(profileDir string) {
	// Remove Firefox lock files that may be left over from crashes
	lockFiles := []string{
		filepath.Join(profileDir, "parent.lock"),
		filepath.Join(profileDir, "lock"),
		filepath.Join(profileDir, ".parentlock"),
	}
	for _, f := range lockFiles {
		os.Remove(f)
	}
}

func initializeFirefoxProfile(profileDir string) error {
	// Remove existing profile to ensure clean state
	// This avoids version mismatch issues and stale data
	os.RemoveAll(profileDir)

	// Create fresh profile directory
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return err
	}

	// Create times.json (Firefox uses this to track profile creation)
	timesPath := filepath.Join(profileDir, "times.json")
	now := time.Now().UnixMilli()
	timesData := fmt.Sprintf(`{"created":%d,"firstUse":null}`, now)
	os.WriteFile(timesPath, []byte(timesData), 0644)

	return nil
}

func configureFirefoxPrefs(profileDir string, device ClientDevice) {
	// Parse the proxy string (format: host:port or host:port:user:pass)
	proxyHost := ""
	proxyPort := 0
	proxyUser := ""
	proxyPass := ""

	parts := strings.Split(device.UpstreamProxy, ":")
	if len(parts) >= 2 {
		proxyHost = parts[0]
		proxyPort, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 4 {
		proxyUser = parts[2]
		proxyPass = strings.Join(parts[3:], ":") // Handle passwords containing colons
	}

	// Create prefs.js for Firefox
	prefs := fmt.Sprintf(`// Lumier Dynamics Browser Configuration
// Device: %s
// Proxy: %s

// Use manual proxy configuration
user_pref("network.proxy.type", 1);

// SOCKS5 proxy settings
user_pref("network.proxy.socks", "%s");
user_pref("network.proxy.socks_port", %d);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);

// Route all DNS through SOCKS proxy
user_pref("network.proxy.allow_hijacking_localhost", false);

// Disable WebRTC to prevent IP leaks
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.navigator.enabled", false);

// Privacy settings
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("geo.enabled", false);

// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);

// Clear data on shutdown
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", false);

// Show about:config warning
user_pref("browser.aboutConfig.showWarning", false);

// Homepage
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.newtabpage.enabled", false);

// Allow unsigned extensions (needed for proxy auth extension)
user_pref("xpinstall.signatures.required", false);
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.enabledScopes", 15);
`, device.Name, device.ProxyName, proxyHost, proxyPort)

	// Add proxy authentication if provided
	if proxyUser != "" && proxyPass != "" {
		// Note: Firefox will prompt for SOCKS5 auth if needed
		// For automatic auth, we'd need an extension
		prefs += fmt.Sprintf(`
// Proxy authentication (may still prompt)
user_pref("signon.autologin.proxy", true);
`)
	}

	// Write prefs.js
	prefsPath := filepath.Join(profileDir, "prefs.js")
	os.WriteFile(prefsPath, []byte(prefs), 0644)

	// Also write user.js (applied on startup, overrides prefs.js)
	userJsPath := filepath.Join(profileDir, "user.js")
	os.WriteFile(userJsPath, []byte(prefs), 0644)
}

// configureFirefoxPrefsWithLocalProxy configures Firefox to use local HTTP proxy
// with comprehensive DNS and WebRTC leak protection
func configureFirefoxPrefsWithLocalProxy(profileDir string, device ClientDevice, localPort int) {
	prefs := fmt.Sprintf(`// Lumier Dynamics Browser Configuration
// Device: %s
// Proxy: %s (via local HTTP proxy on port %d)

// ============================================================
// HTTP PROXY SETTINGS - Connect to local proxy (no auth needed)
// ============================================================
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", %d);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", %d);
user_pref("network.proxy.no_proxies_on", "");

// ============================================================
// DNS LEAK PROTECTION
// ============================================================
// Disable DNS-over-HTTPS (would bypass proxy)
user_pref("network.trr.mode", 0);
user_pref("network.trr.uri", "");
// Disable DNS prefetching
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
// Disable prefetching
user_pref("network.prefetch-next", false);
// Disable speculative connections
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);

// ============================================================
// WEBRTC LEAK PROTECTION
// ============================================================
// Completely disable WebRTC
user_pref("media.peerconnection.enabled", false);
// Backup restrictions
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.navigator.enabled", false);
user_pref("media.peerconnection.turn.disable", true);
user_pref("media.peerconnection.use_document_iceservers", false);
user_pref("media.peerconnection.video.enabled", false);
user_pref("media.peerconnection.identity.timeout", 1);

// ============================================================
// ADDITIONAL PRIVACY PROTECTIONS
// ============================================================
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("geo.enabled", false);
user_pref("beacon.enabled", false);

// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);

// Clear data on shutdown
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", false);

// Disable safebrowsing (sends URLs to Google)
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);

// UI settings
user_pref("browser.aboutConfig.showWarning", false);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.newtabpage.enabled", false);
`, device.Name, device.ProxyName, localPort, localPort, localPort)

	// Write prefs.js
	prefsPath := filepath.Join(profileDir, "prefs.js")
	os.WriteFile(prefsPath, []byte(prefs), 0644)

	// Also write user.js (applied on startup, overrides prefs.js)
	userJsPath := filepath.Join(profileDir, "user.js")
	os.WriteFile(userJsPath, []byte(prefs), 0644)
}

// ============================================================================
// LOCAL HTTP PROXY - Handles SOCKS5 authentication for Firefox
// ============================================================================

// localProxyHandler handles HTTP proxy requests and forwards through SOCKS5
type localProxyHandler struct {
	dialer proxy.Dialer
}

// startLocalProxy starts a local HTTP proxy that forwards through the upstream SOCKS5 proxy
func startLocalProxy(upstreamProxy string) (int, func(), error) {
	// Parse upstream: host:port:user:pass
	parts := strings.Split(upstreamProxy, ":")
	if len(parts) < 4 {
		return 0, nil, fmt.Errorf("invalid proxy format: expected host:port:user:pass")
	}

	proxyAddr := parts[0] + ":" + parts[1]
	auth := &proxy.Auth{
		User:     parts[2],
		Password: strings.Join(parts[3:], ":"), // Handle passwords with colons
	}

	// Create SOCKS5 dialer with authentication
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	// Start local HTTP proxy server on random available port
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

// ServeHTTP handles incoming proxy requests
func (h *localProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS CONNECT tunneling
func (h *localProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Connect to target through SOCKS5 proxy
	targetConn, err := h.dialer.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack the client connection
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

// handleHTTP handles plain HTTP requests
func (h *localProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Build target address
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	// Connect through SOCKS5 proxy
	targetConn, err := h.dialer.Dial("tcp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Forward the request
	if err := r.Write(targetConn); err != nil {
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}

	// Read and forward response
	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func startSession(device ClientDevice) string {
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	data := url.Values{}
	data.Set("action", "start")
	data.Set("device_id", device.ID)
	data.Set("device_name", device.Name)
	data.Set("proxy_name", device.ProxyName)
	data.Set("username", config.Username)
	data.Set("session_id", sessionID)

	resp, err := http.PostForm(config.ServerURL+"/api/client/session", data)
	if err != nil {
		fmt.Printf("Warning: Could not log session start: %v\n", err)
		return sessionID
	}
	defer resp.Body.Close()

	return sessionID
}

func endSession(device ClientDevice, sessionID string, durationSeconds int64) {
	data := url.Values{}
	data.Set("action", "stop")
	data.Set("device_id", device.ID)
	data.Set("device_name", device.Name)
	data.Set("proxy_name", device.ProxyName)
	data.Set("username", config.Username)
	data.Set("session_id", sessionID)
	data.Set("duration", strconv.FormatInt(durationSeconds, 10))

	resp, err := http.PostForm(config.ServerURL+"/api/client/session", data)
	if err != nil {
		fmt.Printf("Warning: Could not log session end: %v\n", err)
		return
	}
	defer resp.Body.Close()
}

func flushDNS() {
	fmt.Println("Flushing DNS cache...")
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ipconfig", "/flushdns")
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("sudo", "dscacheutil", "-flushcache")
	} else {
		// Linux
		cmd = exec.Command("sudo", "systemd-resolve", "--flush-caches")
	}
	cmd.Run()
}

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

func getColorName(hex string) string {
	colors := map[string]string{
		"#f44336": "🔴 Red",
		"#e91e63": "🩷 Pink",
		"#9c27b0": "🟣 Purple",
		"#673ab7": "🔮 Deep Purple",
		"#3f51b5": "🔵 Indigo",
		"#2196f3": "💙 Blue",
		"#03a9f4": "🩵 Light Blue",
		"#00bcd4": "🩵 Cyan",
		"#009688": "🩵 Teal",
		"#4caf50": "🟢 Green",
		"#8bc34a": "💚 Light Green",
		"#cddc39": "💛 Lime",
		"#ffeb3b": "💛 Yellow",
		"#ffc107": "🟡 Amber",
		"#ff9800": "🟠 Orange",
		"#ff5722": "🧡 Deep Orange",
	}
	if name, ok := colors[hex]; ok {
		return name
	}
	return "⚪"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func waitForEnter() {
	fmt.Println("\nPress Enter to exit...")
	readLine()
}
