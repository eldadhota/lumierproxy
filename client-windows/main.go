package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// BrowserProfile represents a browser profile from the server
type BrowserProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ProxyIndex    int    `json:"proxy_index"`
	UpstreamProxy string `json:"upstream_proxy"`
	ProxyName     string `json:"proxy_name"`
	Color         string `json:"color"`
	Notes         string `json:"notes"`
	SessionCount  int64  `json:"session_count"`
}

// ProfilesResponse is the response from the API
type ProfilesResponse struct {
	Profiles      []BrowserProfile `json:"profiles"`
	TotalSessions int              `json:"total_sessions"`
	SessionsToday int              `json:"sessions_today"`
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
	fmt.Println("║           LUMIER DYNAMICS - Browser Profile Launcher       ║")
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

		// Fetch and display profiles
		profiles, err := fetchProfiles()
		if err != nil {
			fmt.Printf("❌ Error fetching profiles: %v\n", err)
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

		if len(profiles) == 0 {
			fmt.Println("No browser profiles configured on the server.")
			fmt.Println("Please create profiles in the dashboard first.")
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

		// Display profiles
		fmt.Println("╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    Available Profiles                      ║")
		fmt.Println("╠════════════════════════════════════════════════════════════╣")
		for i, p := range profiles {
			color := getColorName(p.Color)
			proxy := p.ProxyName
			if proxy == "" {
				proxy = fmt.Sprintf("Proxy #%d", p.ProxyIndex+1)
			}
			fmt.Printf("║  [%2d] %-20s │ %-15s │ %s\n", i+1, truncate(p.Name, 20), truncate(proxy, 15), color)
		}
		fmt.Println("╠════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  [U] Change user (current: %-30s ║\n", truncate(config.Username+")", 30))
		fmt.Println("║  [C] Change server URL                                     ║")
		fmt.Println("║  [R] Refresh list                                          ║")
		fmt.Println("║  [Q] Quit                                                  ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Print("Select profile number: ")

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

		// Parse profile selection
		num, err := strconv.Atoi(choice)
		if err != nil || num < 1 || num > len(profiles) {
			fmt.Println("Invalid selection. Please enter a number from the list.")
			time.Sleep(time.Second)
			continue
		}

		profile := profiles[num-1]
		launchProfile(profile, firefoxPath)
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

func fetchProfiles() ([]BrowserProfile, error) {
	resp, err := http.Get(config.ServerURL + "/api/client/profiles")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result ProfilesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Profiles, nil
}

func launchProfile(profile BrowserProfile, firefoxPath string) {
	fmt.Println()
	fmt.Printf("🚀 Launching profile: %s\n", profile.Name)
	fmt.Printf("   Proxy: %s\n", profile.ProxyName)
	fmt.Println()

	// Create a unique profile directory for this browser profile
	profileDir := getProfileDir(profile.ID)
	os.MkdirAll(profileDir, 0755)

	// Configure Firefox preferences for proxy
	configureFirefoxPrefs(profileDir, profile)

	// Start session
	sessionID := startSession(profile.ID)

	// Launch Firefox
	fmt.Println("Starting Firefox... (close the browser to end session)")
	fmt.Println()

	args := []string{
		"-profile", profileDir,
		"-no-remote",
	}

	cmd := exec.Command(firefoxPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("Firefox exited with error: %v\n", err)
	}

	// End session
	endSession(profile.ID, sessionID, int64(duration.Seconds()))

	fmt.Println()
	fmt.Printf("✓ Session ended. Duration: %s\n", formatDuration(int64(duration.Seconds())))
	fmt.Println()
	time.Sleep(2 * time.Second)

	// Flush DNS cache
	flushDNS()
}

func getProfileDir(profileID string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "LumierClient", "profiles", profileID)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lumier-client", "profiles", profileID)
}

func configureFirefoxPrefs(profileDir string, profile BrowserProfile) {
	// Parse the proxy string (format: host:port or host:port:user:pass)
	proxyHost := ""
	proxyPort := 0
	proxyUser := ""
	proxyPass := ""

	parts := strings.Split(profile.UpstreamProxy, ":")
	if len(parts) >= 2 {
		proxyHost = parts[0]
		proxyPort, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 4 {
		proxyUser = parts[2]
		proxyPass = parts[3]
	}

	// Create prefs.js for Firefox
	prefs := fmt.Sprintf(`// Lumier Dynamics Browser Profile Configuration
// Profile: %s
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
`, profile.Name, profile.ProxyName, proxyHost, proxyPort)

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

func startSession(profileID string) string {
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	data := url.Values{}
	data.Set("action", "start")
	data.Set("profile_id", profileID)
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

func endSession(profileID string, sessionID string, durationSeconds int64) {
	data := url.Values{}
	data.Set("action", "stop")
	data.Set("profile_id", profileID)
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
