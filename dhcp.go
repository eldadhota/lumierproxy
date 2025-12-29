package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Google domains that can be bypassed during device setup
var googleDomains = []string{
	"google.com", "google.co", "googleapis.com", "gstatic.com",
	"googleusercontent.com", "googledrive.com", "gmail.com",
	"android.com", "gvt1.com", "gvt2.com", "gvt3.com",
	"ggpht.com", "googleadservices.com", "doubleclick.net",
	"google-analytics.com", "googlesyndication.com",
}

// isGoogleService checks if a host is a Google service that can be bypassed
func isGoogleService(hostPort string) bool {
	host := strings.ToLower(hostPort)
	// Remove port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for _, domain := range googleDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// ============================================================================
// ACCESS POINT CLIENT MANAGEMENT
// ============================================================================

// isAPClient checks if an IP is from the AP network (10.10.10.x)
func (s *ProxyServer) isAPClient(ip string) bool {
	return strings.HasPrefix(ip, "10.10.10.")
}

// getAPDeviceByIP finds an AP device by its current IP address (O(1) lookup via index)
func (s *ProxyServer) getAPDeviceByIP(ip string) *APDevice {
	s.apMu.RLock()
	defer s.apMu.RUnlock()
	if mac, exists := s.apIPToMAC[ip]; exists {
		return s.apDevices[mac]
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

// ============================================================================
// DHCP LEASE MONITORING
// ============================================================================

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
			// Update IP-to-MAC index if IP changed
			if device.IP != ip {
				delete(s.apIPToMAC, device.IP) // Remove old IP mapping
			}
			s.apIPToMAC[ip] = mac // Add/update new IP mapping
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
			s.apIPToMAC[ip] = mac // Add IP-to-MAC mapping

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

	// Mark devices not in current leases as offline and clean up IP index
	s.apMu.Lock()
	for mac, device := range s.apDevices {
		if !currentLeases[mac] && device.Status == "online" {
			// Check if device was seen recently (within 2 minutes)
			if time.Since(device.LastSeen) > 2*time.Minute {
				device.Status = "offline"
				delete(s.apIPToMAC, device.IP) // Remove from IP index when offline
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

// ============================================================================
// AP TRAFFIC HANDLING
// ============================================================================

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

	var upstream net.Conn
	var err error

	// Google bypass: connect directly if enabled for this device
	if device.GoogleBypass && isGoogleService(target) {
		upstream, err = net.DialTimeout("tcp", target, 30*time.Second)
		if err == nil {
			server.addLog("info", fmt.Sprintf("[AP] Google bypass HTTPS: %s -> %s (direct)", device.CustomName, target))
		}
	} else {
		upstream, err = dialThroughSOCKS5(target, device.UpstreamProxy)
	}
	if err != nil {
		server.apMu.Lock()
		atomic.AddInt64(&device.ErrorCount, 1)
		device.LastError = err.Error()
		device.LastErrorTime = time.Now()
		server.apMu.Unlock()
		server.recordProxyFailure(device.ProxyIndex, err.Error())
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

	var upstream net.Conn
	var err error

	// Google bypass: connect directly if enabled for this device
	if device.GoogleBypass && isGoogleService(target) {
		upstream, err = net.DialTimeout("tcp", target, 30*time.Second)
		if err == nil {
			server.addLog("info", fmt.Sprintf("[AP] Google bypass HTTP: %s -> %s (direct)", device.CustomName, target))
		}
	} else {
		upstream, err = dialThroughSOCKS5(target, device.UpstreamProxy)
	}
	if err != nil {
		server.apMu.Lock()
		atomic.AddInt64(&device.ErrorCount, 1)
		device.LastError = err.Error()
		device.LastErrorTime = time.Now()
		server.apMu.Unlock()
		server.recordProxyFailure(device.ProxyIndex, err.Error())
		http.Error(w, "Failed to connect to upstream proxy", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Normalize request to origin-form for upstream server
	// Clients send absolute-form (GET http://example.com/path HTTP/1.1)
	// but origin servers expect origin-form (GET /path HTTP/1.1)
	outReq := new(http.Request)
	*outReq = *r // Shallow copy

	// Build origin-form URL (just path + query)
	outReq.URL = &url.URL{
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	if outReq.URL.Path == "" {
		outReq.URL.Path = "/"
	}

	// Clear RequestURI (Go requires this to be empty for client requests)
	outReq.RequestURI = ""

	// Copy headers and remove proxy-specific ones
	outReq.Header = make(http.Header)
	for key, values := range r.Header {
		// Skip proxy-specific headers
		if strings.EqualFold(key, "Proxy-Connection") ||
			strings.EqualFold(key, "Proxy-Authenticate") ||
			strings.EqualFold(key, "Proxy-Authorization") {
			continue
		}
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	// Ensure Host header is set
	if outReq.Header.Get("Host") == "" {
		outReq.Header.Set("Host", r.Host)
	}

	// Forward the normalized request
	if err := outReq.Write(upstream); err != nil {
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
