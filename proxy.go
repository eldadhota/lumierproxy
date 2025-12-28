package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ============================================================================
// TRAFFIC ANALYTICS
// ============================================================================

func collectTrafficSnapshots() {
	for range time.NewTicker(5 * time.Minute).C {
		server.apMu.RLock()
		var totalBytesIn, totalBytesOut, totalRequests, totalErrors int64
		activeDevices := 0
		for _, device := range server.apDevices {
			totalBytesIn += device.BytesIn
			totalBytesOut += device.BytesOut
			totalRequests += device.RequestCount
			totalErrors += device.ErrorCount
			if device.Confirmed && time.Since(device.LastSeen) < 5*time.Minute {
				activeDevices++
			}
		}
		server.apMu.RUnlock()

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
		server.apMu.RLock()
		proxyCounts := make(map[int]int)
		for _, device := range server.apDevices {
			if device.Confirmed && time.Since(device.LastSeen) < 5*time.Minute {
				proxyCounts[device.ProxyIndex]++
			}
		}
		server.apMu.RUnlock()

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

	// Non-AP devices are not allowed - must connect through the Access Point
	server.addLog("warn", fmt.Sprintf("[BLOCKED] Non-AP client %s tried to connect to %s", clientIP, r.Host))
	http.Error(w, "Access denied. Please connect through the Access Point.", http.StatusForbidden)
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
