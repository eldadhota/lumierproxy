package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// ============================================================================
// PROXY POOL LOADING
// ============================================================================

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

// ============================================================================
// PROXY HEALTH INITIALIZATION
// ============================================================================

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
	// Restore browser profiles to runtime map
	if s.persistentData.BrowserProfiles != nil {
		s.browserMu.Lock()
		for id, profile := range s.persistentData.BrowserProfiles {
			s.browserProfiles[id] = profile
		}
		s.browserMu.Unlock()
		log.Printf("Restored %d browser profiles from storage\n", len(s.persistentData.BrowserProfiles))
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
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	// Deep copy proxy health data to avoid race during marshal
	s.healthMu.RLock()
	healthSnapshot := make(map[int]*ProxyHealth)
	for k, v := range s.proxyHealth {
		// Deep copy the struct to avoid pointer mutation during marshal
		healthCopy := *v
		healthSnapshot[k] = &healthCopy
	}
	s.healthMu.RUnlock()

	// Deep copy AP devices to avoid race during marshal
	s.apMu.RLock()
	deviceSnapshot := make(map[string]*APDevice)
	for mac, device := range s.apDevices {
		// Deep copy the struct (APDevice has no slice fields, so shallow copy is safe)
		deviceCopy := *device
		deviceSnapshot[mac] = &deviceCopy
	}
	configSnapshot := s.apConfig // Struct copy
	s.apMu.RUnlock()

	// Now we can safely update persistentData and marshal
	s.persistentData.ProxyHealthData = healthSnapshot
	s.persistentData.APDevices = deviceSnapshot
	s.persistentData.APConfig = configSnapshot

	data, _ := json.MarshalIndent(s.persistentData, "", "  ")
	os.WriteFile(s.dataFile, data, 0644)
}

func autoSaveData() {
	for range time.NewTicker(5 * time.Minute).C {
		server.savePersistentData()
	}
}

// pruneStaleDevices removes old pending and long-offline devices
func pruneStaleDevices() {
	for range time.NewTicker(1 * time.Hour).C {
		server.pruneDevices()
	}
}

func (s *ProxyServer) pruneDevices() {
	pendingHours := s.persistentData.SystemSettings.PrunePendingAfterHours
	offlineDays := s.persistentData.SystemSettings.PruneOfflineAfterDays

	// Skip if both pruning options are disabled
	if pendingHours <= 0 && offlineDays <= 0 {
		return
	}

	now := time.Now()
	var pruned []string

	s.apMu.Lock()
	for mac, device := range s.apDevices {
		// Prune pending (unapproved) devices after configured hours
		if pendingHours > 0 && !device.Confirmed {
			if now.Sub(device.FirstSeen) > time.Duration(pendingHours)*time.Hour {
				pruned = append(pruned, fmt.Sprintf("%s (pending, first seen %s ago)", mac, now.Sub(device.FirstSeen).Round(time.Hour)))
				delete(s.apDevices, mac)
				delete(s.apIPToMAC, device.IP)
				continue
			}
		}

		// Prune long-offline confirmed devices after configured days
		if offlineDays > 0 && device.Confirmed {
			if now.Sub(device.LastSeen) > time.Duration(offlineDays)*24*time.Hour {
				pruned = append(pruned, fmt.Sprintf("%s (offline, last seen %s ago)", mac, now.Sub(device.LastSeen).Round(time.Hour)))
				delete(s.apDevices, mac)
				delete(s.apIPToMAC, device.IP)
				continue
			}
		}
	}
	s.apMu.Unlock()

	if len(pruned) > 0 {
		s.addLog("info", fmt.Sprintf("Pruned %d stale devices: %v", len(pruned), pruned))
		s.savePersistentData()
	}
}
