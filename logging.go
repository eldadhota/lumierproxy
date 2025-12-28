package main

import (
	"time"
)

// ============================================================================
// LOGGING AND ACTIVITY TRACKING
// ============================================================================

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

	// Update AP device's LastActive on successful connections
	if success {
		s.apMu.Lock()
		for _, apDevice := range s.apDevices {
			if apDevice.IP == deviceIP {
				apDevice.LastSeen = time.Now()
				break
			}
		}
		s.apMu.Unlock()
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
