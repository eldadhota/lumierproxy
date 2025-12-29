package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// ============================================================================
// DASHBOARD SERVER & ROUTE REGISTRATION
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
	http.HandleFunc("/api/ap/device/bypass", server.requireAuth(handleAPDeviceBypassAPI))

	// Browser Profiles API
	http.HandleFunc("/browsers", server.requireAuth(handleBrowserProfilesPage))
	http.HandleFunc("/api/browser-profiles", server.requireAuth(handleBrowserProfilesAPI))
	http.HandleFunc("/api/browser-profiles/create", server.requireAuth(handleCreateBrowserProfileAPI))
	http.HandleFunc("/api/browser-profiles/update", server.requireAuth(handleUpdateBrowserProfileAPI))
	http.HandleFunc("/api/browser-profiles/delete", server.requireAuth(handleDeleteBrowserProfileAPI))
	http.HandleFunc("/api/browser-profiles/session", server.requireAuth(handleBrowserSessionAPI))
	http.HandleFunc("/api/browser-profiles/client-download", handleClientDownload)

	// Client API (no auth required - for Windows client app)
	http.HandleFunc("/api/client/profiles", handleClientProfilesAPI)
	http.HandleFunc("/api/client/session", handleClientSessionAPI)

	http.HandleFunc("/dashboard", server.requireAuth(handleDashboard))
	http.HandleFunc("/health", server.requireAuth(handleHealthPage))
	http.HandleFunc("/diagnostics", server.requireAuth(handleDiagnosticsPage))
	http.HandleFunc("/analytics", server.requireAuth(handleAnalyticsPage))
	http.HandleFunc("/activity", server.requireAuth(handleActivityPage))
	http.HandleFunc("/device-monitor", server.requireAuth(handleDeviceMonitorPage))
	http.HandleFunc("/screenshots", server.requireAuth(handleScreenshotsPage))
	http.HandleFunc("/settings", server.requireAuth(handleSettingsPage))
	http.HandleFunc("/monitoring", server.requireAuth(handleMonitoringPage))

	http.HandleFunc("/api/stats", server.requireAuth(handleStatsAPI))
	http.HandleFunc("/api/devices", server.requireAuth(handleDevicesAPI))
	http.HandleFunc("/api/server-ip", server.requireAuth(handleServerIPAPI))
	http.HandleFunc("/api/proxies", server.requireAuth(handleProxiesAPI))
	http.HandleFunc("/api/groups", server.requireAuth(handleGroupsAPI))
	http.HandleFunc("/api/add-group", server.requireAuth(handleAddGroupAPI))
	http.HandleFunc("/api/delete-group", server.requireAuth(handleDeleteGroupAPI))
	http.HandleFunc("/api/add-proxy", server.requireAuth(handleAddProxyAPI))
	http.HandleFunc("/api/delete-proxy", server.requireAuth(handleDeleteProxyAPI))
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

	// Screenshot API (Dashboard)
	http.HandleFunc("/api/screenshot/request", server.requireAuth(handleScreenshotRequest))
	http.HandleFunc("/api/screenshot/list", server.requireAuth(handleScreenshotList))
	http.HandleFunc("/api/screenshot/image", server.requireAuth(handleScreenshotImage))
	http.HandleFunc("/api/screenshot/delete", server.requireAuth(handleScreenshotDelete))
	http.HandleFunc("/api/screenshot/active-devices", server.requireAuth(handleActiveDevicesAPI))

	// Client Screenshot API (no auth - used by Windows client)
	http.HandleFunc("/api/client/screenshot/pending", handleClientScreenshotPending)
	http.HandleFunc("/api/client/screenshot/upload", handleClientScreenshotUpload)

	log.Printf("📊 Dashboard on port %d\n", server.dashPort)
	addr := fmt.Sprintf("%s:%d", server.bindAddr, server.dashPort)
	// Use http.Server with timeouts for security
	dashServer := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := dashServer.ListenAndServe(); err != nil {
		log.Fatalf("failed to start dashboard on %s: %v", addr, err)
	}
}
