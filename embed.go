package main

import (
	"bytes"
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed dashboard/pages/*.html
//go:embed dashboard/assets/css/*.css
//go:embed dashboard/assets/js/*.js
//go:embed dashboard/partials/*.html
var dashboardFS embed.FS

// Cached page content (loaded once at startup)
var (
	loginPageHTML          []byte
	dashboardPageHTML      []byte
	healthPageHTML         []byte
	diagnosticsPageHTML    []byte
	analyticsPageHTML      []byte
	activityPageHTML       []byte
	browserProfilesPageHTML []byte
	settingsPageHTML       []byte
	monitoringPageHTML     []byte
	accessPointPageHTML    []byte
	deviceMonitorPageHTML  []byte
	navHTML                []byte
	baseStyles             []byte
	baseJS                 []byte
)

// initEmbeddedContent loads all embedded files into memory at startup
func initEmbeddedContent() {
	var err error

	loginPageHTML, err = dashboardFS.ReadFile("dashboard/pages/login.html")
	if err != nil {
		log.Fatal("Failed to load login.html:", err)
	}

	dashboardPageHTML, err = dashboardFS.ReadFile("dashboard/pages/dashboard.html")
	if err != nil {
		log.Fatal("Failed to load dashboard.html:", err)
	}

	healthPageHTML, err = dashboardFS.ReadFile("dashboard/pages/health.html")
	if err != nil {
		log.Fatal("Failed to load health.html:", err)
	}

	diagnosticsPageHTML, err = dashboardFS.ReadFile("dashboard/pages/diagnostics.html")
	if err != nil {
		log.Fatal("Failed to load diagnostics.html:", err)
	}

	analyticsPageHTML, err = dashboardFS.ReadFile("dashboard/pages/analytics.html")
	if err != nil {
		log.Fatal("Failed to load analytics.html:", err)
	}

	activityPageHTML, err = dashboardFS.ReadFile("dashboard/pages/activity.html")
	if err != nil {
		log.Fatal("Failed to load activity.html:", err)
	}

	browserProfilesPageHTML, err = dashboardFS.ReadFile("dashboard/pages/browser-profiles.html")
	if err != nil {
		log.Fatal("Failed to load browser-profiles.html:", err)
	}

	settingsPageHTML, err = dashboardFS.ReadFile("dashboard/pages/settings.html")
	if err != nil {
		log.Fatal("Failed to load settings.html:", err)
	}

	monitoringPageHTML, err = dashboardFS.ReadFile("dashboard/pages/monitoring.html")
	if err != nil {
		log.Fatal("Failed to load monitoring.html:", err)
	}

	accessPointPageHTML, err = dashboardFS.ReadFile("dashboard/pages/access-point.html")
	if err != nil {
		log.Fatal("Failed to load access-point.html:", err)
	}

	deviceMonitorPageHTML, err = dashboardFS.ReadFile("dashboard/pages/device-monitor.html")
	if err != nil {
		log.Fatal("Failed to load device-monitor.html:", err)
	}

	navHTML, err = dashboardFS.ReadFile("dashboard/partials/nav.html")
	if err != nil {
		log.Fatal("Failed to load nav.html:", err)
	}

	baseStyles, err = dashboardFS.ReadFile("dashboard/assets/css/base.css")
	if err != nil {
		log.Fatal("Failed to load base.css:", err)
	}

	baseJS, err = dashboardFS.ReadFile("dashboard/assets/js/base.js")
	if err != nil {
		log.Fatal("Failed to load base.js:", err)
	}

	// Assemble HTML by replacing placeholders with actual content
	dashboardPageHTML = assembleHTML(dashboardPageHTML)
	healthPageHTML = assembleHTML(healthPageHTML)
	diagnosticsPageHTML = assembleHTML(diagnosticsPageHTML)
	analyticsPageHTML = assembleHTML(analyticsPageHTML)
	activityPageHTML = assembleHTML(activityPageHTML)
	browserProfilesPageHTML = assembleHTML(browserProfilesPageHTML)
	settingsPageHTML = assembleHTML(settingsPageHTML)
	monitoringPageHTML = assembleHTML(monitoringPageHTML)
	accessPointPageHTML = assembleHTML(accessPointPageHTML)
	deviceMonitorPageHTML = assembleHTML(deviceMonitorPageHTML)

	log.Println("Loaded embedded dashboard content")
}

// assembleHTML replaces Go template placeholders with actual content
func assembleHTML(html []byte) []byte {
	// Replace ` + baseStyles + ` with actual CSS
	html = bytes.ReplaceAll(html, []byte("` + baseStyles + `"), baseStyles)
	// Replace ` + baseJS + ` with actual JS
	html = bytes.ReplaceAll(html, []byte("` + baseJS + `"), baseJS)
	// Replace ` + navHTML + ` with actual nav HTML
	html = bytes.ReplaceAll(html, []byte("` + navHTML + `"), navHTML)
	return html
}

// registerStaticRoutes sets up static file serving for CSS and JS
func registerStaticRoutes() {
	assetsFS, err := fs.Sub(dashboardFS, "dashboard/assets")
	if err != nil {
		log.Fatal("Failed to create assets sub-fs:", err)
	}

	http.Handle("/static/", http.StripPrefix("/static/",
		http.FileServer(http.FS(assetsFS))))
}
