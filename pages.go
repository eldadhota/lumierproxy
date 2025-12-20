package main

import (
	"net/http"
)

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(loginPageHTML))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}

func handleHealthPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(healthPageHTML))
}

func handleDeviceHealthPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(deviceHealthPageHTML))
}

func handleAnalyticsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(analyticsPageHTML))
}

func handleActivityPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(activityPageHTML))
}

func handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(settingsPageHTML))
}

func handleMonitoringPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(monitoringPageHTML))
}

func handleAuditPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(auditPageHTML))
}

// HTML templates - these would be your actual HTML pages
// For brevity, providing minimal working templates

const loginPageHTML = `<!DOCTYPE html>
<html><head><title>LumierProxy - Login</title>
<style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e}
.login{background:#16213e;padding:40px;border-radius:10px;color:#fff}
input{display:block;margin:10px 0;padding:10px;width:200px;border:none;border-radius:5px}
button{background:#e94560;color:#fff;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;width:100%}</style></head>
<body><div class="login"><h2>🌐 LumierProxy</h2>
<form onsubmit="login(event)"><input type="text" id="user" placeholder="Username" required>
<input type="password" id="pass" placeholder="Password" required><button type="submit">Login</button></form></div>
<script>async function login(e){e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:document.getElementById('user').value,password:document.getElementById('pass').value})});
if(r.ok)location.href='/dashboard';else alert('Login failed')}</script></body></html>`

const dashboardHTML = `<!DOCTYPE html>
<html><head><title>LumierProxy Dashboard</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:20px}
.stat{background:#16213e;padding:20px;border-radius:10px;text-align:center}
.stat h3{font-size:2em;color:#e94560}.devices{background:#16213e;border-radius:10px;padding:20px}
table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #333}
.online{color:#4ade80}.offline{color:#f87171}.btn{background:#e94560;color:#fff;border:none;padding:5px 10px;border-radius:5px;cursor:pointer}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard" class="active">Dashboard</a><a href="/device-health">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity">Activity</a><a href="/audit">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><div class="stats" id="stats"></div><div class="devices"><h2>Connected Devices</h2>
<table><thead><tr><th>Username</th><th>IP</th><th>Proxy</th><th>Status</th><th>Health</th><th>Requests</th><th>Actions</th></tr></thead>
<tbody id="devices"></tbody></table></div></div>
<script>async function loadData(){const[stats,devices,proxies]=await Promise.all([fetch('/api/stats').then(r=>r.json()),
fetch('/api/devices').then(r=>r.json()),fetch('/api/proxies').then(r=>r.json())]);
document.getElementById('stats').innerHTML='<div class="stat"><h3>'+stats.active_devices+'</h3><p>Active Devices</p></div>'+
'<div class="stat"><h3>'+stats.total_devices+'</h3><p>Total Devices</p></div>'+
'<div class="stat"><h3>'+stats.total_proxies+'</h3><p>Proxies</p></div>'+
'<div class="stat"><h3>'+formatBytes(stats.total_bytes_in+stats.total_bytes_out)+'</h3><p>Total Traffic</p></div>';
document.getElementById('devices').innerHTML=devices.map(d=>'<tr><td>'+d.username+'</td><td>'+d.ip+'</td>'+
'<td>'+(proxies.find(p=>p.full===d.upstream_proxy)?.custom_name||'Unknown')+'</td>'+
'<td class="'+(isOnline(d.last_seen)?'online':'offline')+'">'+(isOnline(d.last_seen)?'Online':'Offline')+'</td>'+
'<td>'+d.health_score+'%</td><td>'+d.request_count+'</td><td><button class="btn" onclick="deleteDevice(\''+d.username+'\')">Delete</button></td></tr>').join('')}
function isOnline(t){return new Date()-new Date(t)<300000}
function formatBytes(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB'}
async function deleteDevice(u){if(confirm('Delete device '+u+'?')){await fetch('/api/delete-device',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});loadData()}}
async function logout(){await fetch('/api/logout');location.href='/'}
loadData();setInterval(loadData,5000)</script></body></html>`

const deviceHealthPageHTML = `<!DOCTYPE html>
<html><head><title>Device Health - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-bottom:20px}
.stat{background:#16213e;padding:15px;border-radius:10px;text-align:center}
.stat.healthy{border-left:4px solid #4ade80}.stat.degraded{border-left:4px solid #fbbf24}
.stat.unhealthy{border-left:4px solid #f87171}.stat.offline{border-left:4px solid #888}
.devices{background:#16213e;border-radius:10px;padding:20px}table{width:100%;border-collapse:collapse}
th,td{padding:10px;text-align:left;border-bottom:1px solid #333}
.healthy{color:#4ade80}.degraded{color:#fbbf24}.unhealthy{color:#f87171}.offline{color:#888}
.btn{background:#e94560;color:#fff;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;margin:2px}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health" class="active">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity">Activity</a><a href="/audit">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>📱 Device Health Monitor</h2><p style="color:#888;margin:10px 0">Real-time health status of connected devices</p>
<div class="stats" id="healthStats"></div>
<div class="devices"><table><thead><tr><th>Device</th><th>Status</th><th>Health</th><th>Proxy</th><th>Last Check</th><th>Session</th><th>Success Rate</th><th>Actions</th></tr></thead>
<tbody id="deviceHealth"></tbody></table></div></div>
<script>async function loadHealth(){const[stats,health]=await Promise.all([fetch('/api/device-health-stats').then(r=>r.json()),fetch('/api/device-health').then(r=>r.json())]);
document.getElementById('healthStats').innerHTML=
'<div class="stat healthy"><h3>'+stats.healthy+'</h3><p>Healthy</p></div>'+
'<div class="stat degraded"><h3>'+stats.degraded+'</h3><p>Degraded</p></div>'+
'<div class="stat unhealthy"><h3>'+stats.unhealthy+'</h3><p>Unhealthy</p></div>'+
'<div class="stat offline"><h3>'+stats.offline+'</h3><p>Offline</p></div>'+
'<div class="stat"><h3>'+stats.avg_health_score+'%</h3><p>Avg Health</p></div>';
document.getElementById('deviceHealth').innerHTML=health.map(d=>
'<tr><td><strong>'+(d.custom_name||d.username)+'</strong><br><small>'+d.ip+'</small></td>'+
'<td class="'+d.status+'">'+d.status.toUpperCase()+'</td>'+
'<td><div style="background:#333;border-radius:5px;overflow:hidden;width:100px;height:20px">'+
'<div style="background:'+(d.health_score>=80?'#4ade80':d.health_score>=50?'#fbbf24':'#f87171')+';height:100%;width:'+d.health_score+'%"></div></div>'+d.health_score+'%</td>'+
'<td>'+d.proxy_name+'<br><small>'+d.proxy_ip+'</small></td>'+
'<td>'+d.proxy_check_status+'<br><small>'+formatTime(d.last_proxy_check)+'</small></td>'+
'<td>'+(d.session_valid?'<span class="healthy">Valid</span>':'<span class="unhealthy">Expired</span>')+'</td>'+
'<td>'+d.success_rate.toFixed(1)+'%</td>'+
'<td><button class="btn" onclick="verifyDevice(\''+d.username+'\')">Verify</button></td></tr>').join('')}
function formatTime(t){if(!t||t==='0001-01-01T00:00:00Z')return'Never';const d=new Date(t);return d.toLocaleTimeString()}
async function verifyDevice(u){const r=await fetch('/api/verify-device-proxy',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});
const res=await r.json();alert('Verification: '+res.status+' (Health: '+res.health_score+'%)');loadHealth()}
async function logout(){await fetch('/api/logout');location.href='/'}
loadHealth();setInterval(loadHealth,10000)</script></body></html>`

const healthPageHTML = `<!DOCTYPE html>
<html><head><title>Proxy Health - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.proxies{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}
.proxy{background:#16213e;padding:20px;border-radius:10px}
.proxy.healthy{border-left:4px solid #4ade80}.proxy.degraded{border-left:4px solid #fbbf24}
.proxy.unhealthy{border-left:4px solid #f87171}.proxy.unknown{border-left:4px solid #888}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health">Device Health</a><a href="/health" class="active">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity">Activity</a><a href="/audit">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>Proxy Health Status</h2>
<div class="proxies" id="proxies"></div></div>
<script>async function loadHealth(){const proxies=await fetch('/api/proxy-health').then(r=>r.json());
document.getElementById('proxies').innerHTML=proxies.map(p=>
'<div class="proxy '+p.status+'"><h3>SG'+(p.index+1)+' - '+p.ip_address+'</h3>'+
'<p>Status: <strong>'+p.status.toUpperCase()+'</strong></p>'+
'<p>Success Rate: '+p.success_rate.toFixed(1)+'%</p>'+
'<p>Total Requests: '+p.total_requests+'</p>'+
'<p>Active Devices: '+p.active_devices+'</p>'+
'<p>Avg Response: '+p.avg_response_time_ms+'ms</p></div>').join('')}
async function logout(){await fetch('/api/logout');location.href='/'}
loadHealth();setInterval(loadHealth,10000)</script></body></html>`

const analyticsPageHTML = `<!DOCTYPE html>
<html><head><title>Analytics - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.chart{background:#16213e;padding:20px;border-radius:10px;margin-bottom:20px}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics" class="active">Analytics</a><a href="/activity">Activity</a><a href="/audit">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>Traffic Analytics</h2><div class="chart" id="chart">Loading...</div></div>
<script>async function loadAnalytics(){const data=await fetch('/api/traffic-history').then(r=>r.json());
document.getElementById('chart').innerHTML='<p>'+data.length+' snapshots collected</p>'+
'<p>Latest: '+(data.length?JSON.stringify(data[data.length-1]):'No data')+'</p>'}
async function logout(){await fetch('/api/logout');location.href='/'}
loadAnalytics()</script></body></html>`

const activityPageHTML = `<!DOCTYPE html>
<html><head><title>Activity - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.logs{background:#16213e;padding:20px;border-radius:10px;max-height:600px;overflow-y:auto}
.log{padding:10px;border-bottom:1px solid #333}.log.error{border-left:3px solid #f87171}
.log.warn{border-left:3px solid #fbbf24}.log.info{border-left:3px solid #4ade80}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity" class="active">Activity</a><a href="/audit">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>Activity Log</h2><div class="logs" id="logs"></div></div>
<script>async function loadLogs(){const logs=await fetch('/api/logs?limit=100').then(r=>r.json());
document.getElementById('logs').innerHTML=logs.reverse().map(l=>
'<div class="log '+l.level+'"><small>'+new Date(l.timestamp).toLocaleString()+'</small> '+
(l.username?'['+l.username+'] ':'')+l.message+'</div>').join('')}
async function logout(){await fetch('/api/logout');location.href='/'}
loadLogs();setInterval(loadLogs,5000)</script></body></html>`

const auditPageHTML = `<!DOCTYPE html>
<html><head><title>Audit Log - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.filters{margin-bottom:20px}select{padding:8px;background:#16213e;color:#fff;border:1px solid #333;border-radius:5px}
.logs{background:#16213e;padding:20px;border-radius:10px}table{width:100%;border-collapse:collapse}
th,td{padding:10px;text-align:left;border-bottom:1px solid #333}.success{color:#4ade80}.failure{color:#f87171}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity">Activity</a><a href="/audit" class="active">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>🔒 Audit Log</h2>
<div class="filters"><select id="category" onchange="loadAudit()"><option value="">All Categories</option>
<option value="auth">Authentication</option><option value="device">Device</option><option value="proxy">Proxy</option>
<option value="session">Session</option><option value="config">Config</option></select></div>
<div class="logs"><table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>IP</th><th>Details</th><th>Status</th></tr></thead>
<tbody id="auditLogs"></tbody></table></div></div>
<script>async function loadAudit(){const cat=document.getElementById('category').value;
const logs=await fetch('/api/audit-logs?limit=200&category='+cat).then(r=>r.json());
document.getElementById('auditLogs').innerHTML=logs.reverse().map(l=>
'<tr><td>'+new Date(l.timestamp).toLocaleString()+'</td><td>'+l.event+'</td><td>'+l.username+'</td><td>'+l.ip+'</td>'+
'<td>'+l.details+'</td><td class="'+(l.success?'success':'failure')+'">'+(l.success?'✓':'✗')+'</td></tr>').join('')}
async function logout(){await fetch('/api/logout');location.href='/'}
loadAudit();setInterval(loadAudit,10000)</script></body></html>`

const settingsPageHTML = `<!DOCTYPE html>
<html><head><title>Settings - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.section{background:#16213e;padding:20px;border-radius:10px;margin-bottom:20px}
input,select{padding:8px;background:#1a1a2e;color:#fff;border:1px solid #333;border-radius:5px;margin:5px 0}
.btn{background:#e94560;color:#fff;border:none;padding:10px 20px;border-radius:5px;cursor:pointer}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity">Activity</a><a href="/audit">Audit</a><a href="/settings" class="active">Settings</a>
<a href="/monitoring">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>Settings</h2>
<div class="section"><h3>Session Settings</h3>
<p>Session Timeout: <input type="number" id="sessionTimeout" min="1" max="24"> hours</p>
<p>Device Health Check: <input type="number" id="healthCheck" min="1" max="60"> minutes</p>
<p>Max Consecutive Errors: <input type="number" id="maxErrors" min="1" max="20"></p>
<button class="btn" onclick="saveSettings()">Save Settings</button></div>
<div class="section"><h3>Server Info</h3><div id="serverInfo"></div></div></div>
<script>async function loadSettings(){const[settings,info]=await Promise.all([fetch('/api/session-settings').then(r=>r.json()),fetch('/api/server-ip').then(r=>r.json())]);
document.getElementById('sessionTimeout').value=settings.session_timeout_hours;
document.getElementById('healthCheck').value=settings.device_health_check_mins;
document.getElementById('maxErrors').value=settings.max_consecutive_errors;
document.getElementById('serverInfo').innerHTML='<p>Server IP: '+info.ip+'</p><p>Proxy Port: '+info.proxy_port+'</p><p>Dashboard Port: '+info.dash_port+'</p>'}
async function saveSettings(){await fetch('/api/session-settings',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({session_timeout_hours:parseInt(document.getElementById('sessionTimeout').value),
device_health_check_mins:parseInt(document.getElementById('healthCheck').value),
max_consecutive_errors:parseInt(document.getElementById('maxErrors').value)})});alert('Settings saved!')}
async function logout(){await fetch('/api/logout');location.href='/'}
loadSettings()</script></body></html>`

const monitoringPageHTML = `<!DOCTYPE html>
<html><head><title>Monitoring - LumierProxy</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial;background:#0f0f23;color:#fff}
.nav{background:#1a1a2e;padding:15px;display:flex;gap:20px;align-items:center}
.nav a{color:#888;text-decoration:none}.nav a:hover,.nav a.active{color:#e94560}
.content{padding:20px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px}
.stat{background:#16213e;padding:20px;border-radius:10px;text-align:center}.stat h3{font-size:2em;color:#e94560}</style></head>
<body><nav class="nav"><span>🌐 LumierProxy</span>
<a href="/dashboard">Dashboard</a><a href="/device-health">Device Health</a><a href="/health">Proxy Health</a>
<a href="/analytics">Analytics</a><a href="/activity">Activity</a><a href="/audit">Audit</a><a href="/settings">Settings</a>
<a href="/monitoring" class="active">Monitoring</a><a href="#" onclick="logout()">Logout</a></nav>
<div class="content"><h2>System Monitoring</h2><div class="stats" id="stats"></div></div>
<script>async function loadStats(){const s=await fetch('/api/system-stats').then(r=>r.json());
document.getElementById('stats').innerHTML=
'<div class="stat"><h3>'+s.cpu_percent.toFixed(1)+'%</h3><p>CPU Usage</p></div>'+
'<div class="stat"><h3>'+(s.memory_alloc/1048576).toFixed(1)+' MB</h3><p>Memory Used</p></div>'+
'<div class="stat"><h3>'+s.goroutines+'</h3><p>Goroutines</p></div>'+
'<div class="stat"><h3>'+formatUptime(s.uptime_seconds)+'</h3><p>Uptime</p></div>'}
function formatUptime(s){const h=Math.floor(s/3600);const m=Math.floor((s%3600)/60);return h+'h '+m+'m'}
async function logout(){await fetch('/api/logout');location.href='/'}
loadStats();setInterval(loadStats,2000)</script></body></html>`
