# run_proxy.ps1
# Lumier Dynamics launcher for Windows

$ErrorActionPreference = "Stop"
Write-Host "=== Lumier Dynamics Proxy Launcher ===" -ForegroundColor Cyan
Write-Host ""

function Ensure-GoInstalled {
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        Write-Host "Go is installed: $($go.Source)" -ForegroundColor Green
        return
    }

    Write-Host "Go is not installed on this system." -ForegroundColor Yellow

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Host ""
        Write-Host "winget is not available, so I can't auto-install Go." -ForegroundColor Red
        Write-Host "Please download and install Go manually from https://go.dev/dl" -ForegroundColor Yellow
        Write-Host "Then run this script again." -ForegroundColor Yellow
        Read-Host "Press Enter to close"
        exit 1
    }

    Write-Host ""
    Write-Host "Installing Go via winget (this may take a few minutes)..." -ForegroundColor Yellow
    Write-Host "Command: winget install -e --id GoLang.Go" -ForegroundColor DarkGray

    winget install -e --id GoLang.Go

    Write-Host ""
    Write-Host "Go installation finished. Verifying..." -ForegroundColor Yellow
    $go = Get-Command go -ErrorAction SilentlyContinue
    if (-not $go) {
        Write-Host "Failed to detect Go even after install. Please log out / log in or restart and try again." -ForegroundColor Red
        Read-Host "Press Enter to close"
        exit 1
    }

    Write-Host "Go is now installed: $($go.Source)" -ForegroundColor Green
}

function Ensure-GoModule {
    param(
        [string]$ModulePath = "golang.org/x/net/proxy"
    )

    if (-not (Test-Path "go.mod")) {
        Write-Host ""
        Write-Host "go.mod not found, initializing module..." -ForegroundColor Yellow
        go mod init lumier-dynamics
    }

    # Check if module already present in go.mod/go.sum
    $modText = if (Test-Path "go.sum") { Get-Content "go.sum" -Raw } else { "" }
    if ($modText -notlike "*$ModulePath*") {
        Write-Host "Fetching Go dependency: $ModulePath" -ForegroundColor Yellow
        go get $ModulePath
    }
}

function Ensure-ProxiesFile {
    if (Test-Path "proxies.txt") {
        return
    }

    Write-Host ""
    Write-Host "proxies.txt not found, creating a template..." -ForegroundColor Yellow

    @"
# Put one proxy per line in this format:
# host:port:username:password
# Example:
# brd.superproxy.io:22228:brd-customer-XXXXX-zone-isp_thirty_sg-ip-1.2.3.4:yourpassword
"@ | Out-File -Encoding utf8 "proxies.txt"

    Write-Host "Created proxies.txt. Please edit it and add your proxies, then run this script again." -ForegroundColor Green
    Read-Host "Press Enter to close"
    exit 0
}

# ----- MAIN -----

# Move to the script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

Write-Host "Working directory: $scriptDir" -ForegroundColor DarkGray

Ensure-GoInstalled
Ensure-GoModule
Ensure-ProxiesFile

Write-Host ""
Write-Host "Starting Lumier Dynamics proxy (go run .)..." -ForegroundColor Cyan
Write-Host ""

# Run the Go program
go run .

Write-Host ""
Write-Host "Proxy exited. You can close this window." -ForegroundColor Yellow
Read-Host "Press Enter to close"
