@echo off
REM Simple launcher to run the PowerShell script with relaxed policy just for this run

powershell -ExecutionPolicy Bypass -File "%~dp0run_proxy.ps1"
