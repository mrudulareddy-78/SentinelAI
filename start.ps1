# ============================================================
# Sentinel Elite Core Orchestrator
# ============================================================

$ErrorActionPreference = 'Continue'
$ROOT = $PSScriptRoot

Write-Host ''
Write-Host '  ========================================' -ForegroundColor Cyan
Write-Host '    SENTINEL ELITE — Zero-Dependency     '  -ForegroundColor White
Write-Host '  ========================================' -ForegroundColor Cyan
Write-Host ''

# ---- 1. Data Migration ----
Write-Host '[1/3] Database Optimization...' -ForegroundColor Yellow
$venvPython = "$ROOT\Intelligence\.venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $migrateScript = "$ROOT\scripts\migrate_csv_to_sqlite.py"
    & "$venvPython" "$migrateScript"
}

# ---- 2. Gateway ----
Write-Host '[2/3] Starting Gateway (Port 5050)...' -ForegroundColor Yellow
$gatewayDir = "$ROOT\Gateway"
Start-Process -FilePath 'dotnet' -ArgumentList 'run' -WorkingDirectory $gatewayDir -WindowStyle Normal
Start-Sleep -Seconds 5
Write-Host '  -> Gateway Active.' -ForegroundColor Green

# ---- 3. AI and Dashboard ----
Write-Host '[3/3] Launching Components...' -ForegroundColor Yellow
$intelligenceDir = "$ROOT\Intelligence"
$dashboardApp = "$ROOT\Dashboard\app.py"

if (Test-Path $venvPython) {
    Start-Process -FilePath "$venvPython" -ArgumentList 'inference.py' -WorkingDirectory $intelligenceDir -WindowStyle Normal
    Start-Process -FilePath "$venvPython" -ArgumentList "$dashboardApp" -WorkingDirectory $ROOT -WindowStyle Normal
}

Write-Host ''
Write-Host '  Monitor: http://localhost:8501/monitor' -ForegroundColor Green
Write-Host ''

Start-Process 'http://localhost:8501/monitor'
