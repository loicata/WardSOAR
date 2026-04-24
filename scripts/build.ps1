<#
.SYNOPSIS
    Build WardSOAR MSI installer.
.DESCRIPTION
    Orchestrates PyInstaller build and WiX compilation
    to produce the final WardSOAR.msi installer.
.PARAMETER SkipPyInstaller
    Skip PyInstaller step, use existing dist/ folder.
.PARAMETER SkipMSI
    Skip WiX MSI step (for testing PyInstaller only).
.PARAMETER Version
    Override version string (default: read from src/__init__.py).
#>

param(
    [switch]$SkipPyInstaller,
    [switch]$SkipMSI,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Set-Location $ProjectRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WardSOAR Build Script (MSI)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# PHASE 1: Validate environment
# ============================================================
Write-Host "[1/6] Validating environment..." -ForegroundColor Yellow

# Check Python
$pythonPath = ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonPath)) {
    Write-Host "ERROR: Python venv not found at $pythonPath" -ForegroundColor Red
    Write-Host "Run: python -m venv .venv && .venv\Scripts\pip install -r requirements.txt" -ForegroundColor Red
    exit 1
}

$pythonVersion = & $pythonPath --version 2>&1
Write-Host "  Python: $pythonVersion" -ForegroundColor Green

# Check PyInstaller
$pyinstallerCheck = & $pythonPath -m PyInstaller --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: PyInstaller not installed." -ForegroundColor Red
    Write-Host "Run: .venv\Scripts\pip install pyinstaller" -ForegroundColor Red
    exit 1
}
Write-Host "  PyInstaller: $pyinstallerCheck" -ForegroundColor Green

# Check WiX (add dotnet tools to PATH)
$dotnetToolsPath = "$env:USERPROFILE\.dotnet\tools"
if ($env:PATH -notlike "*$dotnetToolsPath*") {
    $env:PATH = "$dotnetToolsPath;$env:PATH"
}

if (-not $SkipMSI) {
    $wixCheck = & wix --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: WiX Toolset not found." -ForegroundColor Red
        Write-Host "Run: dotnet tool install --global wix" -ForegroundColor Red
        exit 1
    }
    Write-Host "  WiX: $wixCheck" -ForegroundColor Green

    # Ensure WiX UI extension is available
    $wixExtCheck = & wix extension list 2>&1
    if ($wixExtCheck -notmatch "WixToolset.UI.wixext") {
        Write-Host "  Installing WiX UI extension..." -ForegroundColor Yellow
        & wix extension add WixToolset.UI.wixext 2>&1 | Out-Null
    }
    Write-Host "  WiX UI extension: OK" -ForegroundColor Green
}

# Check icon
if (-not (Test-Path "src\ui\assets\ward.ico")) {
    Write-Host "ERROR: Application icon not found at src\ui\assets\ward.ico" -ForegroundColor Red
    exit 1
}
Write-Host "  Icon: OK" -ForegroundColor Green

# Read version
if ($Version -eq "") {
    $initContent = Get-Content "src\__init__.py" -Raw
    if ($initContent -match '__version__\s*=\s*"([^"]+)"') {
        $Version = $Matches[1]
    } else {
        Write-Host "ERROR: Could not read version from src/__init__.py" -ForegroundColor Red
        exit 1
    }
}
Write-Host "  Version: $Version" -ForegroundColor Green
Write-Host ""

# ============================================================
# PHASE 1.5: Security scans (bandit + pip-audit)
# ============================================================
Write-Host "[1.5/6] Running security scans..." -ForegroundColor Yellow

$banditPath = ".venv\Scripts\bandit.exe"
$pipAuditPath = ".venv\Scripts\pip-audit.exe"

if (-not (Test-Path $banditPath)) {
    Write-Host "ERROR: bandit not installed. Run: .venv\Scripts\pip install -r requirements-dev.txt" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $pipAuditPath)) {
    Write-Host "ERROR: pip-audit not installed. Run: .venv\Scripts\pip install -r requirements-dev.txt" -ForegroundColor Red
    exit 1
}

# bandit: fail on MEDIUM+ findings. Lower ErrorActionPreference temporarily
# because bandit routinely writes benign WARNINGs to stderr ("Test in comment:
# required is not a test name") and PowerShell treats any stderr write as
# a NativeCommandError under "Stop" mode.
$ErrorActionPreference = "Continue"
& $banditPath -r src/ -ll --quiet 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
$banditExitCode = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($banditExitCode -ne 0) {
    Write-Host "ERROR: bandit found MEDIUM+ severity issues -- fix before building" -ForegroundColor Red
    exit 1
}
Write-Host "  bandit: 0 MEDIUM+ findings" -ForegroundColor Green

# pip-audit: fail on any CVE
$ErrorActionPreference = "Continue"
& $pipAuditPath -r requirements.txt 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
$pipAuditExitCode = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($pipAuditExitCode -ne 0) {
    Write-Host "ERROR: pip-audit found CVEs in dependencies -- upgrade before building" -ForegroundColor Red
    exit 1
}
Write-Host "  pip-audit: 0 CVEs" -ForegroundColor Green
Write-Host ""

# ============================================================
# PHASE 2: Clean previous build
# ============================================================
Write-Host "[2/6] Cleaning previous build artifacts..." -ForegroundColor Yellow

if (-not $SkipPyInstaller) {
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    Write-Host "  Cleaned build/ and dist/" -ForegroundColor Green
} else {
    # Only clean the MSI output
    Get-Item "dist\*.msi" -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Host "  Cleaned MSI output (keeping dist/WardSOAR/)" -ForegroundColor Green
}
Write-Host ""

# ============================================================
# PHASE 3: PyInstaller build
# ============================================================
if (-not $SkipPyInstaller) {
    Write-Host "[3/6] Running PyInstaller..." -ForegroundColor Yellow

    $ErrorActionPreference = "Continue"
    & $pythonPath -m PyInstaller installer\ward.spec --noconfirm 2>&1 | ForEach-Object {
        $line = $_.ToString()
        if ($line -match "ERROR") {
            Write-Host "  $line" -ForegroundColor Red
        } else {
            Write-Host "  $line" -ForegroundColor DarkGray
        }
    }
    $ErrorActionPreference = "Stop"

    if (-not (Test-Path "dist\WardSOAR\WardSOAR.exe")) {
        Write-Host "ERROR: PyInstaller build failed -- WardSOAR.exe not found in dist/" -ForegroundColor Red
        exit 1
    }
    Write-Host "  PyInstaller build successful" -ForegroundColor Green
} else {
    Write-Host "[3/6] Skipping PyInstaller (using existing dist/)" -ForegroundColor DarkGray
    if (-not (Test-Path "dist\WardSOAR\WardSOAR.exe")) {
        Write-Host "ERROR: dist\WardSOAR\WardSOAR.exe not found" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# ============================================================
# PHASE 4: Post-PyInstaller cleanup (remove unused Qt modules)
# ============================================================
# Lower the error preference for the whole cleanup phase. Remove-Item on
# a directory that's still held by Explorer can emit a non-terminating
# error that, under "Stop", aborts the whole script before Phase 5 even
# announces itself -- this is the bug that silently dropped the MSI
# output in builds prior to 0.5.1.
$ErrorActionPreference = "Continue"
Write-Host "[4/6] Cleaning unused Qt modules from dist..." -ForegroundColor Yellow

$qtCleanup = @(
    "dist\WardSOAR\PySide6\QtWebEngine*",
    "dist\WardSOAR\PySide6\Qt3D*",
    "dist\WardSOAR\PySide6\QtQuick*",
    "dist\WardSOAR\PySide6\QtQml*",
    "dist\WardSOAR\PySide6\QtMultimedia*",
    "dist\WardSOAR\PySide6\QtDesigner*",
    "dist\WardSOAR\PySide6\QtBluetooth*",
    "dist\WardSOAR\PySide6\QtNfc*",
    "dist\WardSOAR\PySide6\QtSensors*",
    "dist\WardSOAR\PySide6\QtSerialPort*",
    "dist\WardSOAR\PySide6\QtRemoteObjects*",
    "dist\WardSOAR\PySide6\translations"
)

$savedMB = 0
foreach ($pattern in $qtCleanup) {
    $items = Get-Item $pattern -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        $size = (Get-ChildItem $item -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        $savedMB += $size / 1MB
        Remove-Item -Recurse -Force $item -ErrorAction SilentlyContinue
    }
}

Write-Host ("  Removed {0:N0} MB of unused Qt modules" -f $savedMB) -ForegroundColor Green

$distSize = (Get-ChildItem "dist\WardSOAR" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
Write-Host ("  Final dist size: {0:N0} MB" -f $distSize) -ForegroundColor Green
Write-Host ""

# ============================================================
# PHASE 5: WiX MSI compilation
# ============================================================
if ($SkipMSI) {
    Write-Host "[5/6] Skipping MSI build" -ForegroundColor DarkGray
    Write-Host ""
} else {
    Write-Host "[5/6] Building MSI with WiX..." -ForegroundColor Yellow

    $wxsContent = Get-Content "installer\ward.wxs" -Raw
    $wxsContent = $wxsContent -replace 'Version="[0-9]+\.[0-9]+\.[0-9]+"', ('Version="' + $Version + '"')
    Set-Content "installer\ward.wxs" -Value $wxsContent -NoNewline

    $msiOutput = "dist\WardSOAR_$Version.msi"
    $wixPath = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
    if (-not (Test-Path $wixPath)) { $wixPath = "wix" }

    $ErrorActionPreference = "Continue"
    $wixLog = & $wixPath build installer\ward.wxs -ext WixToolset.UI.wixext -d "AppVersion=$Version" -o $msiOutput 2>&1
    $wixExitCode = $LASTEXITCODE
    $ErrorActionPreference = "Stop"

    foreach ($line in $wixLog) {
        Write-Host ("  " + $line)
    }

    if ($wixExitCode -ne 0) {
        Write-Host "ERROR: wix build exited with code $wixExitCode" -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path $msiOutput)) {
        Write-Host "ERROR: WiX reported success but $msiOutput is missing" -ForegroundColor Red
        exit 1
    }
    $msiBytes = (Get-Item $msiOutput).Length
    $msiSizeMB = [math]::Round($msiBytes / 1MB, 1)
    Write-Host "  MSI build successful ($msiSizeMB MB)" -ForegroundColor Green
    Write-Host ""
}

# ============================================================
# PHASE 6: Report
# ============================================================
Write-Host "[6/6] Build complete!" -ForegroundColor Green
Write-Host ""

if (-not $SkipMSI) {
    $msiFile = "dist\WardSOAR_$Version.msi"
    if (Test-Path $msiFile) {
        $msiSize = (Get-Item $msiFile).Length / 1MB
        Write-Host "  MSI Installer: $msiFile" -ForegroundColor Cyan
        Write-Host ("  Size: {0:N1} MB" -f $msiSize) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Install:  msiexec /i $msiFile" -ForegroundColor DarkCyan
        Write-Host "  Silent:   msiexec /i $msiFile /quiet" -ForegroundColor DarkCyan
        Write-Host "  Uninstall: msiexec /x $msiFile /quiet" -ForegroundColor DarkCyan
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Build finished successfully!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
