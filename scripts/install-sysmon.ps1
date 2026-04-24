<#
.SYNOPSIS
    Download and install Microsoft Sysinternals Sysmon with a sensible config.
.DESCRIPTION
    Triggered from the WardSOAR "Install Sysmon" button (bootstrap
    checklist). Must be run elevated — WardSOAR launches it via
    ``Start-Process -Verb RunAs`` so Windows prompts for UAC.

    Steps:
      1. Download Sysmon.zip from Microsoft (download.sysinternals.com).
      2. Verify the Authenticode signature chains to Microsoft.
      3. Download the SwiftOnSecurity sysmonconfig-export.xml.
      4. Run Sysmon64.exe -accepteula -i <config>.
      5. Keep the console open so the operator can read the outcome.

    Fails loudly: any error stops the script, prints a red message,
    waits for Enter so the operator sees the reason before the window
    disappears.
#>

$ErrorActionPreference = "Stop"

$workDir = Join-Path $env:TEMP "wardsoar_sysmon_install"
$sysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WardSOAR Sysmon Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (Test-Path $workDir) {
    Remove-Item -Recurse -Force $workDir
}
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
Push-Location $workDir

try {
    Write-Host "[1/5] Downloading Sysmon.zip from Microsoft..."
    # Use TLS 1.2 explicitly — older Windows hosts default to TLS 1.0
    # which Sysinternals rejects.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $sysmonZipUrl -OutFile "Sysmon.zip" -UseBasicParsing
    Write-Host "    Downloaded $(((Get-Item Sysmon.zip).Length / 1KB).ToString('F1')) KB" -ForegroundColor DarkGray

    Write-Host "[2/5] Expanding archive..."
    Expand-Archive -Path "Sysmon.zip" -DestinationPath "Sysmon" -Force

    $sysmonExe = Join-Path $workDir "Sysmon\Sysmon64.exe"
    if (-not (Test-Path $sysmonExe)) {
        throw "Sysmon64.exe not found after extraction — archive format changed?"
    }

    Write-Host "[3/5] Verifying Authenticode signature..."
    $sig = Get-AuthenticodeSignature $sysmonExe
    if ($sig.Status -ne "Valid") {
        throw "Invalid Authenticode signature on Sysmon64.exe (status: $($sig.Status))"
    }
    if ($sig.SignerCertificate.Subject -notmatch "Microsoft") {
        throw "Sysmon64.exe signer is not Microsoft (got: $($sig.SignerCertificate.Subject))"
    }
    Write-Host "    Signed by $($sig.SignerCertificate.Subject.Split(',')[0])" -ForegroundColor DarkGray

    Write-Host "[4/5] Downloading SwiftOnSecurity sysmonconfig-export.xml..."
    Invoke-WebRequest -Uri $configUrl -OutFile "sysmonconfig-export.xml" -UseBasicParsing
    Write-Host "    Downloaded $(((Get-Item sysmonconfig-export.xml).Length / 1KB).ToString('F1')) KB" -ForegroundColor DarkGray

    Write-Host "[5/5] Installing Sysmon service..."
    & $sysmonExe -accepteula -i (Join-Path $workDir "sysmonconfig-export.xml")
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon64.exe -i exited with code $LASTEXITCODE"
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Sysmon installed successfully." -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "The WardSOAR banner in the Netgate tab will clear on its"
    Write-Host "next probe (up to a minute after this window closes)."
    Write-Host ""
    Read-Host "Press Enter to close"
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Installation failed." -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "You can still install Sysmon manually — see"
    Write-Host "docs/bootstrap-netgate.md, step 1."
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 1
}
finally {
    Pop-Location
}
