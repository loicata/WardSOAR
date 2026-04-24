#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Grant the current user read access to Sysmon and Security event logs.
.DESCRIPTION
    Modifies the channel ACL to allow non-admin read access.
    Takes effect immediately — no reboot or logoff required.
#>

$ErrorActionPreference = "Stop"

# Get current user SID
$userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Write-Host "User SID: $userSID"

# Sysmon channel — get current SDDL, append read access for user
$sysmonChannel = "Microsoft-Windows-Sysmon/Operational"
try {
    $currentSDDL = (wevtutil gl $sysmonChannel | Select-String "channelAccess").ToString().Split(":")[-1].Trim()
    Write-Host "Current Sysmon SDDL: $currentSDDL"

    # Append read access (0x1 = read) for user SID
    $newSDDL = $currentSDDL + "(A;;0x1;;;$userSID)"
    wevtutil sl $sysmonChannel /ca:$newSDDL
    Write-Host "Sysmon: READ access granted" -ForegroundColor Green
} catch {
    Write-Host "Sysmon error: $_" -ForegroundColor Red
}

# Security channel
$secChannel = "Security"
try {
    $currentSDDL = (wevtutil gl $secChannel | Select-String "channelAccess").ToString().Split(":")[-1].Trim()
    Write-Host "Current Security SDDL: $currentSDDL"

    $newSDDL = $currentSDDL + "(A;;0x1;;;$userSID)"
    wevtutil sl $secChannel /ca:$newSDDL
    Write-Host "Security: READ access granted" -ForegroundColor Green
} catch {
    Write-Host "Security error: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Done — no reboot needed." -ForegroundColor Cyan
