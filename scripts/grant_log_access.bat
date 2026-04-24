@echo off
echo Granting Sysmon log read access...
for /f "tokens=*" %%i in ('powershell -Command "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"') do set USERSID=%%i
echo User SID: %USERSID%

echo.
echo --- Sysmon channel ---
wevtutil gl Microsoft-Windows-Sysmon/Operational | findstr channelAccess
for /f "tokens=2 delims= " %%a in ('wevtutil gl Microsoft-Windows-Sysmon/Operational ^| findstr channelAccess') do set SDDL=%%a
echo Current SDDL: %SDDL%
set NEWSDDL=%SDDL%(A;;0x1;;;%USERSID%)
echo New SDDL: %NEWSDDL%
wevtutil sl Microsoft-Windows-Sysmon/Operational /ca:%NEWSDDL%
if %errorlevel% equ 0 (echo Sysmon: OK) else (echo Sysmon: FAILED)

echo.
echo --- Security channel ---
for /f "tokens=2 delims= " %%a in ('wevtutil gl Security ^| findstr channelAccess') do set SDDL2=%%a
set NEWSDDL2=%SDDL2%(A;;0x1;;;%USERSID%)
wevtutil sl Security /ca:%NEWSDDL2%
if %errorlevel% equ 0 (echo Security: OK) else (echo Security: FAILED)

echo.
echo Done. No reboot needed.
