"""Absolute paths to Windows system executables.

Using absolute paths instead of bare names prevents PATH-injection
attacks where a malicious executable of the same name could be
loaded from an attacker-controlled directory earlier in PATH.

Resolves bandit finding B607 (start_process_with_partial_path).
"""

from __future__ import annotations

import os

_SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
_SYSTEM32 = os.path.join(_SYSTEM_ROOT, "System32")

_PROGRAM_FILES = os.environ.get("ProgramFiles", r"C:\Program Files")

POWERSHELL = os.path.join(_SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
ARP = os.path.join(_SYSTEM32, "ARP.EXE")
ICACLS = os.path.join(_SYSTEM32, "icacls.exe")
# Service Control Manager CLI — used to probe whether Sysmon is running.
SC = os.path.join(_SYSTEM32, "sc.exe")
# Windows Defender command-line scanner. Path is stable on Windows 10/11 x64.
MPCMDRUN = os.path.join(_PROGRAM_FILES, "Windows Defender", "MpCmdRun.exe")
