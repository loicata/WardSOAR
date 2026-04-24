# WardSOAR Architecture

> Last updated: 2026-04-24 (v0.22.7)
> Source of truth for the overall design of WardSOAR and the related
> Virus Sniff appliance. Every significant decision is logged here
> with its rationale so that contributors, future maintainers, and
> AI assistants can understand *why* things are the way they are,
> not just *what* they are.

---

## 1. Vision

WardSOAR is an autonomous mini-SOAR (Security Orchestration,
Automation and Response) aimed at power users and small offices. It
analyzes Suricata alerts, enriches them with threat intelligence, lets
Claude Opus weigh in on the verdict, and takes reactive action
(firewall block, process kill, forensic acquisition).

Two products are planned in the same repository:

- **WardSOAR PC** — installed on the user's Windows desktop. Does the
  heavy lifting: forensic acquisition, AI correlation, UI, full
  incident response workflow.
- **Virus Sniff** *(future)* — a plug-and-play diagnostic appliance
  on a Raspberry Pi 5 that sits between the user's Internet box and
  their PC, observes the traffic for a few days, and escalates to a
  WardSOAR install if an infection is detected.

They share the same analysis core; they differ in their operating
environment (Windows vs. Linux ARM64), their deployment model
(desktop software vs. sealed appliance), and their user interface
(native PySide6 vs. web in Firefox).

---

## 2. Deployment model — PC-centric

WardSOAR is **PC-centric**: the irreducible unit is the operator's
workstation. External sensors (Netgate 4200 running pfSense + Suricata,
or a Virus Sniff Pi) are **optional agents** that augment the PC but
are not required.

```
                    +----------------------------+
                    |   WardSOAR on Windows PC   |
                    |  ------------------------  |
                    |   * Suricata local         |
                    |   * Sysmon + forensics     |
                    |   * Claude analyzer        |
                    |   * Pipeline orchestrator  |
                    |   * UI (PySide6 + Fluent)  |
                    |   * Windows Firewall blocks|
                    +-------------+--------------+
                                  | SSH (RemoteAgent abstraction)
                         +--------+---------+
                         |                  |
               +---------+--------+  +------+-----------+
               | Netgate 4200     |  | Virus Sniff Pi   |
               | (pfSense)        |  | (future)         |
               | optional         |  | optional         |
               +------------------+  +------------------+
```

### Why PC-centric (not Netgate-centric)

**Rationale**: the PC is where the operator lives, where the processes
run, where the secrets are stored. It is the irreducible point of
defence. A firewall can be bypassed (VPN, cellular hotspot, other
interface); the PC cannot. Putting the detection core at the closest
point to what we protect is the correct direction.

**Consequences**:
- WardSOAR can run on a single PC without any external appliance.
- Adding a Netgate or a Virus Sniff Pi *enriches* the signal; removing
  them does not break the core. The configuration matrix is reduced
  from three (Netgate-only / PC-only / both) to two (PC-only /
  PC + agents).
- The Netgate-specific code in the current codebase
  (`pfsense_ssh.py`, `netgate_apply.py`, etc.) will be refactored
  behind a common `RemoteAgent` interface so that Virus Sniff and any
  future sensor slots in naturally.

---

## 3. Repository structure — monorepo (Option 2)

The repository is organised as a **monorepo with three independent
Python packages**.

```
WardSOAR/
|-- packages/
|   |-- wardsoar-core/             cross-platform (Linux + Windows)
|   |   |-- src/wardsoar/core/
|   |   |-- pyproject.toml         pydantic, httpx, anthropic, asyncssh
|   |   +-- tests/
|   |
|   |-- wardsoar-pc/               Windows-only
|   |   |-- src/wardsoar/pc/
|   |   |-- pyproject.toml         pywin32, wmi, PySide6, yara-python
|   |   +-- tests/
|   |
|   +-- wardsoar-virus-sniff/      Linux ARM64 (future)
|       |-- src/wardsoar/vs/
|       |-- pyproject.toml         flask, nftables, ...
|       +-- tests/
|
|-- docs/                          this file lives here
|-- installer/                     MSI (WiX) + PyInstaller spec
|-- scripts/                       build.ps1 and friends
|-- pyproject.toml                 workspace root
+-- README.md
```

### Why monorepo with separated packages (Option 2)

**Rationale**:
- Build targets are fundamentally different: MSI for Windows PC,
  SD image or `.deb` for Linux ARM64.
- Dependencies are fundamentally different: PySide6 + pywin32 vs.
  Flask + nftables.
- Release cycles can desynchronise (Virus Sniff can ship v1 while
  PC is in v3, independently).
- The core can be validated on both platforms with pytest in isolation.

**Why not Option 1 (single project, packages inside `src/`)**: the
MSI would ship Virus Sniff code it does not need; dependencies would
be conditional via `extras_require` which is fragile; tests would be
imports-conditional everywhere.

**Why not Option 3 (flat with namespaces)**: no real decoupling of
dependencies, still one `pyproject.toml`, no independent versioning.

Option 2 is the mainstream approach in the modern Python ecosystem
(Django, FastAPI, tooling like `uv` or `hatch` workspaces).

### Status

The current codebase (v0.22.7) is still pre-refactor: everything lives
in `src/`. The migration to the monorepo layout is planned as the
*next* architectural work, before adding the Suricata-on-PC integration.

---

## 4. Pipeline — 13 stages

Every alert (whether it comes from the local Suricata, from the
Netgate, or from Virus Sniff in the future) traverses the same
ordered pipeline. The pipeline itself lives in `wardsoar-core`.

| # | Stage | Module | Purpose |
|---|---|---|---|
| 1 | Filter | `filter.py` | Drop known false positives (signature / category / (sig, dst) pair). |
| 2 | Deduplicator | `deduplicator.py` | Group bursts by (src_ip, sig_id) in a 60s window. |
| 3 | Correlation | (inferred) | Attach Sysmon process/file context. |
| 4 | PreScorer | `prescorer.py` | Local threat score 0-100; below threshold -> skip analysis. |
| 5 | Collector | `collector.py` | Network context: active connections, DNS/ARP cache. |
| 6 | Forensics | `forensics.py` | Local forensic cascade: processes, registry, event logs. |
| 7 | VirusTotal | `virustotal.py` | Hash / IP lookup on VT. |
| 8 | IP enrichment | `ip_enrichment.py` | ASN, reputation clients. |
| 9 | Analyzer | `analyzer.py` | Claude Opus: final verdict + confidence. |
| 10 | Responder.whitelist | `responder.py` | Refuse to block whitelisted IPs / RFC1918. |
| 11 | Responder.rate_limit | `responder.py` | Cap at N blocks/hour. |
| 12 | Responder.block | `responder.py` + `pfsense_ssh.py` / `windows_firewall.py` | Execute the block. |
| 13 | Logging | `logger.py` | Structured audit trail. |

Every stage is **fail-safe**: an unexpected error produces an
`INCONCLUSIVE` verdict and lets the next alert proceed. The pipeline
never crashes on a single bad input.

---

## 5. Key architectural decisions (decision log)

Each entry: **what** was decided, **why**, **alternatives considered**,
and the **date** so the rationale is traceable over time.

### 5.1 Local Suricata is mandatory on WardSOAR PC *(2026-04-24)*

**Decision**: WardSOAR PC ships with local Suricata installation
enforced at first-run wizard. The operator cannot start WardSOAR
without Suricata being installed and running.

**Rationale**:
- Maximum detection, including traffic that never reaches the Netgate
  (loopback, VPN-terminated on PC, traffic after the firewall is
  bypassed).
- Process context: local Suricata alerts can be correlated to PIDs,
  something the Netgate never sees.
- Defence in depth: a compromised router doesn't silence detection.

**Alternatives considered**:
- Suricata optional, Netgate required: rejected because it made the
  "without Netgate" deployment path a second-class citizen.
- No local Suricata, rely on Sysmon Event 3 only: rejected because
  Sysmon has no signature-matching and misses classic IDS detections.

### 5.2 Local blocking uses Windows Firewall *(2026-04-24)*

**Decision**: When the Netgate is absent, blocking is done through
the Windows Firewall (`netsh advfirewall firewall add rule ...`).

**Rationale**: natively available on every supported Windows SKU, no
extra driver, administers the NDIS-level packet filter exactly like a
dedicated firewall would. Symmetric with `pfctl` on the Netgate and
future `nftables` on Virus Sniff.

**Alternatives**: kill local process only (too narrow); MONITOR-only
without any block capability (not enough for HARD_PROTECT mode).

### 5.3 Npcap is downloaded at wizard time, not bundled *(2026-04-24)*

**Decision**: The WardSOAR MSI does **not** bundle Npcap. The setup
wizard downloads the official Npcap installer from `npcap.com`, runs
it, and waits for the operator to accept Npcap's own licence inside
the Npcap installer window.

**Rationale**: WardSOAR is GPL-3.0. Npcap is under the Nmap Public
Source License (a modified GPL with proprietary restrictions) and is
not GPL-compatible. Bundling it would create a licence conflict;
distributing the combined work would require the paid Npcap OEM
licence. Downloading it at setup time side-steps the issue, because
we do not distribute Npcap; the operator does.

**Alternatives**: bundle Npcap with a GPL linking exception
(complicates the licence, still needs OEM); switch to WinDivert
(Suricata does not support it); use ETW (too limited for IDS-class
capture).

### 5.4 SSH everywhere for remote agents *(2026-04-24)*

**Decision**: Netgate (FreeBSD) and Virus Sniff Pi (Ubuntu) both
communicate with WardSOAR PC over **SSH + EVE JSON streaming**. A
single `RemoteAgent` abstraction in `wardsoar-core` accommodates
them both.

**Rationale**: proven protocol, already working for Netgate, trivially
deployable on Ubuntu (`openssh-server`). Uniform approach means a
single library (`asyncssh`), a single authentication model
(SSH keys), a single code path for new sensor types.

**Alternatives**: REST/HTTP (more code to secure, new authentication
scheme), gRPC (heavy, not needed for low-volume EVE JSON).

### 5.5 Virus Sniff is a single-PC diagnostic appliance *(2026-04-24)*

**Decision**: Virus Sniff is designed to diagnose **one** PC. It
inserts itself between the Internet box and that single PC, observes
traffic, and escalates to a WardSOAR install if an infection is
detected.

**Rationale**: focused product, simple onboarding ("no intervention
on the client PC"), aligns with USB Gadget transport (one USB cable,
one PC). Scales horizontally (one appliance per PC) rather than
vertically (one appliance per LAN).

**Alternatives**: multi-PC (would require DHCP server, switch in the
box, more complex UX, broader responsibility).

### 5.6 Virus Sniff connects via USB Gadget *(2026-04-24)*

**Decision**: The Pi exposes itself to the client PC via USB Gadget
Mode (RNDIS on Windows, NCM on macOS/Linux). A single USB-A /
USB-C cable is the only link to the PC.

**Rationale**: zero-driver experience on Windows 10/11 (RNDIS is
native); works on any OS with minimal configuration; physical
isolation of the PC's Internet route; automatic configuration of the
new network interface on Windows via DHCP-on-USB.

**Consequence**: the routing mode is **NAT** (not transparent bridge).
Accepted because the appliance covers a single PC, is diagnostic
(not long-term), and double-NAT limitations (P2P, UPnP, IPv6) are
acceptable in this context.

### 5.7 Virus Sniff WAN is Wi-Fi or Ethernet (auto-detect) *(2026-04-24)*

**Decision**: The Pi's WAN uplink is either its internal Wi-Fi (client
mode to the user's box) or its native RJ45 Ethernet port. The choice
is made automatically at boot based on which interface is up and
connected.

**Rationale**: covers both the 90% case (laptop user: Pi gets the Wi-Fi
for convenience) and the 10% case (desktop user or no usable Wi-Fi:
cable between box and Pi). A **single routing mode** (NAT) regardless
of the WAN interface, so no dual `bridge + NAT` code paths.

Ethernet also serves as a bootstrap for Wi-Fi provisioning: the user
connects Ethernet, opens Firefox on the Pi's web UI, enters their Wi-Fi
credentials, then can unplug Ethernet if they want.

### 5.8 Virus Sniff UI is a web UI in Firefox *(2026-04-24)*

**Decision**: Configuration and real-time reporting happen in a
browser (Firefox) on the PC, pointing at `http://virus-sniff.local`
or the Pi's fixed IP over USB.

**Rationale**: zero-install for the operator, works offline on the Pi
(served locally), scales well for reports (HTML/CSS/JS), natively
cross-platform regardless of the operator's PC OS.

---

## 6. Remote Agent abstraction

To unify the way external sensors plug in, `wardsoar-core` will
expose an abstract `RemoteAgent`:

```python
class RemoteAgent(Protocol):
    source_name: str                          # e.g. "netgate_4200"
    async def stream_alerts(self) -> AsyncIterator[SuricataAlert]: ...
    async def is_healthy(self) -> bool: ...
    async def block_ip(self, ip: str) -> bool: ...   # optional
```

Concrete implementations:
- `NetgateAgent` — SSH + `pfctl` + reads EVE JSON on Netgate.
- `VirusSniffAgent` — SSH + `nftables` + reads EVE JSON on the Pi.
  *(Future)*

This replaces the current `PfSenseSSH` monolith.

---

## 7. Security posture

### Threat model (in scope)
- Malware on the PC (primary target).
- Tampering with forensic artefacts (DPAPI encryption + ACL sealing).
- Replay of captured alerts (every alert is idempotent, see
  `CLAUDE.md` section 3).
- Rate-limit exhaustion of free-tier APIs (circuit breakers, see
  `src/intel/http_client_base.py`).
- Compromised pfSense corrupting detection (Netgate audit).

### Not in scope (explicitly)
- Protection against a compromised WardSOAR process itself (we are
  inside the trust boundary).
- Protection against a hostile operator (this is a defensive tool,
  not a DRM system).

### Sensitive data never committed
The `.gitignore` explicitly excludes:
- Any file under `Key/` (SSH private keys).
- `.env` and variants (API keys).
- `data/`, `evidence/`, `intel_feeds/`, `reports/` (runtime data,
  often containing user IPs or forensic artefacts).
- `configuration/`, `config/config.yaml`, `snapshots/` (operator-
  specific state).
- `*.db`, `*.jsonl`, `*.log`, `eve.json` (forensic/telemetry).

A public clone of this repo must contain **only** source code, tests,
shared configuration (whitelists, known_false_positives, etc.), and
documentation. Nothing personal, nothing operational.

---

## 8. Build targets

### WardSOAR PC (Windows)
- **Tooling**: PyInstaller + WiX.
- **Artefact**: `WardSOAR_X.Y.Z.msi`.
- **Orchestrator**: `scripts/build.ps1`.
- **Quality gates** before build: black, ruff, mypy --strict, bandit,
  pip-audit. See `CLAUDE.md` section 1.
- **Cache hygiene**: `build/`, `dist/WardSOAR/`, `__pycache__/` are
  wiped before every build so the MSI never ships stale bytecode.

### Virus Sniff (Linux ARM64, planned)
- **Tooling**: pre-flashed SD/SSD image built with `packer` or `debos`.
- **Artefact**: `virus_sniff_X.Y.Z.img` + `.deb` package for upgrades.
- **OS**: Ubuntu Server 26.04 LTS ARM64.

---

## 9. Testing discipline

### Quality gates (Five Checks)
Before any commit on a `.py` file:

```
black --check --line-length 100 src/ tests/
ruff check src/ tests/
mypy src/ --strict
bandit -r src/ -ll
pip-audit -r requirements.txt
```

All five must pass. See `CLAUDE.md` section 1.

### Phase 9 hardening (planned)
The following will be added *after* the monorepo refactor and before
production release:

- End-to-end integration tests (8 canonical scenarios).
- State machine validation (explicit `AlertState` enum + transitions).
- Snapshot testing for forensic report ZIP structure.
- Property-based tests with Hypothesis for invariants.
- Mutation testing with mutmut, target >= 85% on CRITICAL modules.
- Opus cross-review on CRITICAL modules (alert_queue, responder,
  pfsense_ssh, netgate_audit, analyzer, notifier).

See `CLAUDE.md` for the full contract.

---

## 10. Glossary

- **EVE JSON** — Suricata's structured alert output format.
- **NAT** — Network Address Translation.
- **NCM / RNDIS** — USB networking classes (used by Virus Sniff).
- **pfctl** — FreeBSD's firewall controller (used over SSH on Netgate).
- **nftables** — Linux's modern firewall framework (used on Virus Sniff
  Pi).
- **SID** — Suricata rule signature ID.
- **SOAR** — Security Orchestration, Automation and Response.

---

## 11. Change log of this document

| Date | Change |
|---|---|
| 2026-04-24 | Initial version. Captures every architectural decision taken up to v0.22.7, including PC-centric model, monorepo plan, Virus Sniff design, SSH for RemoteAgent, USB Gadget transport, Npcap download-at-setup, Windows Firewall for local blocking. |
