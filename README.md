# WardSOAR

**Autonomous Mini-SOAR** — Automated network threat detection and
response, running on your Windows desktop.

Current version: **0.22.7** (2026-04-24)
License: **GNU GPL-3.0**

---

## What it does

WardSOAR watches your Suricata alerts, enriches them with threat
intelligence (VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, and
13 more sources), lets Claude Opus reason over the full context, and
automatically blocks confirmed threats at the firewall level — with
forensic acquisition, chain-of-custody, and a Windows native UI.

It is designed to run unattended on a power-user or small-office PC,
with safety gates (whitelist, rate limit, dry-run mode) that make it
safe to let it take real actions.

## Architecture at a glance

```
             +----------------------------+
             |   WardSOAR on Windows PC   |
             |                            |
             |   * Suricata local         |
             |   * Sysmon + forensics     |
             |   * Claude analyzer        |
             |   * Pipeline orchestrator  |
             |   * UI (PySide6 + Fluent)  |
             |   * Windows Firewall blocks|
             +-------------+--------------+
                           | SSH (optional)
                   +-------+--------+
                   |                |
           +-------+------+   +-----+-----------+
           | Netgate 4200 |   | Virus Sniff Pi  |
           | (optional)   |   | (planned)       |
           +--------------+   +-----------------+
```

WardSOAR is **PC-centric**: it runs fully on the PC alone. External
sensors (a Netgate 4200 running pfSense+Suricata, or a planned Virus
Sniff appliance on Raspberry Pi 5) are optional and enrich the
signal through an SSH-based `RemoteAgent` interface.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full
design, decision log, and rationale.

---

## Prerequisites

- Windows 10 or 11 (x86_64)
- Python 3.12+ (only if you build from source)
- Sysmon (the installer wizard downloads it)
- Npcap (the installer wizard downloads it, subject to Npcap's own
  licence — WardSOAR is GPL-3.0 and does not bundle Npcap)
- An Anthropic API key (Claude Opus)

Optional:
- A Netgate 4200 (or any pfSense box) for network-level detection
- Free-tier accounts on VirusTotal, AbuseIPDB, GreyNoise for
  enrichment

---

## Installation

### End-user install (recommended)

Download the latest `WardSOAR_X.Y.Z.msi` from the
[Releases](https://github.com/loicata/WardSOAR/releases) page and
run it. The first launch opens a setup wizard that guides you through
the prerequisites (Sysmon, Npcap, Suricata, API keys, Netgate
connection if any).

### From source (developer)

```powershell
git clone https://github.com/loicata/WardSOAR.git
cd WardSOAR
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
copy .env.example .env
# Edit .env with your API keys
python -m src.main
```

### Build the MSI from source

```powershell
.\scripts\build.ps1
```

The MSI lands in `dist/WardSOAR_X.Y.Z.msi`. See
[`docs/installation.md`](docs/installation.md) for details.

---

## Configuration

Most configuration lives in `%APPDATA%\WardSOAR\` once the wizard
has run:

- `config/config.yaml` — main configuration (network, thresholds,
  modes)
- `config/whitelist.yaml` — IPs that are never blocked
- `.env` — API keys (never committed)

Shared reference lists live in the repo's `config/`:

- `cdn_allowlist.yaml` — known CDN IPs, protected from accidental
  block
- `known_false_positives.yaml` — Suricata SIDs / categories to
  suppress
- `known_bad_actors.yaml` — registry of established threat actors
- `suspect_asns.yaml` — ASNs and Tor exit nodes

---

## Safety

WardSOAR is designed to fail safe:

- **Fail-safe verdicts**: any unexpected error in the pipeline
  yields `INCONCLUSIVE`, never a spurious block.
- **Whitelist**: RFC1918 / loopback / link-local / operator
  whitelist / CDN allowlist — all refuse the block unconditionally.
- **Rate limiter**: capped at 20 blocks per hour by default.
- **Dry-run mode**: the default setting. Logs every decision without
  actually blocking.
- **Three operational modes**: `monitor` (observe only), `protect`
  (block on confirmed threats), `hard_protect` (block anything that
  is not explicitly benign with high confidence).
- **1-click rollback**: any block can be undone from the UI.
- **Circuit breakers** on every external API (Claude, intel clients)
  so a quota-exhausted or failing service does not hammer itself.
- **Idempotence**: the same alert can be processed twice without
  duplicate side effects (no double block, no duplicate forensic
  report).

See [`CLAUDE.md`](CLAUDE.md) for the engineering contract, including
timeout discipline, idempotence guarantees, state machine invariants,
and the Phase-9 hardening plan (property-based tests, mutation
testing, Opus cross-review).

---

## Roadmap

- **Short term** — monorepo refactor (Option 2: three independent
  packages `wardsoar-core`, `wardsoar-pc`, `wardsoar-virus-sniff`)
  before adding the Suricata-on-PC integration.
- **Mid term** — Virus Sniff diagnostic appliance (Raspberry Pi 5 +
  Ubuntu Server 26.04 + USB Gadget transport + Firefox-based
  configuration).
- **Long term** — Phase 9 hardening (property-based tests, mutation
  testing, state machine formalisation, Opus adversarial review on
  every CRITICAL module).

---

## License

WardSOAR is free software, licensed under the
**GNU General Public License version 3** or later. See the
[`LICENSE`](LICENSE) file for the full text.

© Loic Ader

---

## Contributing

The project is in active development and currently managed by a
single maintainer. Issues, discussions, and pull requests are
welcome. Please read [`CLAUDE.md`](CLAUDE.md) first — it documents
the project's engineering standards (quality gates, fail-safe
discipline, English-only for source / tests / commits, etc.).
