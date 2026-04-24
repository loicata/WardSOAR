================================================================================

  WardSOAR — Autonomous Network Threat Detection and Response

================================================================================

  Version : 0.1.0
  Author  : Loic Ader (loicata.com)
  License : MIT
  Platform: Windows 10/11
  Language: Python 3.12+

================================================================================
  TABLE OF CONTENTS
================================================================================

  1. Overview
  2. How It Works
  3. Hardware and Software Requirements
  4. Architecture
  5. Alert Processing Pipeline
  6. Anti-False-Positive Layers
  7. Installation
  8. Configuration
  9. First Run — Dry-Run Mode
  10. Transitioning to Active Mode
  11. Desktop Application
  12. Notifications
  13. Forensic Evidence Packages
  14. Configuration Management and Rollback
  15. Alert Replay and Simulation
  16. Security Considerations
  17. Troubleshooting
  18. File Structure
  19. Development
  20. License

================================================================================
  1. OVERVIEW
================================================================================

WardSOAR is an autonomous mini-SOAR (Security Orchestration, Automation
and Response) system designed for small and medium-sized businesses.

It connects three components into a closed security loop:

  - Netgate 4200 (pfSense + Suricata) detects network threats via IDS
  - A Windows PC runs WardSOAR, which performs local forensic analysis
    and uses Claude AI to assess whether each alert is a genuine threat
  - When a threat is confirmed, WardSOAR automatically creates a
    blocking rule on pfSense via its REST API

The system operates autonomously — no human intervention is required for
confirmed threats. For borderline cases, the system notifies the operator
and waits for manual review.

================================================================================
  2. HOW IT WORKS
================================================================================

The full processing flow for each alert:

  1. Suricata on the Netgate 4200 detects suspicious network activity and
     writes an alert to the EVE JSON log file.

  2. The EVE JSON file is forwarded to the Windows PC (via syslog or
     network share).

  3. WardSOAR's Watcher module detects the new alert and pushes it
     into an asynchronous priority queue.

  4. The alert passes through the anti-false-positive pipeline:
     - Known false positive signatures are filtered out
     - Duplicate alerts from the same source are grouped
     - A local pre-score determines if the alert warrants AI analysis

  5. If the alert passes pre-screening, WardSOAR collects context:
     - Network context (active connections, DNS cache, ARP table)
     - IP reputation (AbuseIPDB, VirusTotal, OTX)
     - Network baseline comparison (is this traffic normal?)

  6. Local forensic analysis is performed on the Windows PC:
     - Which process is communicating with the suspect IP?
     - What is the process tree (parent/child relationships)?
     - What does Sysmon report (process creation, DLL loads, DNS queries)?
     - Are there suspicious files in common drop locations?
     - Are there unusual registry persistence entries?

  7. If suspicious files are found, their SHA-256 hashes are checked
     against VirusTotal (free API, 500 lookups/day).

  8. All collected evidence is sent to the Claude AI API for analysis.
     Claude receives: the alert, network context, forensic results,
     VirusTotal results, and the network baseline. It returns a structured
     verdict with confidence score and detailed reasoning.

  9. If the confidence is borderline (0.5-0.7), a second Claude analysis
     is triggered with a counter-argument prompt specifically looking for
     reasons the alert might be a false positive.

 10. If the final verdict is "confirmed" with confidence >= 0.7:
     - A block rule is created on pfSense via the REST API
     - The offending local process is optionally terminated
     - A Windows toast notification alerts the operator
     - The full decision is logged to the audit trail

 11. If the verdict is "inconclusive", the operator is notified for
     manual review. No automated action is taken.

 12. The verdict is cached to avoid re-analyzing identical alert patterns.

================================================================================
  3. HARDWARE AND SOFTWARE REQUIREMENTS
================================================================================

Hardware:
  - Netgate 4200 (or any pfSense device with Suricata)
  - Windows 10/11 PC (the analysis host)
  - Network connectivity between the PC and the Netgate

Software on the Netgate:
  - pfSense with Suricata package installed and configured
  - pfSense REST API package installed (for automated blocking)
  - EVE JSON logging enabled in Suricata
  - Syslog or file-based log forwarding to the Windows PC

Software on the Windows PC:
  - Python 3.12 or later
  - Sysmon (Microsoft Sysinternals) — essential for forensic visibility
  - PySide6 (Qt6) — installed automatically via requirements.txt

API accounts (free tiers are sufficient):
  - Anthropic Claude API — for threat analysis
  - VirusTotal API — for hash lookups (free: 500/day, 4/min)
  - Optional: AbuseIPDB, OTX AlienVault for IP reputation

================================================================================
  4. ARCHITECTURE
================================================================================

WardSOAR is structured as a modular Python application with a native
Windows desktop interface built on PySide6 (Qt6).

Core Pipeline Modules:
  - Watcher         : Monitors the EVE JSON file for new alerts
  - AlertQueue      : Async priority queue with backpressure protection
  - Filter          : Suppresses known false positive signatures
  - Deduplicator    : Groups identical alerts within a time window
  - PreScorer       : Computes a weighted score before Claude API call
  - Collector       : Gathers network context and IP reputation
  - Forensics       : Performs local host forensic analysis
  - VirusTotal      : Looks up file hashes and optionally submits files
  - Baseline        : Compares traffic against known normal patterns
  - Analyzer        : Sends enriched context to Claude API for verdict
  - Confirmer       : Runs second-opinion analysis for borderline cases
  - DecisionCache   : Caches recent verdicts to avoid redundant API calls
  - Responder       : Creates pfSense block rules and kills local processes
  - RuleManager     : Manages pfSense rule lifecycle (expiry, cleanup)
  - ForensicReport  : Generates evidence ZIP packages for law enforcement

Operations Modules:
  - Notifier        : Windows toast + optional email/Telegram notifications
  - Metrics         : Collects system metrics for the dashboard
  - HealthCheck     : Periodic self-monitoring of all components
  - Logger          : Structured JSON audit logging

Management Modules:
  - ChangeManager   : Configuration versioning with snapshot and rollback
  - Replay          : Replays historical alerts in simulation mode

Desktop Application:
  - System tray icon with color-coded status indicator
  - Main window with four tabs: Dashboard, Alerts, Configuration, Replay
  - Native Windows toast notifications for critical events

================================================================================
  5. ALERT PROCESSING PIPELINE
================================================================================

  Alert arrives
      |
      v
  [1] Filter -- signature in known_false_positives.yaml?
      |          YES -> log as suppressed, skip
      |          NO  -> continue
      v
  [2] Deduplicator -- same (src_ip + signature) in last 60 seconds?
      |                YES -> merge into group, skip individual processing
      |                NO  -> create new group, continue
      v
  [3] DecisionCache -- identical pattern already judged recently?
      |                YES + benign    -> log, skip
      |                YES + confirmed -> fast-track to Responder
      |                NO  -> continue
      v
  [4] PreScorer -- compute weighted score
      |            Below threshold -> log as low priority, skip
      |            Above threshold -> continue
      v
  [5] Collector -- gather network context
      v
  [6] Forensics -- local PC analysis (Sysmon, processes, registry)
      v
  [7] VirusTotal -- hash lookup for suspect files
      v
  [8] Baseline -- compare against known normal traffic patterns
      v
  [9] Analyzer -- Claude API threat analysis
      |
      |-- confidence >= 0.7 -> CONFIRMED -> Responder
      |-- confidence 0.5-0.7 -> [10] Confirmer (second opinion)
      |-- confidence < 0.5 -> log, no action
      v
  [10] Confirmer -- second Claude API call (counter-argument)
       |            Both agree -> combined verdict
       |            Disagree   -> INCONCLUSIVE, notify for manual review
       v
  [11] Responder -- whitelist check -> rate limit -> pfSense block
       v
  [12] Logger -- full audit record
       v
  [13] DecisionCache -- store verdict

================================================================================
  6. ANTI-FALSE-POSITIVE LAYERS
================================================================================

False positives are the biggest risk in an autonomous blocking system.
WardSOAR uses six layers to minimize them:

Layer 1 — Known False Positive Filter:
  Configured in config/known_false_positives.yaml. Suricata signatures that
  are known to trigger on legitimate traffic in your specific environment
  are suppressed before any analysis. Each entry includes a review date
  to ensure suppressions are periodically re-evaluated.

Layer 2 — Alert Deduplication:
  When Suricata detects a port scan or brute force, it may generate hundreds
  of identical alerts in seconds. The Deduplicator groups alerts by
  (source IP + signature ID) within a configurable time window (default: 60s)
  and processes the group as a single event.

Layer 3 — Local Pre-Scoring:
  A weighted scoring system evaluates each alert locally before calling the
  Claude API. Factors include: Suricata severity, IP reputation, port
  suspicion, Sysmon process matches, time of day. Only alerts above the
  score threshold are sent to Claude. The pre-scorer starts in "learning"
  mode (scores everything but filters nothing) and must be calibrated from
  real traffic data before activating filtering.

  SAFETY: The score threshold can never exceed 30 (enforced in code).
  A single high-severity alert (score 40) always passes regardless.

Layer 4 — Network Baseline:
  Configured in config/network_baseline.yaml. Documents the normal traffic
  patterns for your network: expected services, common destinations,
  legitimate ports. Traffic matching the baseline reduces suspicion.
  Traffic on suspicious ports (4444, 6667, etc.) increases it.

Layer 5 — Decision Cache:
  Stores recent verdicts keyed by (source IP, signature ID, destination port).
  Benign verdicts are cached for 1 hour, confirmed threats for 24 hours,
  inconclusive results for 10 minutes. Prevents redundant API calls and
  ensures consistent decisions for identical patterns.

Layer 6 — Double Confirmation:
  When Claude's initial analysis returns borderline confidence (0.5-0.7),
  a second Claude API call is made with a counter-argument prompt that
  specifically looks for false positive indicators. If the two analyses
  disagree, the verdict defaults to "inconclusive" (no blocking).

FAIL-SAFE PRINCIPLE:
  If any anti-false-positive layer encounters an error, the alert continues
  through the pipeline. No layer is allowed to silently block an alert from
  reaching the Analyzer. When in doubt, the system does nothing rather than
  risk blocking legitimate traffic.

================================================================================
  7. INSTALLATION
================================================================================

Step 1 — Clone the repository:

  git clone <repo-url>
  cd WardSOAR

Step 2 — Create a virtual environment (recommended):

  python -m venv .venv
  .venv\Scripts\activate

Step 3 — Install dependencies:

  pip install -r requirements.txt

Step 4 — Configure API keys:

  copy .env.example .env

  Edit .env and fill in your API keys:
  - ANTHROPIC_API_KEY    (required)
  - VIRUSTOTAL_API_KEY   (required)
  - PFSENSE_API_URL      (required)
  - PFSENSE_API_KEY      (required)
  - PFSENSE_API_SECRET   (required)
  - SMTP_USER / SMTP_PASSWORD (optional, for email notifications)
  - TELEGRAM_BOT_TOKEN   (optional, for Telegram notifications)

Step 5 — Configure network settings:

  Edit config/config.yaml:
  - Set your pfSense IP, PC IP, LAN subnet, DNS servers
  - Set the path to the EVE JSON file on the PC
  - Review all default settings

Step 6 — Configure the whitelist:

  Edit config/whitelist.yaml:
  - Add your gateway, DNS servers, and any critical IPs
  - These IPs will NEVER be blocked, regardless of alert severity

Step 7 — Install Sysmon on the Windows PC:

  Run as Administrator:
  .\scripts\install_sysmon.ps1

  This installs Sysmon with the SwiftOnSecurity configuration, providing
  detailed process, network, file, and registry event logging.

Step 8 — Configure Suricata log forwarding:

  On the Netgate 4200, configure Suricata to forward EVE JSON alerts
  to the Windows PC via syslog or network file share. The EVE JSON path
  must match the watcher.eve_json_path setting in config.yaml.

================================================================================
  8. CONFIGURATION
================================================================================

All configuration files are in the config/ directory:

config.yaml:
  Main configuration file. Controls all module behavior: network topology,
  alert thresholds, scoring weights, API settings, notification channels,
  queue sizes, healthcheck intervals, and more. Every setting is documented
  with inline comments.

whitelist.yaml:
  IP addresses and subnets that must never be blocked. Includes
  infrastructure IPs (gateway, DNS), trusted services, and custom entries.
  This is a critical safety file — errors here can cause service disruption.

known_false_positives.yaml:
  Suricata signature IDs known to produce false positives in your
  environment. Each entry includes a reason and a review date. Start empty
  and populate after observing traffic in dry-run mode.

network_baseline.yaml:
  Describes the expected traffic patterns on your network: internal
  services, common external destinations, expected and suspicious ports.
  Used by the Baseline module to help Claude distinguish normal from
  abnormal traffic.

prompts/analyzer_system.txt:
  The system prompt sent to Claude for primary threat analysis.
  Editable without code changes. Versioned by the ChangeManager.

prompts/confirmer_counter.txt:
  The system prompt for the second-opinion counter-argument analysis.
  Editable without code changes.

.env:
  API keys and secrets. NEVER committed to version control.
  See .env.example for the template.

================================================================================
  9. FIRST RUN — DRY-RUN MODE
================================================================================

WardSOAR starts in DRY-RUN MODE by default. In this mode:

  - Alerts are processed through the full pipeline
  - Claude AI analyzes each alert and produces a verdict
  - All decisions are logged to the audit trail
  - BUT NO BLOCKING ACTIONS ARE EXECUTED on pfSense
  - No processes are terminated on the local PC

This allows you to:
  - Verify that the system is receiving and parsing Suricata alerts
  - Observe Claude's analysis quality and verdict distribution
  - Identify false positive signatures to add to known_false_positives.yaml
  - Calibrate the PreScorer threshold from real traffic data
  - Build confidence that the system makes correct decisions

To start WardSOAR:

  python -m src.main

The system tray icon will appear in the bottom-right corner of the screen.
Double-click it to open the main window.

RECOMMENDED: Run in dry-run mode for at least 1-2 weeks before activating
real blocking. Review the decision log daily during this period.

================================================================================
  10. TRANSITIONING TO ACTIVE MODE
================================================================================

After the dry-run period, when you are confident in the system's decisions:

Step 1 — Review the decision log:
  Open the Alerts tab in the desktop application. Review all "confirmed"
  verdicts. Verify that each one represents a genuine threat that should
  have been blocked.

Step 2 — Calibrate the PreScorer (optional):
  Review the score distribution in the decision log. If any genuine threats
  had scores below 15 (the default threshold), lower the threshold further.
  Switch the PreScorer from "learning" to "active" mode only when confident.

Step 3 — Activate blocking:
  In config/config.yaml, change:
    responder:
      dry_run: false

  IMPORTANT: Use the Configuration tab in the desktop application to make
  this change. It will automatically create a snapshot before applying,
  so you can rollback instantly if needed.

Step 4 — Monitor closely:
  Watch the dashboard and notifications for the first few days after
  activation. Be ready to rollback to dry-run mode if you observe
  incorrect blocking.

================================================================================
  11. DESKTOP APPLICATION
================================================================================

WardSOAR includes a native Windows desktop application built with
PySide6 (Qt6). It provides four tabs:

DASHBOARD TAB:
  Real-time overview of system health and activity:
  - System status banner (Operational / Alert / Critical)
  - Key metrics: alerts today, blocked today, false positive rate, queue depth
  - Current operating mode (Dry-run / Learning / Active)
  - Component healthcheck status grid
  - Alert activity chart (last 24 hours)
  - Recent activity log

ALERTS TAB:
  Alert management and manual review:
  - Sortable, filterable alert table (date, verdict, severity, IP, signature)
  - Detailed view of selected alert with full context (network, forensic,
    VirusTotal, Claude analysis with reasoning)
  - Manual review form for overriding verdicts
  - Emergency IP unblock button
  - Forensic evidence package download (see section 13)

CONFIGURATION TAB:
  Configuration editing with safety features:
  - YAML editor with syntax highlighting
  - Snapshot history with dates and descriptions
  - Diff viewer comparing any two versions
  - Save with automatic pre-snapshot and diff preview
  - One-click rollback to any previous snapshot (see section 14)

REPLAY TAB:
  Test configuration changes against historical alerts:
  - Select date range and filters
  - Run simulation in background thread
  - Impact report showing what would change
  - Side-by-side comparison of original vs replay verdicts (see section 15)

SYSTEM TRAY:
  The system tray icon is always visible in the Windows taskbar:
  - Color-coded status: green (healthy), orange (alert pending),
    red (threat blocked or failure), grey (offline)
  - Shape indicators for accessibility: circle, triangle, square
  - Toast notifications for critical events
  - Right-click context menu: Open, Status, Unread count, Mode, Quit
  - Double-click opens the main window
  - Closing the window minimizes to tray (does not quit)

Display requirements:
  - Target resolution: 1920x1080 (Full HD)
  - Default window size: 1600x900
  - Minimum window size: 1280x720
  - Dark theme by default

================================================================================
  12. NOTIFICATIONS
================================================================================

WardSOAR sends notifications on key events:

  - Threat confirmed and blocked (Critical)
  - Alert requires manual review (Warning)
  - System component healthcheck failure (Critical)
  - System startup and shutdown (Info)
  - Daily activity summary (Info)

Three notification channels are available:

WINDOWS TOAST (mandatory, always active):
  Native Windows notifications appear in the bottom-right corner of the
  screen via the system tray icon. Critical alerts include a sound.
  No configuration needed — this is the primary notification channel.

EMAIL (optional, disabled by default):
  Configure SMTP settings in config.yaml and credentials in .env.
  You can choose which event types trigger emails.

TELEGRAM (optional, disabled by default):
  Configure a bot token in .env and a chat ID in config.yaml.
  You can choose which event types trigger Telegram messages.

Rate limiting prevents notification storms during burst alerts
(default: max 10 notifications per minute).

================================================================================
  13. FORENSIC EVIDENCE PACKAGES
================================================================================

For every confirmed threat that triggered a firewall modification,
WardSOAR can generate a complete forensic evidence package.

In the Alerts tab, select a confirmed alert and click
"Download Forensic Report". A standard Windows save dialog will open,
allowing you to choose where to save the ZIP archive on your computer.

The archive (FORENSIC_REPORT_{ip}_{date}.zip) contains:

  01_suricata_alert/          — Original IDS alert and related alerts
  02_network_context/         — Active connections, DNS, ARP, IP reputation, WHOIS
  03_local_forensic_analysis/ — Processes, process tree, Sysmon, event logs, registry
  04_virustotal_analysis/     — Hash lookup and analysis results
  05_ai_analysis/             — Claude primary and counter analyses with reasoning
  06_actions_taken/           — Block rules, terminated processes, timestamps
  07_system_configuration/    — System config (API keys replaced with [REDACTED])

Plus:
  README.txt        — Human-readable incident summary
  TIMELINE.txt      — Chronological event timeline
  METADATA.json     — Machine-readable metadata
  CHECKSUMS.sha256  — SHA-256 hashes of all files for integrity verification

The archive is self-contained: a forensic analyst with no knowledge of
WardSOAR can understand the incident from the README alone.

All timestamps are in UTC (ISO 8601). All files are UTF-8 encoded.
No API keys or secrets are included anywhere in the archive.

This archive can be transmitted directly to law enforcement, a CERT team,
or a forensic analyst for further investigation.

================================================================================
  14. CONFIGURATION MANAGEMENT AND ROLLBACK
================================================================================

Every configuration change is automatically versioned. The ChangeManager
creates a snapshot before each modification, allowing you to:

  - View the full history of configuration changes
  - Compare any two snapshots with a visual diff
  - Rollback to any previous state with one click

When you save a configuration change through the desktop application:

  1. The current configuration is automatically snapshotted
  2. A diff preview shows exactly what will change
  3. You enter a description for the change
  4. You confirm or cancel
  5. If confirmed, the change is applied and the new state is active

To rollback:

  1. Open the Configuration tab
  2. Select a snapshot from the history
  3. Click "Restore"
  4. Review the diff between current state and the target snapshot
  5. Confirm the rollback

The rollback itself creates a snapshot of the current state, so a rollback
is always reversible. Up to 50 snapshots are kept (configurable).

Managed files: config.yaml, whitelist.yaml, known_false_positives.yaml,
network_baseline.yaml, and all prompt files in config/prompts/.

================================================================================
  15. ALERT REPLAY AND SIMULATION
================================================================================

Before changing thresholds, prompts, or baseline configurations, you can
test the impact against historical alerts without affecting the live network.

In the Replay tab:

  1. Select a date range and optional filters (verdict, severity)
  2. Click "Start Simulation"
  3. The system replays each historical alert through the current pipeline
     configuration (filter, dedup, prescore, analyze)
  4. No real blocking actions are executed — simulation only

The impact report shows:
  - Total alerts replayed
  - Number of verdicts that changed vs original
  - New blocks that would have been created
  - Blocks that would have been removed
  - Change in false positive rate

Results are displayed in a table highlighting changed verdicts:
  - Red rows: was benign, now confirmed (potential over-blocking)
  - Green rows: was confirmed, now benign (potential improvement)

Use this to validate that a configuration change improves detection
without introducing regressions before applying it to production.

================================================================================
  16. SECURITY CONSIDERATIONS
================================================================================

FAIL-SAFE PRINCIPLE:
  When in doubt, WardSOAR does nothing. A missed low-severity alert
  is acceptable. A false block on legitimate traffic is not.
  Any error in any module results in: log the error, skip the action, continue.

WHITELIST ENFORCEMENT:
  The whitelist is checked at multiple layers before any block is executed.
  A whitelist bypass is treated as a critical bug (P0).

RATE LIMITING:
  Maximum 20 blocks per hour (configurable). Prevents runaway scenarios
  where a misconfiguration could block large portions of traffic.

BLOCK DURATION:
  All blocks are temporary by default (24 hours). Permanent blocks require
  explicit configuration. Every block is reversible.

CONFIDENCE THRESHOLD:
  Minimum 0.7 confidence before auto-blocking. Cannot be set below 0.5
  (enforced in code). Borderline cases (0.5-0.7) trigger double confirmation.

DRY-RUN MODE:
  The system starts in dry-run mode. Blocking must be explicitly activated
  after a validation period.

API KEY SECURITY:
  All API keys are stored in .env (never committed to version control).
  Keys are never logged, displayed in the UI, or included in forensic reports.

FORENSIC REPORT SECURITY:
  Evidence packages never contain API keys, passwords, or secrets. All
  sensitive configuration values are replaced with [REDACTED].
  SHA-256 checksums ensure chain-of-evidence integrity.

SINGLE INSTANCE:
  The desktop application enforces single-instance execution to prevent
  conflicting blocking decisions from parallel processes.

LOCAL ACCESS:
  The desktop application runs locally on the Windows PC. There is no
  network-accessible interface — the operator must be physically or
  remotely logged into the PC.

================================================================================
  17. TROUBLESHOOTING
================================================================================

PROBLEM: No alerts are being detected
  - Verify Suricata is running on the Netgate 4200
  - Verify EVE JSON logging is enabled in Suricata configuration
  - Verify the EVE JSON file is being forwarded to the Windows PC
  - Check the watcher.eve_json_path setting in config.yaml
  - Check the application log for file access errors

PROBLEM: Claude API calls are failing
  - Verify ANTHROPIC_API_KEY is set correctly in .env
  - Check the HealthCheck status in the Dashboard tab
  - Check the application log for API error details
  - Verify network connectivity from the PC to api.anthropic.com

PROBLEM: pfSense blocking is not working
  - Verify the system is NOT in dry-run mode (check config.yaml)
  - Verify PFSENSE_API_URL, PFSENSE_API_KEY, PFSENSE_API_SECRET in .env
  - Verify the pfSense API package is installed on the Netgate
  - Check the HealthCheck status for pfSense API connectivity
  - Check the application log for API error details

PROBLEM: Too many false positives
  - Run in dry-run mode and review the decision log
  - Add confirmed false positive signatures to known_false_positives.yaml
  - Update network_baseline.yaml with your normal traffic patterns
  - Use the Replay feature to test configuration changes

PROBLEM: Sysmon events are not available
  - Verify Sysmon service is running: Get-Service Sysmon64
  - Verify the Sysmon event log exists in Event Viewer
  - Check the sysmon_channel setting in config.yaml
  - Run install_sysmon.ps1 again as Administrator

PROBLEM: VirusTotal lookups are failing
  - Verify VIRUSTOTAL_API_KEY is set in .env
  - Check if you have exceeded the daily quota (500 requests/day)
  - The system will continue without VirusTotal if the API is unavailable

PROBLEM: System tray icon is not visible
  - Check the Windows taskbar overflow area (^ arrow)
  - Ensure PySide6 is installed correctly
  - Check the application log for Qt initialization errors

================================================================================
  18. FILE STRUCTURE
================================================================================

WardSOAR/
|-- CLAUDE.md                   Claude Code development instructions
|-- README.md                   Project summary (Markdown)
|-- README.txt                  This file (detailed documentation)
|-- requirements.txt            Python dependencies
|-- requirements-dev.txt        Development dependencies
|-- .env.example                API keys template
|-- .gitignore                  Git ignore rules
|
|-- config/
|   |-- config.yaml             Main configuration
|   |-- whitelist.yaml          IPs that must never be blocked
|   |-- known_false_positives.yaml  Suricata signatures to suppress
|   |-- network_baseline.yaml   Known normal traffic patterns
|   |-- prompts/
|       |-- analyzer_system.txt     Claude analysis system prompt
|       |-- confirmer_counter.txt   Claude counter-argument prompt
|
|-- src/
|   |-- main.py                 Entry point
|   |-- config.py               Configuration management
|   |-- models.py               Pydantic data models
|   |-- watcher.py              EVE JSON alert monitor
|   |-- alert_queue.py          Async priority queue
|   |-- filter.py               Known false positive suppression
|   |-- deduplicator.py         Alert grouping
|   |-- prescorer.py            Weighted local scoring
|   |-- collector.py            Network context collector
|   |-- forensics.py            Local forensic analysis
|   |-- virustotal.py           VirusTotal API integration
|   |-- baseline.py             Normal traffic comparison
|   |-- analyzer.py             Claude API threat analysis
|   |-- confirmer.py            Second-opinion analysis
|   |-- decision_cache.py       Verdict caching
|   |-- responder.py            pfSense blocking + process kill
|   |-- rule_manager.py         pfSense rule lifecycle
|   |-- forensic_report.py      Evidence ZIP generation
|   |-- notifier.py             Notification system
|   |-- metrics.py              System metrics
|   |-- healthcheck.py          Self-monitoring
|   |-- change_manager.py       Config versioning and rollback
|   |-- replay.py               Alert replay simulation
|   |-- logger.py               Structured audit logging
|   |-- ui/
|       |-- app.py              Main window and system tray
|       |-- views/
|           |-- dashboard.py    Dashboard tab
|           |-- alerts.py       Alerts tab
|           |-- config_view.py  Configuration tab
|           |-- replay_view.py  Replay tab
|
|-- tests/                      Test files (mirrors src/ structure)
|-- docs/                       Additional documentation
|-- scripts/
|   |-- install_sysmon.ps1      Sysmon installation script
|-- snapshots/                  Config snapshots for rollback (gitignored)
|-- logs/                       Runtime logs (gitignored)

================================================================================
  19. DEVELOPMENT
================================================================================

WardSOAR is developed using Claude Code with strict quality controls
defined in CLAUDE.md. The development philosophy prioritizes quality over
speed — this is a security system that controls a production firewall.

Development workflow:
  1. Write tests first (TDD mandatory)
  2. Implement incrementally (one function at a time)
  3. Verify coverage gates (80% to 95% depending on module criticality)
  4. Run quality checks (black, ruff, mypy --strict)
  5. Self-review with checklist before completion

Module criticality levels:
  CRITICAL (95% coverage): responder, analyzer, confirmer, whitelist config,
    filter, rule_manager, change_manager, forensic_report
  HIGH (85% coverage): forensics, virustotal, watcher, prescorer,
    deduplicator, baseline, decision_cache, alert_queue, replay
  STANDARD (80% coverage): collector, logger, models, main, notifier,
    metrics, healthcheck, UI views

Development tools:
  pip install -r requirements-dev.txt
  pytest tests/ -v                              # run tests
  pytest tests/ --cov=src --cov-report=term     # coverage report
  black --line-length 100 src/ tests/           # formatting
  ruff check src/ tests/                        # linting
  mypy src/ --strict                            # type checking

================================================================================
  20. LICENSE
================================================================================

MIT License

Copyright (c) Loic Ader (loicata.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

================================================================================
