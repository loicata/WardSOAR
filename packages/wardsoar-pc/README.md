# wardsoar-pc

Windows-only application layer of WardSOAR. Installs on a user
desktop as an MSI.

## What lives here

- **Local forensics** — Sysmon queries, Windows Event Log, registry
  persistence, process tree, file freshness.
- **Local AV** — Microsoft Defender integration, YARA scanning.
- **DPAPI encryption** — sealed evidence artefacts,
  tamper-resistant MANIFEST.
- **Native UI** — PySide6 + qfluentwidgets, Fluent Design.
- **Setup wizard** — Npcap + Suricata + ruleset, API keys, first-run
  flow.
- **Local blocking** — Windows Firewall rules via `netsh
  advfirewall`.
- **MSI packaging** — PyInstaller spec + WiX installer.

## What does NOT live here

- Core pipeline, analyzer, intel clients, models. → `wardsoar-core`.

## Status

**Skeleton package — not yet populated.** Modules migrate in from the
legacy `src/` layout during the monorepo refactor.
