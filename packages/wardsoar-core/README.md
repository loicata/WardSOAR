# wardsoar-core

Cross-platform core of WardSOAR. Runs unmodified on Windows (WardSOAR PC)
and Linux ARM64 (Virus Sniff).

## What lives here

- **Pipeline** — filter, deduplicator, prescorer, responder (abstract),
  analyzer, VT lookup.
- **Models** — Pydantic data classes (`SuricataAlert`, `ThreatAnalysis`,
  `DecisionRecord`, …).
- **Intelligence clients** — every `src/intel/` module (VirusTotal,
  AbuseIPDB, GreyNoise, threatfox, …). Includes the `http_client_base`
  with circuit breaker + negative cache.
- **RemoteAgent abstraction** — `NetgateAgent`, `VirusSniffAgent` and
  any future sensor plug into the pipeline through this interface.

## What does NOT live here

- No Windows-only code (pywin32, wmi, DPAPI, Sysmon, YARA, PySide6).
  → `wardsoar-pc`.
- No Linux-appliance code (Flask, nftables, routing).
  → `wardsoar-virus-sniff`.

## Status

**Skeleton package — not yet populated.** The migration from the legacy
`src/` layout is in progress. See `docs/ARCHITECTURE.md` at the repo
root for the plan.
