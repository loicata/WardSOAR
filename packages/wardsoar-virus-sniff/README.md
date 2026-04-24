# wardsoar-virus-sniff

Virus Sniff — standalone diagnostic appliance on Raspberry Pi 5.

## Product vision

A plug-and-play box the user receives, connects between their Internet
router and a single PC (via USB Gadget), and leaves observing for
24-48 hours. If an infection is detected, Virus Sniff proposes
installing **wardsoar-pc** on the client PC for deep investigation.

## Hardware

- Raspberry Pi 5, 16 GB RAM, 512 GB SSD (NVMe or USB 3.0 SATA).
- Ubuntu Server 26.04 LTS ARM64.
- Single native RJ45 + Wi-Fi (auto-selected as WAN).
- USB Gadget Mode (RNDIS/NCM) to the client PC.

## What lives here

- **Web UI** (Flask or FastAPI) — operator-facing configuration +
  real-time dashboard in Firefox at `http://virus-sniff.local`.
- **Networking** — nftables NAT setup, WAN auto-detect
  (Wi-Fi / Ethernet), USB Gadget device tree overlay.
- **Provisioning** — first-run Wi-Fi configuration flow, bootstrap
  via Ethernet fallback.
- **Escalation bridge** — pairing protocol with a WardSOAR PC
  install (SSH handshake, EVE history handoff).

## What does NOT live here

- Core pipeline, analyzer, intel clients, models. → `wardsoar-core`.
- Anything Windows-specific. → `wardsoar-pc`.

## Status

**Skeleton package — design only, no code yet.** The appliance is
scheduled to land after the Suricata-on-PC integration is complete.
See `docs/ARCHITECTURE.md` at the repo root for the full design and
decision log.
