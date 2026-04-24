"""Remote sensor/enforcement agents plugged into the WardSOAR pipeline.

Each concrete agent (Netgate / pfSense, future Virus Sniff on Pi, any
third-party sensor) lives in its own module inside this package. They
share the SSH + EVE-JSON transport and expose the same high-level
surface: stream alerts, report health, block an IP when supported.

The formal ``RemoteAgent`` protocol is not yet defined; it will land
with Phase 3 of the monorepo refactor (OS-agnostic abstractions).
Until then the concrete classes (``PfSenseSSH``, ``PersistentBlocklist``)
keep their current API and callers use them directly.
"""

from __future__ import annotations
