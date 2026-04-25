"""Remote sensor/enforcement agents plugged into the WardSOAR pipeline.

Each concrete agent (Netgate / pfSense, future Virus Sniff on Pi, any
third-party sensor) lives in its own module inside this package. They
share the SSH + EVE-JSON transport and expose the same high-level
surface: stream alerts, report health, block an IP when supported.

The formal ``RemoteAgent`` protocol lives in :mod:`.protocol` and the
registry that bookkeeps the running instances lives in :mod:`.registry`.
Concrete implementations (``PfSenseSSH`` today, ``VirusSniffAgent``
later) depend on the protocol, and pipeline code (``responder``,
``rule_manager``, ``netgate_audit``) will be migrated to consume the
protocol type rather than the concrete classes (Phase 3b.3).
"""

from __future__ import annotations

from wardsoar.core.remote_agents.netgate_agent import NetgateAgent
from wardsoar.core.remote_agents.protocol import RemoteAgent
from wardsoar.core.remote_agents.registry import RemoteAgentRegistry

__all__ = ["NetgateAgent", "RemoteAgent", "RemoteAgentRegistry"]
