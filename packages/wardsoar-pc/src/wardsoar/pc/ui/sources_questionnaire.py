"""Source-topology answer dataclass — shared by the wizard and downstream wiring.

Up to v0.22.x, a standalone ``SourcesQuestionnaire`` dialog ran
before :class:`~wardsoar.pc.ui.setup_wizard.SetupWizard` and asked
three yes/no questions:

  1. Do you have a Netgate pfSense on this LAN?
  2. Do you have a Virus Sniff (Raspberry Pi) appliance?
  3. Install Suricata locally on this PC?

…with a rule that *at least one* alert source must be reachable.

In v0.23.x those four pages were inlined as the head of the
``SetupWizard`` so the operator no longer hops between two dialogs.
This module survives only to host :class:`SourceChoices` — the typed
answer object the wizard, ``RemoteAgentRegistry``, and ``config.yaml``
generation all consume — plus :meth:`SourceChoices.coverage_warnings`,
the recap-page warning logic that lives on the data, not the UI.

Persistence happens in ``config.yaml`` under the ``sources:`` key
and feeds the in-process ``RemoteAgentRegistry`` at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceChoices:
    """The three boolean answers from the source-topology pages.

    Consumed by:

    * the detailed :class:`~wardsoar.pc.ui.setup_wizard.SetupWizard`
      (skips the pfSense SSH + Suricata pages when the matching flag
      is False),
    * the ``RemoteAgentRegistry`` wire-up at pipeline boot,
    * ``config.yaml`` generation (``sources:`` section).
    """

    netgate: bool
    virus_sniff: bool
    suricata_local: bool

    def at_least_one_source(self) -> bool:
        """Invariant: the operator must have at least one alert source.

        WardSOAR cannot run without an alert stream, so we refuse to
        accept "no Netgate, no Virus Sniff, no local Suricata".
        """
        return self.netgate or self.virus_sniff or self.suricata_local

    def coverage_warnings(self) -> list[str]:
        """Plain-English warnings about gaps the operator is signing up for.

        Surfaced on the recap screen so the operator can flip a choice
        before committing rather than discovering the gap weeks later
        when something slips through.
        """
        warnings: list[str] = []
        if self.netgate and not self.suricata_local:
            warnings.append(
                "Loopback and VPN-tunnelled traffic on this PC will not be "
                "monitored — the Netgate only sees traffic that crosses it. "
                "Enable local Suricata if you want full coverage."
            )
        if self.netgate and self.virus_sniff:
            warnings.append(
                "Netgate and Virus Sniff cannot both be active at the same "
                "time (the Pi's USB Gadget mode replaces the LAN's WAN path). "
                "Only one will run at runtime; the other stays configured "
                "and can be activated by physically plugging the Pi in."
            )
        if not self.netgate and not self.virus_sniff and self.suricata_local:
            warnings.append(
                "Standalone PC mode — alerts come exclusively from local "
                "Suricata. Threats targeting other devices on the LAN will "
                "not be visible to WardSOAR."
            )
        return warnings
