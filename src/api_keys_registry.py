"""Single source of truth for all external API keys WardSOAR consumes.

Both the first-run setup wizard and the "API Keys & Secrets" settings
tab build their UI from this registry so the two surfaces can never
drift out of sync. Downstream modules (``ip_enrichment``, ``analyzer``,
``notifier``, ``virustotal``) pull their runtime configuration from
the same source.

The registry also lists the **auto-enabled** intelligence feeds that
require no user action: the UI renders these as an informational
block at the top of the Keys page so the operator understands that
these sources are already providing signal without any setup.

Design rules (v0.10.0)
----------------------
1. One entry per environment variable. The variable name is the
   contract between the UI, the config loader and the HTTP clients.
2. ``tier`` groups the UI into sections: ``auto`` / ``required`` /
   ``essential`` / ``useful`` / ``paid`` / ``notification``. No
   collapsed sections — every block is visible by default so the
   operator sees the full catalogue in one glance.
3. ``signup_url`` is rendered as a "Sign up →" link next to the
   field. ``None`` when there is nothing to sign up for.
4. ``pricing`` is the tier-specific quota (``Free 500/day``) or the
   paid price (``$50 / month``). Shown as a right-aligned caption.
5. ``description`` is rendered under the label. Two or three lines
   max — enough context for a non-specialist to decide whether to
   create an account.
6. Everything is optional. Only ``ANTHROPIC_API_KEY`` carries
   ``required=True``; the pipeline gracefully degrades when others
   are absent.

Nothing in this module performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Tier = Literal["auto", "required", "essential", "useful", "paid", "notification"]


@dataclass(frozen=True)
class AutoEnabledSource:
    """An intelligence feed that needs no user action.

    The operator still sees it in the Keys tab (informational block)
    so they understand that the signal is there. Refresh cadence is
    shown as a caption.
    """

    name: str
    refresh_cadence: str
    description: str


@dataclass(frozen=True)
class ApiKeySpec:
    """One external API credential managed by WardSOAR.

    Attributes:
        env_var: Environment-variable name. Written verbatim to
            ``%APPDATA%\\WardSOAR\\.env`` and consumed by the HTTP
            clients via ``os.environ``.
        display_label: Shown next to the password field in the UI.
        placeholder: Hint text inside the empty password field.
        tier: UI grouping bucket.
        pricing: Human-readable quota/price caption. ``""`` when
            irrelevant (e.g. ``SMTP_USER``).
        signup_url: Direct URL to create an account. ``None`` when
            the key is provided by an existing service (Telegram) or
            the credential is not for an external service.
        description: One-paragraph explanation of the signal the key
            unlocks. English only, operator-facing.
        required: When ``True``, the wizard's final "Done" button is
            disabled until the field is filled. Only the Anthropic
            key is required.
    """

    env_var: str
    display_label: str
    placeholder: str
    tier: Tier
    pricing: str
    signup_url: str | None
    description: str
    required: bool = False


# -----------------------------------------------------------------------------
# Auto-enabled sources (informational block)
# -----------------------------------------------------------------------------
#
# These 11 intelligence sources run automatically in the background.
# The operator does not need to do anything — they appear in every
# alert's "IP Ownership & Reputation" section once WardSOAR starts.
# Listed in the same order used by the UI.
AUTO_ENABLED_SOURCES: tuple[AutoEnabledSource, ...] = (
    AutoEnabledSource(
        name="URLhaus (abuse.ch)",
        refresh_cadence="refresh /hour",
        description=("Authoritative database of URLs serving malware " "(distribution, C&C)."),
    ),
    AutoEnabledSource(
        name="ThreatFox (abuse.ch)",
        refresh_cadence="refresh /hour",
        description=("IOC feed (IP / URL / hash) for active botnet C&C and " "malware."),
    ),
    AutoEnabledSource(
        name="Feodo Tracker (abuse.ch)",
        refresh_cadence="refresh /hour",
        description=(
            "Banking-botnet C&C tracker (Emotet, TrickBot, QakBot, " "Dridex, BazarLoader)."
        ),
    ),
    AutoEnabledSource(
        name="MalwareBazaar (abuse.ch)",
        refresh_cadence="on-demand, 24h cache",
        description=("Malware sample database with SHA-256 hashes (lookup by " "hash)."),
    ),
    AutoEnabledSource(
        name="Blocklist.de",
        refresh_cadence="refresh /30 min",
        description=("IPs actively brute-forcing SSH / HTTP / Mail on public " "honeypots."),
    ),
    AutoEnabledSource(
        name="Spamhaus DROP / EDROP",
        refresh_cadence="refresh daily",
        description=(
            "Bulletproof-hosting networks (hosting providers known " "to host attackers)."
        ),
    ),
    AutoEnabledSource(
        name="FireHOL IP Lists",
        refresh_cadence="refresh daily",
        description=("Aggregator of ~100 free reputation feeds. Global " "safety net."),
    ),
    AutoEnabledSource(
        name="Team Cymru Whois",
        refresh_cadence="on-demand, 30d cache",
        description=("WHOIS IP \u2192 ASN service. Fallback when ipinfo.io " "is unreachable."),
    ),
    AutoEnabledSource(
        name="Tor exit list",
        refresh_cadence="refresh daily",
        description=("Pulled from check.torproject.org/torbulkexitlist."),
    ),
    AutoEnabledSource(
        name="ipinfo.io (anonymous tier)",
        refresh_cadence="50k / month free",
        description=("ASN + country + city geolocation. Active without an " "API key."),
    ),
    AutoEnabledSource(
        name="CDN allowlist (local)",
        refresh_cadence="bundled in the MSI",
        description=(
            "Whitelist of major CDN ASNs (Cloudflare, Fastly, " "Akamai, Google, Amazon, ...)."
        ),
    ),
)


# -----------------------------------------------------------------------------
# API keys
# -----------------------------------------------------------------------------
API_KEY_SPECS: tuple[ApiKeySpec, ...] = (
    # --- Required -----------------------------------------------------------
    ApiKeySpec(
        env_var="ANTHROPIC_API_KEY",
        display_label="Anthropic API Key",
        placeholder="sk-ant-...",
        tier="required",
        pricing="usage-based pricing",
        signup_url="https://console.anthropic.com",
        description=("Claude Opus analyzes the alerts that pass the filter " "stages."),
        required=True,
    ),
    # --- Essentials ---------------------------------------------------------
    ApiKeySpec(
        env_var="VIRUSTOTAL_API_KEY",
        display_label="VirusTotal",
        placeholder="Free tier key",
        tier="essential",
        pricing="Free 500 lookups / day",
        signup_url="https://www.virustotal.com/gui/join-us",
        description=(
            "Aggregates 92 antivirus scanners + threat-intel feeds "
            "in a single lookup. One key is the equivalent of "
            "connecting to dozens of sources simultaneously."
        ),
    ),
    ApiKeySpec(
        env_var="ABUSEIPDB_API_KEY",
        display_label="AbuseIPDB",
        placeholder="Free tier key",
        tier="essential",
        pricing="Free 1000 checks / day",
        signup_url="https://www.abuseipdb.com/register",
        description=(
            "Crowdsourced abuse database (scan / brute-force / "
            "spam / DDoS). Score 0\u2013100 + precise categories "
            "+ count of independent reports."
        ),
    ),
    ApiKeySpec(
        env_var="GREYNOISE_API_KEY",
        display_label="GreyNoise",
        placeholder="Community tier key",
        tier="essential",
        pricing="Free unlimited",
        signup_url="https://viz.greynoise.io/signup",
        description=(
            'Classifies IPs scanning the internet: "benign '
            'scanner" (researchers, Shodan) vs "malicious" '
            "(botnets). Saves roughly 70 % of Opus calls on "
            "internet-wide background noise."
        ),
    ),
    ApiKeySpec(
        env_var="OTX_API_KEY",
        display_label="AlienVault OTX (AT&T)",
        placeholder="Free tier key",
        tier="essential",
        pricing="Free unlimited",
        signup_url="https://otx.alienvault.com/signup",
        description=(
            'Real-time community threat intel. Access to "pulses" '
            "published by 100 000+ security analysts. Unique "
            '"who published and when" signal.'
        ),
    ),
    # --- Useful for specific cases ------------------------------------------
    ApiKeySpec(
        env_var="XFORCE_API_KEY",
        display_label="IBM X-Force Exchange",
        placeholder="API key",
        tier="useful",
        pricing="Free tier",
        signup_url="https://exchange.xforce.ibmcloud.com/",
        description=(
            "Commercial-grade threat intel, free. IP / URL / file / "
            "hash score, categorization, history. Curated by the "
            "IBM Research team."
        ),
    ),
    ApiKeySpec(
        env_var="XFORCE_API_PASSWORD",
        display_label="IBM X-Force API Password",
        placeholder="API password (companion of the key)",
        tier="useful",
        pricing="Free tier",
        signup_url="https://exchange.xforce.ibmcloud.com/",
        description=(
            "IBM X-Force requires both a key and a password. Both "
            "are displayed after registration."
        ),
    ),
    ApiKeySpec(
        env_var="HONEYPOT_API_KEY",
        display_label="Project Honey Pot",
        placeholder="HTTP:BL access key",
        tier="useful",
        pricing="Free (short signup)",
        signup_url="https://www.projecthoneypot.org/create_account.php",
        description=(
            "DNSBL specialized for email harvesters and spammers. "
            "Useful when alerts concern mail traffic."
        ),
    ),
    ApiKeySpec(
        env_var="IPINFO_API_KEY",
        display_label="ipinfo.io (pro tier)",
        placeholder="Access token",
        tier="useful",
        pricing="Free 50k / month",
        signup_url="https://ipinfo.io/signup",
        description=(
            'Unlocks the "privacy detection" response: VPN / '
            'proxy / hosting / Tor / relay. Adds the "is this IP '
            'anonymized" signal.'
        ),
    ),
    # --- Paid sources -------------------------------------------------------
    ApiKeySpec(
        env_var="SHODAN_API_KEY",
        display_label="Shodan",
        placeholder="API key",
        tier="paid",
        pricing="~$49 / year Academic, or $599 / year API",
        signup_url="https://account.shodan.io/register",
        description=(
            "Continuous internet scanner that indexes every exposed "
            "service. Per IP: open ports, banners, running "
            "services, known vulnerabilities. Unique signal of "
            '"what is running on this IP".'
        ),
    ),
    ApiKeySpec(
        env_var="SECURITYTRAILS_API_KEY",
        display_label="SecurityTrails",
        placeholder="API key",
        tier="paid",
        pricing="$50 / month",
        signup_url="https://securitytrails.com/app/signup",
        description=(
            "Passive DNS: history of hostnames that resolved to "
            'this IP over time. Example: "this IP served 12 '
            'phishing domains in six months". Data not available '
            "on any free tier."
        ),
    ),
    ApiKeySpec(
        env_var="CENSYS_API_ID",
        display_label="Censys (API ID)",
        placeholder="API ID",
        tier="paid",
        pricing="$99 / month",
        signup_url="https://accounts.censys.io/register",
        description=(
            "Continuous internet scan focused on TLS certificates "
            "and device fingerprinting. Alternative or complement "
            "to Shodan. Strong at hunting malicious-infrastructure "
            "patterns."
        ),
    ),
    ApiKeySpec(
        env_var="CENSYS_API_SECRET",
        display_label="Censys (API Secret)",
        placeholder="API secret (companion of the ID)",
        tier="paid",
        pricing="$99 / month",
        signup_url="https://accounts.censys.io/register",
        description=(
            "Censys uses an ID + secret pair. Both are shown in "
            "the account dashboard after registration."
        ),
    ),
    # --- Notifications ------------------------------------------------------
    ApiKeySpec(
        env_var="SMTP_USER",
        display_label="SMTP Username",
        placeholder="user@gmail.com",
        tier="notification",
        pricing="",
        signup_url=None,
        description=(
            "Username for outbound email notifications. Tested "
            "against Gmail; any RFC-5321 server should work."
        ),
    ),
    ApiKeySpec(
        env_var="SMTP_PASSWORD",
        display_label="SMTP Password",
        placeholder="Gmail App Password",
        tier="notification",
        pricing="",
        signup_url=None,
        description=(
            'Use a Gmail "App Password" (16 chars, generated in '
            "Google account security). Plain-text Gmail passwords "
            "are refused by Google."
        ),
    ),
    ApiKeySpec(
        env_var="TELEGRAM_BOT_TOKEN",
        display_label="Telegram Bot Token",
        placeholder="123456:ABC-DEF...",
        tier="notification",
        pricing="",
        signup_url="https://t.me/BotFather",
        description=(
            "Issued by @BotFather. Paired with the chat ID in "
            "notifier settings to deliver block alerts via "
            "Telegram."
        ),
    ),
)


def specs_by_tier(tier: Tier) -> tuple[ApiKeySpec, ...]:
    """Return all API-key specs that belong to ``tier``.

    Preserves the registry's declaration order so the UI is
    deterministic across runs.
    """
    return tuple(spec for spec in API_KEY_SPECS if spec.tier == tier)


# -----------------------------------------------------------------------------
# Manual external check URLs (browser click-through, no API key)
# -----------------------------------------------------------------------------
#
# Rendered in the Alert Detail view as a collapsible sub-block under
# "External reputation". No keys, no API calls — just a URL template
# the UI fills in with the alert's IP.
@dataclass(frozen=True)
class ManualCheck:
    """One browser click-through reputation source.

    Attributes:
        name: Shown in the UI row.
        url_template: A ``str.format``-compatible string with a
            single ``{ip}`` placeholder.
        relevance: ``"high"`` or ``"medium"``. Drives the section
            heading (HIGH / MEDIUM relevance) inside the
            collapsible block.
        description: Operator-facing rationale (why click this).
    """

    name: str
    url_template: str
    relevance: Literal["high", "medium"]
    description: str


MANUAL_CHECKS: tuple[ManualCheck, ...] = (
    ManualCheck(
        name="Cisco Talos",
        url_template="https://talosintelligence.com/reputation_center/lookup?search={ip}",
        relevance="high",
        description=(
            'Cisco\'s overall reputation score + "TrustScore" '
            "classification. Industry gold standard for manual IP "
            "reputation checks."
        ),
    ),
    ManualCheck(
        name="SANS ISC / DShield",
        url_template="https://isc.sans.edu/ipinfo.html?ip={ip}",
        relevance="high",
        description=(
            "Real attack counts observed on this IP by SANS "
            "honeypots (SSH brute-force, web scan, malware drop, "
            "...). First seen / last seen, classified attack types."
        ),
    ),
    ManualCheck(
        name="Pulsedive",
        url_template="https://pulsedive.com/indicator/?indicator={ip}",
        relevance="high",
        description=(
            "IOC correlation: which malware / APT / phishing "
            "campaigns are tied to this IP via multi-source feeds. "
            "Community risk score + related indicators."
        ),
    ),
    ManualCheck(
        name="Spamhaus (web lookup)",
        url_template="https://check.spamhaus.org/results/?query={ip}",
        relevance="medium",
        description=(
            "Complements the DROP / EDROP feeds already "
            "auto-enabled: shows the SBL / XBL / PBL lists "
            "(mail-centric: spam sources, compromised hosts, "
            "policy blocks). Redundant for routing IPs but adds "
            "the email-reputation dimension."
        ),
    ),
    ManualCheck(
        name="Netcraft Site Report",
        url_template="https://sitereport.netcraft.com/?url={ip}",
        relevance="medium",
        description=(
            "Focused on domain / URL rather than bare IP. Useful "
            "for seeing the hosting provider, SSL certificates, "
            "web technologies. Less direct for low-level non-HTTP "
            "IPs."
        ),
    ),
    ManualCheck(
        name="Hybrid Analysis",
        url_template="https://www.hybrid-analysis.com/search?query={ip}",
        relevance="medium",
        description=(
            "CrowdStrike sandbox that analyzes files. Also shows "
            "the IPs contacted by malware (C&C, exfiltration). "
            "Useful complement when the alert is tied to a malware "
            "flow."
        ),
    ),
    ManualCheck(
        name="URLScan.io",
        url_template="https://urlscan.io/ip/{ip}/",
        relevance="medium",
        description=(
            "Shows websites scanned that are hosted on this IP, "
            "with screenshots. Useful for alerts on port 80 / 443 "
            "\u2014 lets you see visually what is running on the "
            "IP."
        ),
    ),
)


__all__ = [
    "API_KEY_SPECS",
    "AUTO_ENABLED_SOURCES",
    "ApiKeySpec",
    "AutoEnabledSource",
    "MANUAL_CHECKS",
    "ManualCheck",
    "Tier",
    "specs_by_tier",
]
