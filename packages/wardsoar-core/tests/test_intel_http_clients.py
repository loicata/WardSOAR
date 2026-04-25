"""Tests for v0.12.0 HTTP-based reputation clients.

Every client is exercised through its ``_verdict_from_raw`` parser
(no HTTP call) and through ``query_ip`` with an injected mock so
no real network traffic is generated. The shared SQLite cache is
tested separately for TTL + round-trip behaviour.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from wardsoar.core.intel.abuseipdb import AbuseIpDbClient
from wardsoar.core.intel.alienvault_otx import AlienVaultOtxClient
from wardsoar.core.intel.greynoise import GreyNoiseClient
from wardsoar.core.intel.http_client_base import IpReputationCache, ReputationVerdict
from wardsoar.core.intel.virustotal_client import VirusTotalClient

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class TestIpReputationCache:
    def test_put_get_roundtrip(self, tmp_path: Path) -> None:
        cache = IpReputationCache(db_path=tmp_path / "rep.db", ttl_s=3600)
        verdict = ReputationVerdict(level="bad", verdict="5/92 engines", raw={"src": "test"})
        cache.put("test_client", "1.2.3.4", verdict)
        result = cache.get("test_client", "1.2.3.4")
        assert result is not None
        assert result.level == "bad"
        assert result.verdict == "5/92 engines"
        assert result.raw == {"src": "test"}

    def test_expired_entry_returns_none(self, tmp_path: Path) -> None:
        cache = IpReputationCache(db_path=tmp_path / "rep.db", ttl_s=0)
        cache.put("c", "1.2.3.4", ReputationVerdict(level="clean", verdict="ok"))
        # ttl_s=0 means everything is immediately stale.
        assert cache.get("c", "1.2.3.4") is None

    def test_miss_returns_none(self, tmp_path: Path) -> None:
        cache = IpReputationCache(db_path=tmp_path / "rep.db")
        assert cache.get("c", "1.2.3.4") is None


# ---------------------------------------------------------------------------
# Per-client parsers
# ---------------------------------------------------------------------------


class TestVirusTotalParser:
    def test_all_clean(self, tmp_path: Path) -> None:
        cache = IpReputationCache(db_path=tmp_path / "rep.db")
        client = VirusTotalClient(cache=cache)
        verdict = client._verdict_from_raw(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 72,
                            "undetected": 20,
                        }
                    }
                }
            }
        )
        assert verdict.level == "clean"
        assert "0/" in verdict.verdict

    def test_malicious_hit(self, tmp_path: Path) -> None:
        cache = IpReputationCache(db_path=tmp_path / "rep.db")
        client = VirusTotalClient(cache=cache)
        verdict = client._verdict_from_raw(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 0,
                            "harmless": 67,
                            "undetected": 20,
                        }
                    }
                }
            }
        )
        assert verdict.level == "bad"
        assert "5/" in verdict.verdict

    def test_unknown_ip(self, tmp_path: Path) -> None:
        cache = IpReputationCache(db_path=tmp_path / "rep.db")
        client = VirusTotalClient(cache=cache)
        verdict = client._verdict_from_raw({"_unknown": True})
        assert verdict.level == "unknown"


class TestAbuseIpDbParser:
    def _cli(self, tmp_path: Path) -> AbuseIpDbClient:
        return AbuseIpDbClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_clean_score(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        )
        assert v.level == "clean"
        assert "0/100" in v.verdict

    def test_high_score_is_bad(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"data": {"abuseConfidenceScore": 92, "totalReports": 47}}
        )
        assert v.level == "bad"
        assert "92/100" in v.verdict

    def test_mid_score_is_warn(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"data": {"abuseConfidenceScore": 30, "totalReports": 2}}
        )
        assert v.level == "warn"


class TestGreyNoiseParser:
    def _cli(self, tmp_path: Path) -> GreyNoiseClient:
        return GreyNoiseClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_unknown_ip_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"_unknown": True})
        assert v.level == "clean"

    def test_malicious(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"classification": "malicious", "noise": True, "name": "Mirai"}
        )
        assert v.level == "bad"
        assert "Mirai" in v.verdict

    def test_benign_scanner(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"classification": "benign", "noise": True, "name": "Shodan"}
        )
        assert v.level == "info"
        assert "Shodan" in v.verdict


class TestAlienVaultOtxParser:
    def _cli(self, tmp_path: Path) -> AlienVaultOtxClient:
        return AlienVaultOtxClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    def test_no_pulses_is_clean(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw({"pulse_info": {"count": 0}})
        assert v.level == "clean"

    def test_many_pulses_is_bad(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {
                "pulse_info": {
                    "count": 5,
                    "pulses": [{"name": "Emotet IOCs April 2026"}],
                }
            }
        )
        assert v.level == "bad"
        assert "Emotet" in v.verdict

    def test_few_pulses_is_warn(self, tmp_path: Path) -> None:
        v = self._cli(tmp_path)._verdict_from_raw(
            {"pulse_info": {"count": 1, "pulses": [{"name": "Some IOCs"}]}}
        )
        assert v.level == "warn"


# ---------------------------------------------------------------------------
# Missing-key behaviour
# ---------------------------------------------------------------------------


class TestMissingKeySilentDisable:
    """Every client must return ``None`` without any HTTP call when
    its env var is empty. The aggregator relies on this to omit the
    row for sources the operator has not configured.
    """

    def test_virustotal_disabled_when_env_empty(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        client = VirusTotalClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))
        assert client.is_enabled() is False
        result = asyncio.new_event_loop().run_until_complete(client.query_ip("1.2.3.4"))
        assert result is None

    def test_abuseipdb_disabled_when_env_empty(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        client = AbuseIpDbClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))
        assert client.is_enabled() is False

    def test_greynoise_disabled_when_env_empty(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.delenv("GREYNOISE_API_KEY", raising=False)
        client = GreyNoiseClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))
        assert client.is_enabled() is False

    def test_otx_disabled_when_env_empty(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        client = AlienVaultOtxClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))
        assert client.is_enabled() is False


# ---------------------------------------------------------------------------
# End-to-end query_ip (mock _fetch_raw)
# ---------------------------------------------------------------------------


class _FakeClient(VirusTotalClient):
    """Subclass that returns a stub payload from ``_fetch_raw``."""

    def __init__(self, cache: IpReputationCache, payload: dict[str, Any]) -> None:
        super().__init__(cache=cache)
        self._payload = payload

    async def _fetch_raw(self, ip: str, api_key: str) -> Any:
        return self._payload


@pytest.mark.asyncio
async def test_query_ip_caches_subsequent_calls(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 19,
                }
            }
        }
    }
    cache = IpReputationCache(db_path=tmp_path / "r.db")
    client = _FakeClient(cache=cache, payload=payload)

    v1 = await client.query_ip("1.2.3.4")
    assert v1 is not None and v1.level == "bad"

    # Sabotage the fetcher so a second call would fail if it ran.
    async def _boom(ip: str, key: str) -> Any:
        raise AssertionError("Second call should hit cache, not HTTP")

    client._fetch_raw = _boom  # type: ignore[method-assign]
    v2 = await client.query_ip("1.2.3.4")
    assert v2 is not None and v2.level == "bad"


# ---------------------------------------------------------------------------
# Circuit breaker + negative cache (2026-04-23 GreyNoise 429 incident)
# ---------------------------------------------------------------------------


class _FailingClient(VirusTotalClient):
    """Client whose ``_fetch_raw`` raises an HTTP 429 every time.

    Used by the rate-limit test path: a single 429 must trip the
    breaker immediately (v0.22.15) rather than burning through
    ``_CIRCUIT_BREAKER_THRESHOLD`` more requests.
    """

    def __init__(self, cache: IpReputationCache, retry_after: str | None = None) -> None:
        super().__init__(cache=cache)
        self.fetch_count = 0
        self._retry_after = retry_after

    async def _fetch_raw(self, ip: str, api_key: str) -> Any:
        import httpx

        self.fetch_count += 1
        request = httpx.Request("GET", "https://example.test/")
        headers = {"Retry-After": self._retry_after} if self._retry_after else {}
        response = httpx.Response(status_code=429, request=request, headers=headers)
        raise httpx.HTTPStatusError("429 Too Many Requests", request=request, response=response)


class _GenericFailingClient(VirusTotalClient):
    """Client whose ``_fetch_raw`` raises a generic transport error.

    Used for the 5-strike circuit-breaker tests: a single transient
    error (DNS blip, RST, timeout) must NOT trip the breaker —
    only sustained failure should. Distinct from the 429 path which
    trips immediately because the API explicitly asks us to back off.
    """

    def __init__(self, cache: IpReputationCache) -> None:
        super().__init__(cache=cache)
        self.fetch_count = 0

    async def _fetch_raw(self, ip: str, api_key: str) -> Any:
        import httpx

        self.fetch_count += 1
        raise httpx.RemoteProtocolError("connection lost")


@pytest.mark.asyncio
async def test_negative_cache_suppresses_retry_on_same_ip(tmp_path: Path, monkeypatch: Any) -> None:
    """After a failure on IP X, a second call on X must not hit HTTP.

    Regression for the GreyNoise 429 flood: before the negative
    cache, every new alert on a previously-failed IP re-issued the
    HTTP request and got another 429.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    assert await client.query_ip("1.2.3.4") is None
    assert client.fetch_count == 1

    # Second call on the same IP is short-circuited by the negative cache.
    assert await client.query_ip("1.2.3.4") is None
    assert client.fetch_count == 1


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_threshold(tmp_path: Path, monkeypatch: Any) -> None:
    """After N consecutive *generic* failures across different IPs,
    further calls are suppressed without HTTP — protecting what's
    left of the daily quota until the cooldown expires.

    Uses the generic-failure client (transport error) because 429s
    now trip the breaker immediately on a single occurrence
    (v0.22.15); the threshold rule still applies to non-429 errors.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _GenericFailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    threshold = client._CIRCUIT_BREAKER_THRESHOLD  # noqa: SLF001
    for i in range(threshold):
        assert await client.query_ip(f"10.0.0.{i}") is None
    assert client.fetch_count == threshold

    # Breaker is now open — next IP call bypasses HTTP.
    assert await client.query_ip("10.0.0.99") is None
    assert client.fetch_count == threshold  # unchanged


@pytest.mark.asyncio
async def test_circuit_breaker_closes_after_cooldown(tmp_path: Path, monkeypatch: Any) -> None:
    """Manually expire the cooldown; a new attempt must hit HTTP again.

    Real cooldown is 15 min; we shorten it via the class-level
    attribute so the test can run instantly. Uses the generic
    failing client so the 5-strike rule is what trips the breaker.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _GenericFailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    threshold = client._CIRCUIT_BREAKER_THRESHOLD  # noqa: SLF001
    for i in range(threshold):
        await client.query_ip(f"10.0.0.{i}")
    assert client._is_circuit_open() is True  # noqa: SLF001

    # Fast-forward: pretend the cooldown window has elapsed.
    client._circuit_open_until = 0.0  # noqa: SLF001

    # A fresh IP (not in negative cache) goes through the network
    # again — fetch count increments.
    before = client.fetch_count
    await client.query_ip("10.0.0.200")
    assert client.fetch_count == before + 1


@pytest.mark.asyncio
async def test_success_resets_consecutive_failures(tmp_path: Path, monkeypatch: Any) -> None:
    """One successful call zeroes the failure counter so a single
    transient blip does not push the client to the brink of tripping.

    Uses the generic failing client because 429s do not increment
    ``_consecutive_failures`` — they trip the breaker through a
    different code path.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    cache = IpReputationCache(db_path=tmp_path / "r.db")
    failing = _GenericFailingClient(cache=cache)

    await failing.query_ip("10.0.0.1")
    assert failing._consecutive_failures == 1  # noqa: SLF001

    # Swap in a healthy fetcher and confirm the counter resets.
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 10,
                }
            }
        }
    }

    async def _ok(ip: str, key: str) -> Any:
        return payload

    failing._fetch_raw = _ok  # type: ignore[method-assign]
    result = await failing.query_ip("10.0.0.2")
    assert result is not None
    assert failing._consecutive_failures == 0  # noqa: SLF001
    assert failing._circuit_open_until == 0.0  # noqa: SLF001


@pytest.mark.asyncio
async def test_http_error_with_empty_message_logs_exception_type(
    tmp_path: Path, monkeypatch: Any, caplog: Any
) -> None:
    """Regression for the ``intel.alienvault_otx: HTTP error on X:``
    lines observed on 2026-04-23 — some httpx exceptions carry no
    args, so ``str(exc)`` was empty and the log ended with a dangling
    colon. We now fall back to the exception class name so the
    operator always sees *something* after the colon."""
    import logging

    import httpx

    class _EmptyErrorClient(VirusTotalClient):
        async def _fetch_raw(self, ip: str, api_key: str) -> Any:
            # RemoteProtocolError() with no args → str(exc) == "".
            raise httpx.RemoteProtocolError("")

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _EmptyErrorClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    with caplog.at_level(logging.WARNING, logger="ward_soar.intel.http_client"):
        await client.query_ip("1.2.3.4")

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected a WARNING log on HTTP error"
    message = warnings[-1].getMessage()
    # Message must not end with a dangling colon-space.
    assert not message.rstrip().endswith(":"), message
    assert "RemoteProtocolError" in message


@pytest.mark.asyncio
async def test_negative_cache_expires_after_ttl(tmp_path: Path, monkeypatch: Any) -> None:
    """Once the negative-cache TTL has elapsed, the IP is retried.

    Prevents a dead cache entry from permanently black-holing an IP
    that only glitched transiently.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    await client.query_ip("1.2.3.4")
    assert client.fetch_count == 1
    assert client._is_negatively_cached("1.2.3.4") is True  # noqa: SLF001

    # Expire the negative entry manually and verify the next call hits HTTP.
    client._negative_cache["1.2.3.4"] = 0.0  # noqa: SLF001
    # Fresh circuit (don't let the earlier failure keep it open).
    client._consecutive_failures = 0  # noqa: SLF001
    client._circuit_open_until = 0.0  # noqa: SLF001
    assert client._is_negatively_cached("1.2.3.4") is False  # noqa: SLF001

    await client.query_ip("1.2.3.4")
    assert client.fetch_count == 2


# ---------------------------------------------------------------------------
# Explicit 429 handling (v0.22.15 — GreyNoise rate-limit follow-up)
# ---------------------------------------------------------------------------


class TestParseRetryAfter:
    """Unit tests for the ``Retry-After`` header parser."""

    def test_integer_seconds(self) -> None:
        from wardsoar.core.intel.http_client_base import _parse_retry_after_seconds

        assert _parse_retry_after_seconds("60") == 60.0
        assert _parse_retry_after_seconds(" 30 ") == 30.0

    def test_http_date_in_the_future(self) -> None:
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime

        from wardsoar.core.intel.http_client_base import _parse_retry_after_seconds

        target = datetime.now(timezone.utc) + timedelta(seconds=120)
        header = format_datetime(target, usegmt=True)
        result = _parse_retry_after_seconds(header)
        assert result is not None
        # Allow some clock-drift tolerance (test execution time).
        assert 60 <= result <= 180

    def test_http_date_in_the_past_returns_none(self) -> None:
        from wardsoar.core.intel.http_client_base import _parse_retry_after_seconds

        # RFC 1123 date well in the past.
        assert _parse_retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") is None

    def test_missing_header_returns_none(self) -> None:
        from wardsoar.core.intel.http_client_base import _parse_retry_after_seconds

        assert _parse_retry_after_seconds(None) is None
        assert _parse_retry_after_seconds("") is None
        assert _parse_retry_after_seconds("   ") is None

    def test_malformed_returns_none(self) -> None:
        from wardsoar.core.intel.http_client_base import _parse_retry_after_seconds

        assert _parse_retry_after_seconds("not-a-date") is None
        assert _parse_retry_after_seconds("-1") is None  # not a digit string

    def test_above_24h_cap_returns_none(self) -> None:
        """Hostile or buggy server cannot lock us out for a week."""
        from wardsoar.core.intel.http_client_base import _parse_retry_after_seconds

        assert _parse_retry_after_seconds(str(48 * 3600)) is None


@pytest.mark.asyncio
async def test_429_trips_breaker_immediately(tmp_path: Path, monkeypatch: Any) -> None:
    """A single 429 must open the breaker — distinct from the 5-strike
    rule that applies to generic failures.

    Regression for the GreyNoise rate-limit observation on
    2026-04-25: the legacy code burned 4 more requests reaching the
    threshold while the API was already explicitly asking us to back
    off."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    # Fresh state: breaker closed, no failures recorded.
    assert client._is_circuit_open() is False  # noqa: SLF001
    assert client._consecutive_failures == 0  # noqa: SLF001

    # Exactly one 429 → breaker opens.
    assert await client.query_ip("1.2.3.4") is None
    assert client.fetch_count == 1
    assert client._is_circuit_open() is True  # noqa: SLF001
    # The 429 path must NOT increment ``_consecutive_failures``;
    # that counter belongs to the generic 5-strike rule.
    assert client._consecutive_failures == 0  # noqa: SLF001

    # A second IP would also be blocked silently — without HTTP.
    assert await client.query_ip("5.6.7.8") is None
    assert client.fetch_count == 1


@pytest.mark.asyncio
async def test_429_with_retry_after_seconds_uses_that_cooldown(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """When the server returns ``Retry-After: 30`` the breaker stays
    open for ~30 s, not the 60 s default."""
    import time

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"), retry_after="30")

    before = time.monotonic()
    await client.query_ip("1.2.3.4")
    after = time.monotonic()

    # Cooldown window should be ~30 s from the moment the 429
    # arrived, not the 60 s default.
    expected_lower = before + 30 - 1  # 1 s tolerance
    expected_upper = after + 30 + 1
    assert expected_lower <= client._circuit_open_until <= expected_upper  # noqa: SLF001


@pytest.mark.asyncio
async def test_429_without_retry_after_uses_default_cooldown(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """No ``Retry-After`` header → the 60 s default kicks in."""
    import time

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"), retry_after=None)

    before = time.monotonic()
    await client.query_ip("1.2.3.4")
    after = time.monotonic()

    expected_default = client._RATE_LIMIT_DEFAULT_COOLDOWN_S  # noqa: SLF001
    expected_lower = before + expected_default - 1
    expected_upper = after + expected_default + 1
    assert expected_lower <= client._circuit_open_until <= expected_upper  # noqa: SLF001


@pytest.mark.asyncio
async def test_429_logs_at_info_level_not_warning(
    tmp_path: Path, monkeypatch: Any, caplog: Any
) -> None:
    """Rate-limited is a normal handled condition; logging at
    WARNING would create operator-fatigue noise. INFO matches the
    existing convention for fail-safe routes elsewhere in the
    codebase (cf. v0.22.9 RFC1918 / whitelist log demotions)."""
    import logging

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"))

    with caplog.at_level(logging.INFO, logger="ward_soar.intel.http_client"):
        await client.query_ip("1.2.3.4")

    rate_limit_logs = [r for r in caplog.records if "rate limited" in r.getMessage().lower()]
    assert rate_limit_logs, "expected an INFO log for the 429 trip"
    assert all(
        r.levelno == logging.INFO for r in rate_limit_logs
    ), "429 must NOT log at WARNING — it is a handled signal, not an error"


@pytest.mark.asyncio
async def test_429_breaker_window_only_extends_never_shrinks(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """If two 429s arrive in quick succession with different
    ``Retry-After`` values, the *longer* window must win.

    Without this rule, a later 429 with a 5 s Retry-After could
    cancel an earlier 60 s window and let traffic resume too soon.
    """
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    client = _FailingClient(cache=IpReputationCache(db_path=tmp_path / "r.db"), retry_after="600")
    await client.query_ip("1.2.3.4")
    long_window = client._circuit_open_until  # noqa: SLF001

    # Now fake a second 429 with a much shorter Retry-After. Since
    # the breaker is already open and the IP is in the negative
    # cache, query_ip would short-circuit; call the handler directly
    # to exercise the "only extends" path.
    client._open_breaker_for_rate_limit("9.9.9.9", "10")  # noqa: SLF001
    short_window = client._circuit_open_until  # noqa: SLF001

    assert (
        short_window == long_window
    ), "shorter Retry-After must NOT shrink an already-longer breaker window"


@pytest.mark.asyncio
async def test_429_negative_cache_extended_to_at_least_cooldown(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """When ``Retry-After`` exceeds the per-IP negative-cache TTL
    (15 min default), the negative cache must extend to match.

    Otherwise an IP could re-fetch inside the cooldown window once
    the negative TTL expired but before the breaker was reset by an
    unrelated success."""
    import time

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key")
    long_cooldown_s = client_threshold = 60 * 60  # 1 hour
    client = _FailingClient(
        cache=IpReputationCache(db_path=tmp_path / "r.db"),
        retry_after=str(long_cooldown_s),
    )

    before = time.monotonic()
    await client.query_ip("1.2.3.4")
    expiry = client._negative_cache["1.2.3.4"]  # noqa: SLF001

    # Negative cache should extend to the longer of:
    #   - the default _NEGATIVE_CACHE_TTL_S (15 min)
    #   - the rate-limit cooldown (1 hour here)
    assert expiry >= before + client_threshold - 1
