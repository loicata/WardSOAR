"""Tests for WardSOAR network context collector.

Collector is STANDARD (80% coverage). All external calls
(psutil, subprocess, httpx) are mocked.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from wardsoar.pc.collector import ContextCollector
from wardsoar.core.models import (
    IPReputation,
    NetworkContext,
    SuricataAlert,
    SuricataAlertSeverity,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_alert(src_ip: str = "10.0.0.1") -> SuricataAlert:
    """Create a minimal test alert."""
    return SuricataAlert(
        timestamp=datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc),
        src_ip=src_ip,
        src_port=12345,
        dest_ip="192.168.1.100",
        dest_port=443,
        proto="TCP",
        alert_signature="Test",
        alert_signature_id=1000,
        alert_severity=SuricataAlertSeverity.HIGH,
    )


# ---------------------------------------------------------------------------
# ContextCollector init tests
# ---------------------------------------------------------------------------


class TestContextCollectorInit:
    """Tests for ContextCollector initialization."""

    def test_construction(self) -> None:
        collector = ContextCollector(config={})
        assert collector._config == {}


# ---------------------------------------------------------------------------
# get_active_connections tests
# ---------------------------------------------------------------------------


class TestGetActiveConnections:
    """Tests for ContextCollector.get_active_connections."""

    @pytest.mark.asyncio
    async def test_returns_connections(self) -> None:
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.psutil") as mock_psutil:
            mock_conn = MagicMock()
            mock_conn.laddr = MagicMock(ip="192.168.1.100", port=443)
            mock_conn.raddr = MagicMock(ip="10.0.0.1", port=54321)
            mock_conn.status = "ESTABLISHED"
            mock_conn.pid = 1234
            mock_psutil.net_connections.return_value = [mock_conn]

            result = await collector.get_active_connections()
            assert len(result) == 1
            assert result[0]["local_ip"] == "192.168.1.100"
            assert result[0]["remote_ip"] == "10.0.0.1"
            assert result[0]["pid"] == 1234

    @pytest.mark.asyncio
    async def test_filter_by_ip(self) -> None:
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.psutil") as mock_psutil:
            conn1 = MagicMock()
            conn1.laddr = MagicMock(ip="192.168.1.100", port=443)
            conn1.raddr = MagicMock(ip="10.0.0.1", port=54321)
            conn1.status = "ESTABLISHED"
            conn1.pid = 1234

            conn2 = MagicMock()
            conn2.laddr = MagicMock(ip="192.168.1.100", port=80)
            conn2.raddr = MagicMock(ip="1.2.3.4", port=12345)
            conn2.status = "ESTABLISHED"
            conn2.pid = 5678

            mock_psutil.net_connections.return_value = [conn1, conn2]

            result = await collector.get_active_connections(filter_ip="10.0.0.1")
            assert len(result) == 1
            assert result[0]["remote_ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_handles_connections_without_raddr(self) -> None:
        """Connections with no remote address (listening) should be skipped."""
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.psutil") as mock_psutil:
            conn = MagicMock()
            conn.laddr = MagicMock(ip="0.0.0.0", port=80)
            conn.raddr = None
            conn.status = "LISTEN"
            conn.pid = 100
            mock_psutil.net_connections.return_value = [conn]

            result = await collector.get_active_connections()
            assert len(result) == 0

    @pytest.mark.asyncio
    async def test_error_returns_empty_list(self) -> None:
        """Fail-safe: errors should return empty list, not crash."""
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.psutil") as mock_psutil:
            mock_psutil.net_connections.side_effect = PermissionError("Access denied")
            result = await collector.get_active_connections()
            assert result == []


# ---------------------------------------------------------------------------
# get_dns_cache tests
# ---------------------------------------------------------------------------


class TestGetDnsCache:
    """Tests for ContextCollector.get_dns_cache."""

    @pytest.mark.asyncio
    async def test_returns_dns_entries(self) -> None:
        collector = ContextCollector(config={})
        mock_output = (
            "Entry                RecordName          Record Type  Data\n"
            "----                 ----------          -----------  ----\n"
            "example.com          example.com         A            93.184.216.34\n"
        )
        with patch("wardsoar.pc.collector.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.stdout = mock_output
            mock_result.returncode = 0
            mock_sub.run.return_value = mock_result

            result = await collector.get_dns_cache()
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_error_returns_empty_list(self) -> None:
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.subprocess") as mock_sub:
            mock_sub.run.side_effect = FileNotFoundError("powershell not found")
            result = await collector.get_dns_cache()
            assert result == []

    @pytest.mark.asyncio
    async def test_stdout_none_returns_empty_list(self) -> None:
        """Regression for the 2026-04-20 ``'NoneType' object has no
        attribute 'strip'`` pipeline crashes. ``subprocess.run`` can
        return ``stdout=None`` on an abnormal child exit even under
        ``text=True, capture_output=True``; the collector must fall
        back to an empty list rather than letting the AttributeError
        out."""
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = None  # <-- the pathological case
            mock_sub.run.return_value = mock_result

            result = await collector.get_dns_cache()
            assert result == []


# ---------------------------------------------------------------------------
# get_arp_cache tests
# ---------------------------------------------------------------------------


class TestGetArpCache:
    """Tests for ContextCollector.get_arp_cache."""

    @pytest.mark.asyncio
    async def test_returns_arp_entries(self) -> None:
        collector = ContextCollector(config={})
        mock_output = "192.168.1.1     00-11-22-33-44-55  dynamic\n"
        with patch("wardsoar.pc.collector.subprocess") as mock_sub:
            mock_result = MagicMock()
            mock_result.stdout = mock_output
            mock_result.returncode = 0
            mock_sub.run.return_value = mock_result

            result = await collector.get_arp_cache()
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_error_returns_empty_list(self) -> None:
        collector = ContextCollector(config={})
        with patch("wardsoar.pc.collector.subprocess") as mock_sub:
            mock_sub.run.side_effect = OSError("Command failed")
            result = await collector.get_arp_cache()
            assert result == []


# ---------------------------------------------------------------------------
# get_ip_reputation tests
# ---------------------------------------------------------------------------


class TestGetIpReputation:
    """Tests for ContextCollector.get_ip_reputation."""

    @pytest.mark.asyncio
    async def test_returns_reputation(self) -> None:
        collector = ContextCollector(config={})
        result = await collector.get_ip_reputation("1.2.3.4")
        assert isinstance(result, IPReputation)
        assert result.ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_private_ip_not_malicious(self) -> None:
        collector = ContextCollector(config={})
        result = await collector.get_ip_reputation("192.168.1.1")
        assert result.is_known_malicious is False

    @pytest.mark.asyncio
    async def test_disabled_abuseipdb_skipped(self) -> None:
        """AbuseIPDB should not be queried when disabled."""
        reputation_cfg = {"abuseipdb": {"enabled": False}}
        collector = ContextCollector(config={}, reputation_config=reputation_cfg)
        result = await collector.get_ip_reputation("8.8.8.8")
        assert result.abuseipdb_score is None

    @pytest.mark.asyncio
    async def test_abuseipdb_flags_malicious_ip(self) -> None:
        """AbuseIPDB should flag IPs above confidence threshold."""
        reputation_cfg = {"abuseipdb": {"enabled": True, "confidence_threshold": 50}}
        collector = ContextCollector(config={}, reputation_config=reputation_cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 85}}

        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("wardsoar.pc.collector.httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get.return_value = mock_response
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value = mock_instance

                result = await collector.get_ip_reputation("91.12.44.8")

        assert result.abuseipdb_score == 85
        assert result.is_known_malicious is True
        assert "abuseipdb" in result.sources

    @pytest.mark.asyncio
    async def test_abuseipdb_below_threshold_not_malicious(self) -> None:
        """AbuseIPDB score below threshold should not flag as malicious."""
        reputation_cfg = {"abuseipdb": {"enabled": True, "confidence_threshold": 50}}
        collector = ContextCollector(config={}, reputation_config=reputation_cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 20}}

        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("wardsoar.pc.collector.httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get.return_value = mock_response
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value = mock_instance

                result = await collector.get_ip_reputation("1.2.3.4")

        assert result.abuseipdb_score == 20
        assert result.is_known_malicious is False

    @pytest.mark.asyncio
    async def test_abuseipdb_timeout_failsafe(self) -> None:
        """AbuseIPDB timeout should not crash — fail-safe."""
        reputation_cfg = {"abuseipdb": {"enabled": True}}
        collector = ContextCollector(config={}, reputation_config=reputation_cfg)

        with patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test-key"}):
            with patch("wardsoar.pc.collector.httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get.side_effect = httpx.TimeoutException("timeout")
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value = mock_instance

                result = await collector.get_ip_reputation("91.12.44.8")

        assert result.abuseipdb_score is None
        assert result.is_known_malicious is False

    @pytest.mark.asyncio
    async def test_otx_flags_malicious_ip(self) -> None:
        """OTX should flag IPs with pulse count > 0."""
        reputation_cfg = {"otx": {"enabled": True}}
        collector = ContextCollector(config={}, reputation_config=reputation_cfg)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"pulse_info": {"count": 5}}

        with patch.dict("os.environ", {"OTX_API_KEY": "test-key"}):
            with patch("wardsoar.pc.collector.httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get.return_value = mock_response
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client.return_value = mock_instance

                result = await collector.get_ip_reputation("91.12.44.8")

        assert result.otx_pulse_count == 5
        assert result.is_known_malicious is True
        assert "otx" in result.sources

    @pytest.mark.asyncio
    async def test_no_api_key_skips_service(self) -> None:
        """Services should be skipped if API key is not set."""
        reputation_cfg = {"abuseipdb": {"enabled": True}, "otx": {"enabled": True}}
        collector = ContextCollector(config={}, reputation_config=reputation_cfg)

        with patch.dict("os.environ", {}, clear=True):
            result = await collector.get_ip_reputation("91.12.44.8")

        assert result.abuseipdb_score is None
        assert result.otx_pulse_count is None
        assert result.is_known_malicious is False


# ---------------------------------------------------------------------------
# collect (integration) tests
# ---------------------------------------------------------------------------


class TestCollect:
    """Tests for ContextCollector.collect (full collection)."""

    @pytest.mark.asyncio
    async def test_collect_returns_network_context(self) -> None:
        collector = ContextCollector(config={})
        # Mock all sub-methods
        collector.get_active_connections = AsyncMock(return_value=[])  # type: ignore[method-assign]
        collector.get_dns_cache = AsyncMock(return_value=[])  # type: ignore[method-assign]
        collector.get_arp_cache = AsyncMock(return_value=[])  # type: ignore[method-assign]
        collector.get_ip_reputation = AsyncMock(  # type: ignore[method-assign]
            return_value=IPReputation(ip="10.0.0.1")
        )

        alert = _make_alert()
        result = await collector.collect(alert)

        assert isinstance(result, NetworkContext)
        assert result.ip_reputation is not None
        assert result.ip_reputation.ip == "10.0.0.1"
