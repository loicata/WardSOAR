"""Tests for WardSOAR self-monitoring healthchecks.

HealthCheck is STANDARD (80% coverage). All external calls are mocked.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardsoar.pc.healthcheck import ComponentStatus, HealthChecker, HealthResult
from wardsoar.core.remote_agents.pfsense_ssh import PfSenseSSH


class TestHealthResult:
    """Tests for HealthResult dataclass."""

    def test_construction(self) -> None:
        result = HealthResult(component="test", status=ComponentStatus.HEALTHY, message="OK")
        assert result.component == "test"
        assert result.status == ComponentStatus.HEALTHY


class TestHealthCheckerInit:
    """Tests for HealthChecker initialization."""

    def test_default_config(self) -> None:
        hc = HealthChecker({})
        assert hc._enabled is True
        assert hc._interval_seconds == 300

    def test_get_last_results_empty(self) -> None:
        hc = HealthChecker({})
        assert hc.get_last_results() == []


class TestIndividualChecks:
    """Tests for individual healthcheck methods."""

    @pytest.mark.asyncio
    async def test_check_disk_space_healthy(self) -> None:
        hc = HealthChecker({"disk_warning_threshold_mb": 100})
        with patch("wardsoar.pc.healthcheck.psutil") as mock_psutil:
            mock_psutil.disk_usage.return_value = MagicMock(free=1_000_000_000)
            result = await hc.check_disk_space()
        assert result.status == ComponentStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_check_disk_space_low(self) -> None:
        hc = HealthChecker({"disk_warning_threshold_mb": 1000})
        with patch("wardsoar.pc.healthcheck.psutil") as mock_psutil:
            mock_psutil.disk_usage.return_value = MagicMock(free=100_000_000)
            result = await hc.check_disk_space()
        assert result.status == ComponentStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_check_eve_json_exists(self, tmp_path: Path) -> None:
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("test", encoding="utf-8")
        hc = HealthChecker({"eve_json_path": str(eve_file), "eve_max_age_seconds": 60})
        result = await hc.check_eve_json_file()
        assert result.status == ComponentStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_check_eve_json_missing(self) -> None:
        hc = HealthChecker({"eve_json_path": "/nonexistent/file.json"})
        result = await hc.check_eve_json_file()
        assert result.status == ComponentStatus.FAILED

    @pytest.mark.asyncio
    async def test_check_pfsense_ssh_healthy(self) -> None:
        mock_ssh = MagicMock(spec=PfSenseSSH)
        mock_ssh.check_status = AsyncMock(return_value=(True, "pfSense SSH reachable"))
        hc = HealthChecker({}, pfsense_ssh=mock_ssh)
        result = await hc.check_pfsense_ssh()
        assert result.status == ComponentStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_check_pfsense_ssh_failed(self) -> None:
        mock_ssh = MagicMock(spec=PfSenseSSH)
        mock_ssh.check_status = AsyncMock(return_value=(False, "timeout"))
        hc = HealthChecker({}, pfsense_ssh=mock_ssh)
        result = await hc.check_pfsense_ssh()
        assert result.status == ComponentStatus.FAILED

    @pytest.mark.asyncio
    async def test_check_pfsense_ssh_not_configured(self) -> None:
        hc = HealthChecker({})
        result = await hc.check_pfsense_ssh()
        assert result.status == ComponentStatus.UNKNOWN


class TestRunAllChecks:
    """Tests for run_all_checks."""

    @pytest.mark.asyncio
    async def test_returns_results(self) -> None:
        hc = HealthChecker({})
        hc.check_pfsense_ssh = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="pfSense", status=ComponentStatus.HEALTHY)
        )
        hc.check_claude_api = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="Claude", status=ComponentStatus.HEALTHY)
        )
        hc.check_virustotal_api = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="VirusTotal", status=ComponentStatus.HEALTHY)
        )
        hc.check_eve_json_file = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="EVE JSON", status=ComponentStatus.HEALTHY)
        )
        hc.check_sysmon_service = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="Sysmon", status=ComponentStatus.HEALTHY)
        )
        hc.check_disk_space = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="Disk", status=ComponentStatus.HEALTHY)
        )

        results = await hc.run_all_checks()
        assert len(results) >= 5
        assert all(r.status == ComponentStatus.HEALTHY for r in results)

    @pytest.mark.asyncio
    async def test_check_failure_returns_unknown(self) -> None:
        hc = HealthChecker({})
        hc.check_pfsense_ssh = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        hc.check_claude_api = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="Claude", status=ComponentStatus.HEALTHY)
        )
        hc.check_virustotal_api = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="VT", status=ComponentStatus.HEALTHY)
        )
        hc.check_eve_json_file = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="EVE", status=ComponentStatus.HEALTHY)
        )
        hc.check_sysmon_service = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="Sysmon", status=ComponentStatus.HEALTHY)
        )
        hc.check_disk_space = AsyncMock(  # type: ignore[method-assign]
            return_value=HealthResult(component="Disk", status=ComponentStatus.HEALTHY)
        )

        results = await hc.run_all_checks()
        unknown = [r for r in results if r.status == ComponentStatus.UNKNOWN]
        assert len(unknown) == 1

    @pytest.mark.asyncio
    async def test_check_claude_api_no_key(self) -> None:
        hc = HealthChecker({})
        with patch.dict("os.environ", {}, clear=True):
            result = await hc.check_claude_api()
        assert result.status == ComponentStatus.FAILED

    @pytest.mark.asyncio
    async def test_check_eve_no_path(self) -> None:
        hc = HealthChecker({})
        result = await hc.check_eve_json_file()
        assert result.status == ComponentStatus.UNKNOWN


class TestOverallStatus:
    """Tests for get_overall_status."""

    def test_all_healthy(self) -> None:
        hc = HealthChecker({})
        hc._last_results = [
            HealthResult(component="A", status=ComponentStatus.HEALTHY),
            HealthResult(component="B", status=ComponentStatus.HEALTHY),
        ]
        assert hc.get_overall_status() == ComponentStatus.HEALTHY

    def test_one_degraded(self) -> None:
        hc = HealthChecker({})
        hc._last_results = [
            HealthResult(component="A", status=ComponentStatus.HEALTHY),
            HealthResult(component="B", status=ComponentStatus.DEGRADED),
        ]
        assert hc.get_overall_status() == ComponentStatus.DEGRADED

    def test_one_failed(self) -> None:
        hc = HealthChecker({})
        hc._last_results = [
            HealthResult(component="A", status=ComponentStatus.HEALTHY),
            HealthResult(component="B", status=ComponentStatus.FAILED),
        ]
        assert hc.get_overall_status() == ComponentStatus.FAILED

    def test_no_results(self) -> None:
        hc = HealthChecker({})
        assert hc.get_overall_status() == ComponentStatus.UNKNOWN
