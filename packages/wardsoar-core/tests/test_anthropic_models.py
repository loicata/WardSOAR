"""Tests for the Anthropic model-list resolver.

Every external interaction is mocked at the ``httpx.get`` boundary —
no real network call hits Anthropic. The resolver is best-effort by
contract (returns ``None`` on any failure), so the tests focus on
the failure modes that drive the wizard's fallback path.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

from wardsoar.core.anthropic_models import (
    ANTHROPIC_API_VERSION,
    ANTHROPIC_MODELS_URL,
    fetch_available_models,
)


def _response(status: int, payload: Any) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = "" if isinstance(payload, dict) else str(payload)
    if isinstance(payload, dict):
        resp.json = MagicMock(return_value=payload)
    else:
        # Simulate a body that's not JSON.
        def _raise() -> Any:
            raise ValueError("not JSON")

        resp.json = MagicMock(side_effect=_raise)
    return resp


class TestFetchAvailableModels:
    def test_empty_api_key_returns_none_without_network_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # If the wizard has no key yet (page Keys still empty), do not
        # hit the network — return None straight away.
        called = {"n": 0}

        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            called["n"] += 1
            return _response(200, {"data": []})

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("") is None
        assert called["n"] == 0

    def test_happy_path_returns_id_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {
            "data": [
                {"id": "claude-opus-5-0", "type": "model"},
                {"id": "claude-opus-4-7", "type": "model"},
                {"id": "claude-sonnet-4-6", "type": "model"},
            ]
        }
        captured: dict[str, Any] = {}

        def fake_get(url: str, headers: dict[str, str], timeout: float) -> Any:
            captured["url"] = url
            captured["headers"] = headers
            captured["timeout"] = timeout
            return _response(200, payload)

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        ids = fetch_available_models("sk-ant-test")
        assert ids == ["claude-opus-5-0", "claude-opus-4-7", "claude-sonnet-4-6"]
        # Auth header + version pinned per the contract.
        assert captured["headers"]["x-api-key"] == "sk-ant-test"
        assert captured["headers"]["anthropic-version"] == ANTHROPIC_API_VERSION
        assert captured["url"] == ANTHROPIC_MODELS_URL

    def test_url_override_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, str] = {}

        def fake_get(url: str, **_kwargs: Any) -> Any:
            captured["url"] = url
            return _response(200, {"data": [{"id": "claude-x", "type": "model"}]})

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        ids = fetch_available_models("sk-ant", url="https://example.test/models")
        assert captured["url"] == "https://example.test/models"
        assert ids == ["claude-x"]

    def test_http_error_status_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            return _response(401, {"error": "unauthorized"})

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("sk-ant-bad") is None

    def test_network_error_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            raise httpx.ConnectError("dns down")

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("sk-ant") is None

    def test_non_json_body_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            return _response(200, "<html>not json</html>")

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("sk-ant") is None

    def test_payload_without_data_list_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Schema drift: data isn't there or isn't a list.
        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            return _response(200, {"models": ["claude-x"]})  # wrong key

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("sk-ant") is None

    def test_empty_data_list_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Anthropic returned a valid envelope but with zero models — odd
        # but possible (rate-limit window?). Treat as fallback trigger.
        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            return _response(200, {"data": []})

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("sk-ant") is None

    def test_entries_without_id_are_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {
            "data": [
                {"id": "claude-opus-5-0"},
                {"type": "model"},  # no id
                {"id": "", "type": "model"},  # empty id
                {"id": 42},  # wrong type
                {"id": "claude-haiku-5"},
            ]
        }

        def fake_get(*_args: Any, **_kwargs: Any) -> Any:
            return _response(200, payload)

        monkeypatch.setattr("wardsoar.core.anthropic_models.httpx.get", fake_get)
        assert fetch_available_models("sk-ant") == ["claude-opus-5-0", "claude-haiku-5"]
