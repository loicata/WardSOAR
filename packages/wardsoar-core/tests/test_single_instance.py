"""Tests for the Windows single-instance guard.

The guard is a thin wrapper around a Win32 named mutex. The tests
exercise it on Windows (where the real mutex is created) and verify
the fail-open path when pywin32 is patched out.
"""

from __future__ import annotations

import os
import uuid

import pytest

from wardsoar.core.single_instance import SingleInstanceGuard, activate_existing_window


def _fresh_name() -> str:
    """Return a unique Local\\ mutex name so tests do not collide.

    pytest can run tests in arbitrary order and parallel workers would
    otherwise fight over the default project-wide name.
    """
    return f"Local\\WardSOARGuardTest-{uuid.uuid4()}"


@pytest.mark.skipif(os.name != "nt", reason="Named mutex is Windows-only")
class TestSingleInstanceOnWindows:
    """Real Win32 mutex behaviour — skipped on non-Windows CI."""

    def test_first_acquire_is_free(self) -> None:
        guard = SingleInstanceGuard(name=_fresh_name())
        try:
            assert guard.already_running() is False
        finally:
            guard.release()

    def test_second_guard_detects_prior_owner(self) -> None:
        name = _fresh_name()
        first = SingleInstanceGuard(name=name)
        try:
            assert first.already_running() is False
            second = SingleInstanceGuard(name=name)
            try:
                assert second.already_running() is True
            finally:
                second.release()
        finally:
            first.release()

    def test_release_allows_reacquisition(self) -> None:
        name = _fresh_name()
        first = SingleInstanceGuard(name=name)
        first.release()

        # After release, a new guard built under the same name must
        # become the owner rather than see itself as "already running".
        second = SingleInstanceGuard(name=name)
        try:
            assert second.already_running() is False
        finally:
            second.release()

    def test_double_release_is_safe(self) -> None:
        """Release is idempotent; the second call must not raise."""
        guard = SingleInstanceGuard(name=_fresh_name())
        guard.release()
        guard.release()  # no-op, must not raise


class TestFailOpen:
    """When pywin32 is unavailable, the guard must not refuse to launch."""

    def test_missing_win32_means_not_running(self, monkeypatch: "pytest.MonkeyPatch") -> None:
        """Simulate an environment without pywin32 by making the import fail.

        We patch ``builtins.__import__`` to raise :class:`ImportError`
        for the win32 module names the guard reaches for. The guard
        must then report ``already_running() is False`` so the main
        application still starts — fail-open is safer than fail-closed
        for a desktop app that the user double-clicked.
        """
        import builtins

        original_import = builtins.__import__
        blocked = {"win32event", "win32api", "win32gui", "win32con"}

        def _blocked_import(
            name: str,
            globals_: "dict[str, object] | None" = None,
            locals_: "dict[str, object] | None" = None,
            fromlist: "tuple[str, ...]" = (),
            level: int = 0,
        ) -> object:
            if name in blocked:
                raise ImportError(f"simulated missing {name}")
            return original_import(name, globals_, locals_, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", _blocked_import)

        guard = SingleInstanceGuard(name=_fresh_name())
        assert guard.already_running() is False
        guard.release()  # no-op, must not raise

    def test_activate_existing_returns_false_without_win32(
        self, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        import builtins

        original_import = builtins.__import__

        def _blocked_import(
            name: str,
            globals_: "dict[str, object] | None" = None,
            locals_: "dict[str, object] | None" = None,
            fromlist: "tuple[str, ...]" = (),
            level: int = 0,
        ) -> object:
            if name in {"win32gui", "win32con"}:
                raise ImportError(f"simulated missing {name}")
            return original_import(name, globals_, locals_, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", _blocked_import)

        assert activate_existing_window("WardSOAR") is False
