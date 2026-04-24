"""Single-instance enforcement for the WardSOAR desktop app.

Two instances of WardSOAR running in parallel is a real foot-gun: the
log file takes double writes, ``alerts_history.jsonl`` can interleave
partial JSON lines, two SSH tails race for the same Netgate stream,
and the operator sees a stale UI while a second invisible instance
processes the alerts. All symptoms were observed in the field on
2026-04-22 when two instances started side-by-side after an MSI
upgrade.

This module provides :class:`SingleInstanceGuard`, a thin wrapper
around a Windows named mutex. The mutex lives in the ``Local``
namespace (per-session) so one mutex per user session is enough —
we do not want to block the pipeline on a fast-user-switch or on a
second interactive login.

Fail-open policy: if ``pywin32`` or ``win32event`` is unavailable,
the guard never acquires and ``already_running()`` returns ``False``
so the app still starts. Losing the guard to a missing dependency is
strictly better than refusing to launch.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("ward_soar.single_instance")


# Stable, project-specific name so an MSI upgrade (which reinstalls the
# binaries but keeps the same user session) still sees the mutex of a
# previous instance. ``Local\\`` scopes it to the current session — we
# do not want to block a second user switching in on the same machine.
_MUTEX_NAME = "Local\\WardSOARSingleInstance"


class SingleInstanceGuard:
    """Reserve the WardSOAR "there can be only one" slot for this process.

    Usage::

        guard = SingleInstanceGuard()
        if guard.already_running():
            # show a message, exit 0
            return
        try:
            run_app()
        finally:
            guard.release()

    The instance owns the mutex until either :meth:`release` is called
    or the process exits (Windows releases the mutex automatically on
    process termination, including crashes — no stale lockfile to
    clean up after a hard kill).
    """

    def __init__(self, name: str = _MUTEX_NAME) -> None:
        self._name = name
        self._handle: Optional[int] = None
        self._already_running = self._try_acquire()

    def _try_acquire(self) -> bool:
        """Create the named mutex and detect a prior owner.

        Returns:
            ``True`` if another instance already holds the mutex,
            ``False`` when this call became the owner *or* when the
            Win32 APIs are unavailable (fail-open).
        """
        try:
            import win32event
            import winerror
            from pywintypes import error as PyWinError
        except ImportError:
            logger.debug("pywin32 not available — single-instance guard disabled")
            return False

        try:
            handle = win32event.CreateMutex(None, False, self._name)
        except PyWinError as exc:  # pragma: no cover — rare Win32 edge case
            logger.warning("CreateMutex failed for %s: %s", self._name, exc)
            return False

        # GetLastError is only meaningful right after the CreateMutex
        # call. We must check it before anything else touches Win32.
        try:
            import win32api

            last_error = win32api.GetLastError()
        except ImportError:  # pragma: no cover — pywin32 ships both
            last_error = 0

        if last_error == winerror.ERROR_ALREADY_EXISTS:
            # Someone else owns it. Close our (inert) handle so we do
            # not keep the mutex alive past our own exit.
            try:
                win32event.ReleaseMutex(handle)
            except PyWinError:
                pass
            try:
                import win32api

                win32api.CloseHandle(handle)
            except (ImportError, PyWinError):
                pass
            return True

        # We became the owner. Remember the handle so we can release it
        # on request (and so the mutex stays held for the process'
        # lifetime — Windows closes it automatically on exit).
        self._handle = handle
        return False

    def already_running(self) -> bool:
        """Return ``True`` when another WardSOAR instance owns the slot."""
        return self._already_running

    def release(self) -> None:
        """Release the mutex explicitly.

        Normally unnecessary — Windows cleans up on process exit — but
        useful in tests or when the caller wants to spawn a fresh
        replacement within the same process.
        """
        if self._handle is None:
            return
        try:
            import win32api
            import win32event

            win32event.ReleaseMutex(self._handle)
            win32api.CloseHandle(self._handle)
        except ImportError:  # pragma: no cover — only reachable in tests
            pass
        except Exception:  # noqa: BLE001 — release is best-effort
            logger.debug("Single-instance mutex release raised", exc_info=True)
        finally:
            self._handle = None


def activate_existing_window(window_title: str = "WardSOAR") -> bool:
    """Best-effort: bring the already-running WardSOAR window to front.

    Returns ``True`` when a matching window was found and the focus
    request was issued, ``False`` otherwise (including when the Win32
    APIs are unavailable).
    """
    try:
        import win32con
        import win32gui
    except ImportError:
        return False

    target: list[int] = []

    def _enum(hwnd: int, _arg: object) -> bool:
        text = win32gui.GetWindowText(hwnd) or ""
        if window_title in text and win32gui.IsWindowVisible(hwnd):
            target.append(hwnd)
        return True

    try:
        win32gui.EnumWindows(_enum, None)
    except Exception:  # noqa: BLE001 — enumeration is best-effort
        return False

    if not target:
        return False

    hwnd = target[0]
    try:
        # If minimised to tray, the window is not visible; un-hide it.
        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        win32gui.SetForegroundWindow(hwnd)
    except Exception:  # noqa: BLE001 — focus is best-effort
        return False
    return True
