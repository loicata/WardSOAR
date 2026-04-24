"""Process memory dumps via the Windows MiniDumpWriteDump API.

Captures the RAM of a single target process into a standard
``*.dmp`` file loadable by WinDbg, Volatility 3, or Magnet AXIOM.
This is the most volatile forensic artefact: the process may exit
between the block and the acquisition, so dumps are best-effort.

Mechanism:
    1. ``kernel32.OpenProcess`` with PROCESS_ALL_ACCESS (falls back to
       PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).
    2. ``kernel32.CreateFile`` with GENERIC_WRITE to open the output path.
    3. ``dbghelp.MiniDumpWriteDump`` to serialize the memory snapshot.

Dump type: ``MiniDumpWithFullMemory`` + ``MiniDumpWithHandleData``.
Produces a complete dump suitable for reverse engineering.

Fail-safe: any ctypes / Win32 error returns ``DumpFailed`` with the
reason; callers log and continue (other artefacts still acquired).
"""

from __future__ import annotations

import ctypes
import logging
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ward_soar.forensic.memory")


# Dump type flags (dbghelp.h). We pick a complete dump so downstream
# tools have everything they need.
_MINIDUMP_WITH_FULL_MEMORY = 0x00000002
_MINIDUMP_WITH_HANDLE_DATA = 0x00000004
_MINIDUMP_WITH_UNLOADED_MODULES = 0x00000020
_MINIDUMP_WITH_PROCESS_THREAD_DATA = 0x00000040
DEFAULT_DUMP_TYPE = (
    _MINIDUMP_WITH_FULL_MEMORY
    | _MINIDUMP_WITH_HANDLE_DATA
    | _MINIDUMP_WITH_UNLOADED_MODULES
    | _MINIDUMP_WITH_PROCESS_THREAD_DATA
)

# Win32 process-access rights.
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010
_PROCESS_ALL_ACCESS = 0x1FFFFF

# CreateFile access + share + disposition constants.
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_INVALID_HANDLE_VALUE = -1


@dataclass
class DumpResult:
    """Outcome of a MiniDumpWriteDump call.

    Attributes:
        pid: Target PID.
        success: True if the dump was written.
        path: Output file on success, None otherwise.
        size_bytes: Size of the dump on success.
        error: Description of the failure when ``success`` is False.
    """

    pid: int
    success: bool
    path: Optional[Path] = None
    size_bytes: int = 0
    error: Optional[str] = None


class DumpFailed(RuntimeError):
    """Raised internally; surfaced as :class:`DumpResult` to callers."""


class MinidumpWriter:
    """Write process minidumps via the Windows dbghelp API.

    The loader is lazy: if dbghelp.dll or kernel32 cannot be bound
    (e.g. on Linux tests), ``available`` returns False and
    :meth:`dump_process` returns a failed DumpResult without raising.
    """

    def __init__(self, dump_type: int = DEFAULT_DUMP_TYPE) -> None:
        self._dump_type = dump_type
        self._kernel32: Optional[ctypes.WinDLL] = None
        self._dbghelp: Optional[ctypes.WinDLL] = None
        self._bind()

    def _bind(self) -> None:
        """Load kernel32 / dbghelp. Silent on non-Windows."""
        if os.name != "nt":
            return
        try:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
        except OSError as exc:  # pragma: no cover — platform-specific
            logger.warning("MinidumpWriter: failed to load DLLs: %s", exc)

    @property
    def available(self) -> bool:
        """True if the Win32 APIs were bound successfully."""
        return self._kernel32 is not None and self._dbghelp is not None

    def dump_process(self, pid: int, output_path: Path) -> DumpResult:
        """Capture a minidump of the target PID.

        Args:
            pid: Target process identifier.
            output_path: File to create (will be overwritten).

        Returns:
            A DumpResult describing what happened.
        """
        if not self.available:
            return DumpResult(
                pid=pid,
                success=False,
                error="MinidumpWriter unavailable (non-Windows or DLL load failed)",
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._dump_impl(pid, output_path)
        except DumpFailed as exc:
            logger.warning("MiniDumpWriteDump failed for PID %d: %s", pid, exc)
            return DumpResult(pid=pid, success=False, error=str(exc))
        except OSError as exc:  # pragma: no cover — OS-dependent
            logger.warning("MiniDumpWriteDump OS error for PID %d: %s", pid, exc)
            return DumpResult(pid=pid, success=False, error=str(exc))

        size = output_path.stat().st_size if output_path.is_file() else 0
        logger.info("Minidump captured: pid=%d size=%d path=%s", pid, size, output_path)
        return DumpResult(pid=pid, success=True, path=output_path, size_bytes=size)

    # ------------------------------------------------------------------
    # Win32 plumbing
    # ------------------------------------------------------------------

    def _dump_impl(self, pid: int, output_path: Path) -> None:
        """Low-level: open target, create file, call MiniDumpWriteDump."""
        if self._kernel32 is None or self._dbghelp is None:
            raise DumpFailed("dbghelp/kernel32 not loaded")

        kernel32 = self._kernel32
        dbghelp = self._dbghelp

        # OpenProcess(access, inheritHandle=False, pid) -> HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE

        proc_handle = kernel32.OpenProcess(_PROCESS_ALL_ACCESS, False, pid)
        if not proc_handle:
            # Retry with the minimum rights MiniDumpWriteDump needs.
            proc_handle = kernel32.OpenProcess(
                _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid
            )
        if not proc_handle:
            err = ctypes.get_last_error()
            raise DumpFailed(f"OpenProcess failed (error {err})")

        try:
            # CreateFileW to get a HANDLE pointing at our output file.
            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,  # lpSecurityAttributes
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,  # hTemplateFile
            ]
            kernel32.CreateFileW.restype = wintypes.HANDLE

            file_handle = kernel32.CreateFileW(
                str(output_path),
                _GENERIC_WRITE,
                _FILE_SHARE_READ,
                None,
                _CREATE_ALWAYS,
                _FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if int(file_handle) == _INVALID_HANDLE_VALUE or file_handle == 0:
                err = ctypes.get_last_error()
                raise DumpFailed(f"CreateFile failed (error {err})")

            try:
                # MiniDumpWriteDump(hProcess, pid, hFile, dumpType,
                #                   exceptionParam, userStreamParam,
                #                   callbackParam) -> BOOL
                dbghelp.MiniDumpWriteDump.argtypes = [
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                ]
                dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL

                ok = dbghelp.MiniDumpWriteDump(
                    proc_handle,
                    pid,
                    file_handle,
                    self._dump_type,
                    None,
                    None,
                    None,
                )
                if not ok:
                    err = ctypes.get_last_error()
                    raise DumpFailed(f"MiniDumpWriteDump failed (error {err})")
            finally:
                kernel32.CloseHandle(file_handle)
        finally:
            kernel32.CloseHandle(proc_handle)
