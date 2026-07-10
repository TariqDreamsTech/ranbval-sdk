"""Best-effort RAM pinning for secret buffers.

``mlock`` asks the OS not to swap a page to disk, so a decrypted secret is less likely to land
in swap or a core dump. This is **defence-in-depth, not a guarantee** — CPython still makes
immutable ``str``/``bytes`` copies this can't pin, and a process-memory reader has already won.
Failures are swallowed on purpose (unsupported platform, locked-memory ulimit, etc.).
"""

from __future__ import annotations

import contextlib
import ctypes
import sys


def _libc(buf: bytearray) -> tuple:
    """Return ``(cdll, addr, size)`` for the current platform, or ``(None, None, None)``."""
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    addr = ctypes.c_void_p(ctypes.addressof(c_buf))
    size = ctypes.c_size_t(len(buf))
    if sys.platform.startswith("linux"):
        return ctypes.CDLL("libc.so.6", use_errno=True), addr, size
    if sys.platform == "darwin":
        return ctypes.CDLL("libc.dylib", use_errno=True), addr, size
    return None, None, None


def try_mlock(buf: bytearray) -> bool:
    """Pin buffer pages in RAM so the OS cannot swap them to disk. Returns True on success."""
    if not buf:
        return False
    with contextlib.suppress(Exception):
        cdll, addr, size = _libc(buf)
        if cdll is not None:
            return cdll.mlock(addr, size) == 0
    return False


def try_munlock(buf: bytearray) -> None:
    """Unpin buffer pages after wipe (best-effort)."""
    if not buf:
        return
    with contextlib.suppress(Exception):
        cdll, addr, size = _libc(buf)
        if cdll is not None:
            cdll.munlock(addr, size)
