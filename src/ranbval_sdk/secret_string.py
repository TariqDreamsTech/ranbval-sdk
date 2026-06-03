"""
SecretString — a string wrapper that never exposes its value via print/str/repr/format/log.

The decrypted secret is held in a mutable bytearray so it can be genuinely zeroed
from memory after use. All display paths are blocked against accidental exposure:

    print(secret)        →  [ranbval:secret]
    str(secret)          →  [ranbval:secret]
    repr(secret)         →  SecretString(***)
    f"{secret}"          →  [ranbval:secret]
    logging.info(secret) →  [ranbval:secret]
    json.dumps(secret)   →  TypeError (not serializable — intentional)

Two ways to consume the value:

    # Direct access
    secret.use()         →  returns the raw str; secret remains valid

    # Context manager — zeroes memory automatically on block exit
    with decrypt_key("MY_KEY") as key:
        client = openai.OpenAI(api_key=key)
    # secret is wiped here; cannot be used again
"""

from __future__ import annotations

import ctypes
import sys


def _try_mlock(buf: bytearray) -> bool:
    """Pin buffer pages in RAM so the OS cannot swap them to disk."""
    if not buf:
        return False
    try:
        c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
        addr = ctypes.c_void_p(ctypes.addressof(c_buf))
        size = ctypes.c_size_t(len(buf))
        if sys.platform.startswith("linux"):
            return ctypes.CDLL("libc.so.6", use_errno=True).mlock(addr, size) == 0
        if sys.platform == "darwin":
            return ctypes.CDLL("libc.dylib", use_errno=True).mlock(addr, size) == 0
    except Exception:
        pass
    return False


def _try_munlock(buf: bytearray) -> None:
    """Unpin buffer pages after wipe."""
    if not buf:
        return
    try:
        c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
        addr = ctypes.c_void_p(ctypes.addressof(c_buf))
        size = ctypes.c_size_t(len(buf))
        if sys.platform.startswith("linux"):
            ctypes.CDLL("libc.so.6", use_errno=True).munlock(addr, size)
        elif sys.platform == "darwin":
            ctypes.CDLL("libc.dylib", use_errno=True).munlock(addr, size)
    except Exception:
        pass


class SecretString:
    """Holds a decrypted secret in a mutable bytearray; zeroes memory on wipe/context-exit."""

    __slots__ = ("_buf", "_label", "_wiped")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("SecretString cannot be subclassed")

    def __init__(self, value: str, label: str = "secret") -> None:
        buf = bytearray(value.encode("utf-8"))
        _try_mlock(buf)   # pin to RAM — no swap to disk
        object.__setattr__(self, "_buf", buf)
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_wiped", False)

    # ── Memory wipe ────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Zero the secret bytes in memory and unpin from RAM. After this, use() raises RuntimeError."""
        buf = object.__getattribute__(self, "_buf")
        _try_munlock(buf)         # unpin before zeroing
        buf[:] = b"\x00" * len(buf)
        object.__setattr__(self, "_wiped", True)

    # ── Context manager — wipes automatically on block exit ───────────────

    def __enter__(self) -> str:
        return self.use()

    def __exit__(self, *_: object) -> None:
        self.wipe()

    # ── All display paths are blocked ──────────────────────────────────────

    def __str__(self) -> str:
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        return "SecretString(***)"

    def __format__(self, format_spec: str) -> str:
        return "[ranbval:secret]"

    def __bytes__(self) -> bytes:
        return b"[ranbval:secret]"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretString):
            if object.__getattribute__(self, "_wiped") or object.__getattribute__(other, "_wiped"):
                return False
            return object.__getattribute__(self, "_buf") == object.__getattribute__(other, "_buf")
        return NotImplemented

    def __hash__(self) -> int:
        return hash(bytes(object.__getattribute__(self, "_buf")))

    # Block attribute setting from outside
    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretString is immutable")

    # ── Only explicit access point ─────────────────────────────────────────

    def use(self) -> str:
        """
        Return the raw secret value for use in API calls, headers, etc.
        Raises RuntimeError if the secret has already been wiped or tampered with.
        Every call is recorded in the audit log (label + caller location, no secret value).

        Example:
            client = openai.OpenAI(api_key=secret.use())
        """
        if type(self).use is not SecretString.use:
            raise RuntimeError("SecretString.use() has been tampered with")
        if object.__getattribute__(self, "_wiped"):
            raise RuntimeError("SecretString has been wiped and cannot be used again")
        from ranbval_sdk.audit import record_access
        record_access(object.__getattribute__(self, "_label"))
        return object.__getattribute__(self, "_buf").decode("utf-8")

    def __del__(self) -> None:
        try:
            if not object.__getattribute__(self, "_wiped"):
                self.wipe()
        except Exception:
            pass

    def __len__(self) -> int:
        """Length of the secret in bytes (safe — does not reveal content)."""
        return len(object.__getattribute__(self, "_buf"))

    @property
    def label(self) -> str:
        """Optional label set at decrypt time (e.g. env var name)."""
        return object.__getattribute__(self, "_label")
