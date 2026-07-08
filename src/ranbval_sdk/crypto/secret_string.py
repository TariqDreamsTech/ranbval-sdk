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

import builtins
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
        elif sys.platform == "darwin":
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


class _ProtectedStr(str):
    """
    str subclass returned by SecretString.use().

    IS a real str so third-party SDKs (openai, anthropic, httpx, etc.) can
    use it in string operations and f-string header construction without any
    changes. All *display* paths are blocked so the value cannot be printed,
    logged, or repr'd accidentally:

        print(secret.use())        →  [ranbval:secret]
        repr(secret.use())         →  SecretString(***)
        x = secret.use()
        print(x)                   →  [ranbval:secret]
        logging.info(x)            →  [ranbval:secret]

    SDK internal usage still works: f"Bearer {x}" and str concat use the real
    underlying str value. print(f"{x}") would also expose it — but that requires
    deliberate bypassing, unlike print(x) which is the accidental leak this guards.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> _ProtectedStr:
        return str.__new__(cls, value)

    def __str__(self) -> str:
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        return "SecretString(***)"

    def __format__(self, spec: str) -> str:
        # Python's str.__format__ calls str(self) internally, hitting __str__ and
        # returning "[ranbval:secret]" — which breaks SDK f-string header construction.
        # self[:] slices the underlying str buffer, returning a plain str with the
        # real value without going through __str__. format() on that plain str works
        # correctly, so f"Bearer {key}" in SDK code builds the right Authorization header.
        # print(x) (which calls __str__ directly) remains masked.
        return format(self[:], spec)


# ── Output guards ─────────────────────────────────────────────────────────────

_GUARD_INSTALLED = False
_orig_print = builtins.print
_orig_stdout_write: object = None

_ERR = (
    "Ranbval: cannot output a protected secret. "
    "Pass it directly to the SDK — e.g. OpenAI(api_key=key.use())"
)


def _guarded_print(*args: object, **kwargs: object) -> None:
    # Guard the accidental leak that actually happens in practice: print(key.use())
    # or print(x) where x = key.use(). The value is masked by __str__ regardless; this
    # turns the mistake into a loud PermissionError instead of a silent "[ranbval:secret]".
    for arg in args:
        if isinstance(arg, _ProtectedStr):
            raise PermissionError(_ERR)
    _orig_print(*args, **kwargs)


def _make_guarded_write(original_write):
    def _guarded_write(s: str) -> int:
        if isinstance(s, _ProtectedStr):
            raise PermissionError(_ERR)
        return original_write(s)

    return _guarded_write


def install_output_guards() -> None:
    """
    Patch builtins.print and sys.stdout.write so that passing a _ProtectedStr
    (the value returned by SecretString.use()) directly to an output function
    raises PermissionError instead of masking the plaintext.

    **Opt-in.** Patching global builtins is invasive and can surprise other libraries,
    test capture, and REPLs, so ``load_ranbval()`` no longer installs these guards
    automatically — call ``load_ranbval(guard_stdout=True)`` (or this function directly)
    when you want them. ``SecretString``/``_ProtectedStr`` already mask themselves via
    ``__str__``/``__repr__`` without any global patching. Safe to call multiple times.
    """
    global _GUARD_INSTALLED, _orig_stdout_write
    if _GUARD_INSTALLED:
        return
    builtins.print = _guarded_print
    _orig_stdout_write = sys.stdout.write
    sys.stdout.write = _make_guarded_write(sys.stdout.write)
    _GUARD_INSTALLED = True


class SecretString:
    """Holds a decrypted secret in a mutable bytearray; zeroes memory on wipe/context-exit."""

    __slots__ = ("_buf", "_label", "_wiped")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("SecretString cannot be subclassed")

    def __init__(self, value: str, label: str = "secret") -> None:
        buf = bytearray(value.encode("utf-8"))
        _try_mlock(buf)  # pin to RAM — no swap to disk
        object.__setattr__(self, "_buf", buf)
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_wiped", False)

    # ── Memory wipe ────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Zero the secret bytes in memory and unpin from RAM. After this, use() raises RuntimeError."""
        buf = object.__getattribute__(self, "_buf")
        _try_munlock(buf)  # unpin before zeroing
        buf[:] = b"\x00" * len(buf)
        object.__setattr__(self, "_wiped", True)

    # ── Context manager — wipes automatically on block exit ───────────────

    def __enter__(self) -> _ProtectedStr:
        return self.use()

    def __exit__(self, *_: object) -> None:
        self.wipe()

    # ── All display paths are blocked ──────────────────────────────────────

    def __str__(self) -> str:
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        return "SecretString(***)"

    def __format__(self, _format_spec: str) -> str:
        return "[ranbval:secret]"

    def __bytes__(self) -> bytes:
        return b"[ranbval:secret]"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretString):
            if object.__getattribute__(self, "_wiped") or object.__getattribute__(
                other, "_wiped"
            ):
                return False
            return object.__getattribute__(self, "_buf") == object.__getattribute__(
                other, "_buf"
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash(bytes(object.__getattribute__(self, "_buf")))

    # Block attribute setting from outside
    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("SecretString is immutable")

    # ── Only explicit access point ─────────────────────────────────────────

    def use(self) -> _ProtectedStr:
        """
        Return the secret value for use in API calls, headers, etc.

        Returns a _ProtectedStr — a str subclass that works identically to a
        plain str inside any SDK or HTTP client, but cannot be printed, repr'd,
        or accidentally logged:

            client = openai.OpenAI(api_key=secret.use())  # correct
            print(secret.use())                           # → [ranbval:secret]
            x = secret.use(); print(x)                   # → [ranbval:secret]

        Raises RuntimeError if the secret has been wiped or tampered with.
        Every call is recorded in the audit log (label + caller, no secret value).
        """
        if type(self).use is not SecretString.use:
            raise RuntimeError("SecretString.use() has been tampered with")
        if object.__getattribute__(self, "_wiped"):
            raise RuntimeError("SecretString has been wiped and cannot be used again")
        from ranbval_sdk.crypto.audit import record_access

        record_access(object.__getattribute__(self, "_label"))
        return _ProtectedStr(object.__getattribute__(self, "_buf").decode("utf-8"))

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
