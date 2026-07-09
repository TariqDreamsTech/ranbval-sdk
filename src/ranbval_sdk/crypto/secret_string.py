"""SecretString — a wrapper that blocks the *accidental* exposure paths for a secret.

What it protects against (the mistakes that actually happen)::

    print(secret)          →  [ranbval:secret]
    str(secret)            →  [ranbval:secret]
    repr(secret)           →  SecretString(***)      # also what error reporters capture
    f"{secret}"            →  [ranbval:secret]
    "%s" % secret          →  [ranbval:secret]
    logging.info(secret)   →  [ranbval:secret]
    json.dumps(secret)     →  TypeError (intentional)
    pickle.dumps(secret)   →  TypeError (intentional — can't leak via cache/queue/Sentry)
    copy.deepcopy(secret)  →  TypeError (intentional — no silent plaintext duplicate)

Consuming the value::

    secret.use()           →  the real str, for passing straight into an SDK/HTTP client

    with decrypt_key("MY_KEY") as key:     # context manager wipes on block exit
        client = openai.OpenAI(api_key=key)

The one rule that keeps a secret unseen
---------------------------------------
**Call ``.use()`` only inline, at the exact point you hand the value to the SDK — never
store it in a variable and never print it.** If you follow that, the secret only ever exists
as a sealed ``SecretString`` in your code, and every display path above is masked.

Honest limits (a security library must not over-promise)
--------------------------------------------------------
- ``.use()`` returns a **real ``str``** so third-party SDKs can build headers with it. That
  means the plaintext genuinely exists in the string — ``secret.use()[:]`` or
  ``print(f"{secret.use()}")`` will reveal it. That is *deliberate* bypassing, not the
  accidental leak this guards; anything the SDK can read to build a request, code can read too.
- "Zeroing" and ``mlock`` are **best-effort defence-in-depth, not guarantees.** In a managed
  runtime (CPython) the interpreter and the SDK make immutable ``str``/``bytes`` copies of the
  value that this class cannot pin or wipe. An attacker who can read your process memory
  (ptrace/core-dump/debugger) has already won — that is out of scope for any Python SDK.
- The real protection this product gives is upstream: secrets never sit in plaintext in your
  repo, and the control plane enforces who may decrypt. RAM hardening is a minor extra layer.
"""

from __future__ import annotations

import builtins
import ctypes
import hmac
import os
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

    def __iter__(self):
        # Character-by-character iteration is the signature of an in-memory extraction
        # (``''.join(ch for ch in key.use())``, ``list(key.use())``, a comprehension) — a
        # legitimate SDK never iterates an API key. We do NOT block it (that would be
        # futile and breaks nothing legitimate); we REPORT it to the opt-in access monitor
        # and still yield the real characters, so honest use is unaffected but theft leaves
        # a trace. f-strings hit __format__ (which slices, not iterates), so no false alarm.
        _notify_reveal("iteration")
        return super().__iter__()

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        # ``val.encode()`` turns the secret into raw bytes — an extraction path (and how
        # ``bcrypt.hashpw`` etc. take it). Report it, then return the real bytes. Note: some
        # signing SDKs (AWS SigV4/HMAC) and DB drivers encode the credential legitimately, so
        # this signal can be a false positive; it never blocks. (OpenAI-style header building
        # hits __format__ on a plain str, not this method, so it stays quiet.)
        _notify_reveal("encode")
        return super().encode(encoding, errors)

    # Serialization is a real accidental-leak path: error reporters (Sentry) pickle locals,
    # celery/multiprocessing pickle task args, disk/redis caches pickle values. Refuse it so
    # the plaintext can never ride out that way. copy() is allowed (str is immutable → self).
    def __copy__(self) -> _ProtectedStr:
        return self

    def __deepcopy__(self, memo: object) -> _ProtectedStr:
        return self

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError(
            "Ranbval secret cannot be pickled (it would expose the plaintext)."
        )


# ── Reveal monitor hook ───────────────────────────────────────────────────────
# Set by the opt-in access monitor (:mod:`ranbval_sdk.telemetry.monitor`). Called
# with a method name (e.g. "iteration") when a revealed value is manipulated in a way
# that signals in-memory extraction. ``None`` (default) = zero overhead, never called.
_reveal_notifier: object = None


def set_reveal_notifier(fn: object) -> None:
    """Register (or clear with ``None``) a callback ``fn(method)`` for reveal-side signals."""
    global _reveal_notifier
    _reveal_notifier = fn


def _notify_reveal(method: str) -> None:
    """Fire the reveal-side signal (if a monitor is installed); never raises into the caller."""
    if _reveal_notifier is not None:
        try:
            _reveal_notifier(method)
        except Exception:
            pass


def _reconstruct(buf: bytearray, pad: bytearray) -> bytes:
    """XOR-unmask the stored buffer back to plaintext bytes. Module-level (not a method) so a
    caller cannot reveal a secret via ``s.<method>()`` — the SDK reads the slots with
    ``object.__getattribute__`` and calls this internally."""
    return bytes(b ^ p for b, p in zip(buf, pad, strict=True))


# Set by :mod:`ranbval_sdk.config.reveal`. Called with the secret's label inside ``.use()``;
# it raises if that secret is restricted to a reveal scope and we are not inside one.
_reveal_gate: object = None


def set_reveal_gate(fn: object) -> None:
    """Register (or clear with ``None``) the reveal-scope gate ``fn(label)`` used by ``.use()``."""
    global _reveal_gate
    _reveal_gate = fn


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
    """Holds a decrypted secret in memory, XOR-masked with a per-instance random pad.

    The plaintext is never stored as-is: ``_buf`` holds ``plaintext XOR _pad``, so reading the
    internal buffer directly (``object.__getattribute__(s, "_buf")``) yields only garbage. To
    reconstruct the value you must read *both* slots and know the scheme — which pushes any
    reader back through :meth:`use` (the gated, audited access point). This is bar-raising, not
    absolute (a determined insider can read both slots); it closes the naive one-slot bypass.
    """

    __slots__ = ("_buf", "_pad", "_label", "_wiped")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("SecretString cannot be subclassed")

    def __init__(self, value: str, label: str = "secret") -> None:
        raw = value.encode("utf-8")
        pad = bytearray(os.urandom(len(raw))) if raw else bytearray()
        buf = bytearray(b ^ p for b, p in zip(raw, pad, strict=True))  # plaintext XOR pad
        _try_mlock(buf)  # pin to RAM — no swap to disk
        _try_mlock(pad)
        object.__setattr__(self, "_buf", buf)
        object.__setattr__(self, "_pad", pad)
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_wiped", False)

    def __getattribute__(self, name: str):
        # Reading the masked buffer directly (``s._buf`` / ``s._pad``) is a reveal-gate /
        # monitor bypass — a normal caller never touches these. Report it so the Live Monitor
        # can raise a warning, then still return the value. NOTE: the SDK's own internals read
        # these via ``object.__getattribute__`` (which does NOT come through here), so this only
        # fires on *external* access; and an attacker using ``object.__getattribute__`` directly
        # bypasses this too — that path is unpreventable/undetectable in-process (documented).
        if name in ("_buf", "_pad"):
            _notify_reveal("buffer_read")
        return object.__getattribute__(self, name)

    # ── Memory wipe ────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Zero the secret bytes in memory and unpin from RAM. After this, use() raises RuntimeError."""
        for name in ("_buf", "_pad"):
            b = object.__getattribute__(self, name)
            _try_munlock(b)  # unpin before zeroing
            b[:] = b"\x00" * len(b)
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
            # Deobfuscate both (each has its own pad) and compare in constant time. Read the
            # slots via object.__getattribute__ so we don't trip our own buffer-read monitor.
            return hmac.compare_digest(
                _reconstruct(
                    object.__getattribute__(self, "_buf"),
                    object.__getattribute__(self, "_pad"),
                ),
                _reconstruct(
                    object.__getattribute__(other, "_buf"),
                    object.__getattribute__(other, "_pad"),
                ),
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash(
            _reconstruct(
                object.__getattribute__(self, "_buf"),
                object.__getattribute__(self, "_pad"),
            )
        )

    # Block attribute setting from outside
    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("SecretString is immutable")

    # Refuse serialization and duplication. A slotted object would otherwise pickle its
    # ``_buf`` (the plaintext bytes) straight into a cache/queue/error report, and a
    # deepcopy would scatter extra plaintext copies through memory. Both are blocked.
    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("SecretString cannot be pickled (it would expose the secret).")

    def __copy__(self) -> SecretString:
        raise TypeError(
            "SecretString cannot be copied (it would duplicate the secret)."
        )

    def __deepcopy__(self, memo: object) -> SecretString:
        raise TypeError(
            "SecretString cannot be deep-copied (it would duplicate the secret)."
        )

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
        label = object.__getattribute__(self, "_label")
        # Reveal gate: if this secret is restricted to explicit reveal scopes, refuse to
        # produce the plaintext outside one. Lets you allow .use() at exactly one approved
        # line (e.g. the DB-connect call) and block extraction from anywhere else.
        if _reveal_gate is not None:
            _reveal_gate(label)
        from ranbval_sdk.crypto.audit import record_access

        record_access(label)
        plaintext = _reconstruct(
            object.__getattribute__(self, "_buf"),
            object.__getattribute__(self, "_pad"),
        )
        return _ProtectedStr(plaintext.decode("utf-8"))

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
