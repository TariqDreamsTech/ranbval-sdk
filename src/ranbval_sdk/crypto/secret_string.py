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
- ``.use()`` returns a **real ``str``** so third-party SDKs can build headers with it. Under
  enforcement (the default) the naive extraction spellings raise — iteration, ``.encode()``,
  ``val[:]`` / indexing, and ``_buf``/``_pad`` reads (see ``set_enforcement``). But the plaintext
  genuinely exists in the string, so the **base** ``str`` methods still reach it —
  ``str.__str__(val)`` and ``str.__getitem__(val, ...)`` cannot be blocked (the ``str`` type is
  immutable) and ``object.__getattribute__(s, "_b")`` reads the real slot. This is bar-raising,
  not absolute; anything the SDK can read to build a request, determined code can read too.
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
        # Under enforcement, str()/print()/'%s' raise instead of masking — a loud failure so an
        # accidental (or deliberate) str-dump is caught. With enforcement off, it masks as before.
        # Honest limit: the *base* str.__str__(self) call skips this method entirely and returns
        # the real value — the str type is immutable, so that path cannot be intercepted.
        if _enforce:
            _raise_extraction("str")
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        # repr stays masked even under enforcement: error reporters (Sentry) and debuggers repr()
        # locals, and raising there would break error reporting itself.
        return "SecretString(***)"

    def __format__(self, spec: str) -> str:
        # Python's str.__format__ calls str(self) internally, hitting __str__ and returning
        # "[ranbval:secret]" — which breaks SDK f-string header construction. We reconstruct the
        # real value via the *base* str.__getitem__ (NOT self[:], which now hits our blocking
        # __getitem__), so f"Bearer {key}" builds the right Authorization header while external
        # slicing stays blocked. print(x) (which calls __str__ directly) remains masked.
        return format(str.__getitem__(self, slice(None)), spec)

    def __getitem__(self, key):
        # Slicing / indexing a revealed value (``val[:]``, ``val[0]``, ``val[1:5]``) reads the
        # plaintext out character by character — an extraction path. Reported, and (under
        # enforcement, the default) BLOCKED. The SDK's own f-string path uses the base
        # str.__getitem__ (see __format__), so legitimate header building is unaffected.
        # Honest limit: ``str.__getitem__(val, ...)`` on the base class still bypasses this.
        _guard_reveal("slice")
        return str.__getitem__(self, key)

    def __iter__(self):
        # Character-by-character iteration is the signature of an in-memory extraction
        # (``''.join(ch for ch in key.use())``, ``list(key.use())``, a comprehension) — a
        # legitimate SDK never iterates an API key. Reported to the access monitor, and (in
        # enforcement mode, the default) BLOCKED with RanbvalSecurityError so the theft fails
        # loudly. f-strings hit __format__ (which slices, not iterates), so no false alarm.
        _guard_reveal("iteration")
        return super().__iter__()

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        # ``val.encode()`` turns the secret into raw bytes — an extraction path (and how
        # ``bcrypt.hashpw`` etc. take it). Reported, and (in enforcement mode, the default)
        # BLOCKED. Note: some signing SDKs (AWS SigV4/HMAC) and DB drivers encode the credential
        # legitimately — if one trips this, call set_enforcement(False). (OpenAI-style header
        # building hits __format__ on a plain str, not this method, so it stays quiet.)
        _guard_reveal("encode")
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


# ── Enforcement (strict by default) ───────────────────────────────────────────
# When enforcement is on, a detected extraction (iteration / encode / slice / buffer read) is
# not merely reported — it raises ``RanbvalSecurityError`` so the offending code fails loudly
# instead of silently walking off with the plaintext. Honest limit: this stops the *naive*
# vectors; the base ``str`` methods (``str.__str__(val)``, ``str.__getitem__(val, ...)``) and the
# real slot ``object.__getattribute__(s, "_b")`` still bypass it in-process and cannot be blocked.
# Only ``[proxy]`` secrets are absolute. Turn off with ``set_enforcement(False)``.
_enforce: bool = True

_EXTRACTION_MESSAGE = {
    "iteration": (
        "Ranbval: character-by-character iteration of a secret is blocked — this is how "
        "in-memory extraction (''.join(c for c in key.use())) works. Pass the value straight "
        "to your SDK/HTTP client instead. If a legitimate library needs to iterate it, call "
        "set_enforcement(False); for absolute safety use a [proxy] secret."
    ),
    "encode": (
        "Ranbval: encoding a secret to bytes is blocked (an extraction path). Pass key.use() "
        "directly to the client that needs it. If a legitimate signer/driver must encode it "
        "(e.g. AWS SigV4, a DB driver), call set_enforcement(False); a [proxy] secret avoids "
        "the plaintext entirely."
    ),
    "slice": (
        "Ranbval: slicing/indexing a secret (val[:], val[0]) is blocked — it reads the plaintext "
        "out character by character. Pass key.use() straight to your client; f-strings still work. "
        "(set_enforcement(False) to disable; a [proxy] secret is the only absolute guarantee.)"
    ),
    "str": (
        "Ranbval: str()/print()/'%s' of a secret is blocked under enforcement (it is masked when "
        "enforcement is off). Pass key.use() straight to your client; f-strings build headers fine. "
        "Note: the base str.__str__(val) call CANNOT be intercepted (the str type is immutable) — "
        "only a [proxy] secret keeps the value off the client entirely. (set_enforcement(False) to disable.)"
    ),
    "buffer_read": (
        "Ranbval: reading a secret's internal buffer (_buf/_pad) is blocked — no legitimate "
        "caller touches these. Use key.use() at the point of use. (set_enforcement(False) to "
        "disable; a [proxy] secret is the only absolute guarantee.)"
    ),
}


def set_enforcement(enabled: bool) -> None:
    """Turn extraction enforcement on/off process-wide (default: on).

    On  → a detected extraction (iteration / encode / raw buffer read) raises
          :class:`RanbvalSecurityError`.
    Off → the extraction is only reported to the access monitor (detect + notify), and the
          real value is returned — legacy behaviour, for when a legitimate library trips it.
    """
    global _enforce
    _enforce = bool(enabled)


def is_enforced() -> bool:
    """True when extraction attempts raise (strict mode). See :func:`set_enforcement`."""
    return _enforce


def _guard_reveal(method: str) -> None:
    """Report the reveal-side signal, then (in enforcement mode) raise to stop the extraction.

    The notify runs first so the Live Monitor still records the attempt before the caller
    crashes; the raise is what converts silent theft into a loud, alerting failure.
    """
    _notify_reveal(method)
    if _enforce:
        _raise_extraction(method)


def _raise_extraction(method: str) -> None:
    """Raise the extraction error (no notify). Used by paths — like ``str()`` — that are masked
    (and frequent) when enforcement is off, so we must not flood the monitor with events."""
    from ranbval_sdk.exceptions import RanbvalSecurityError

    raise RanbvalSecurityError(
        _EXTRACTION_MESSAGE.get(method, f"Ranbval: blocked secret extraction via {method}."),
        code="secret_extraction_blocked",
        method=method,
    )


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

    The plaintext is never stored as-is: the real bytes live in the private slots ``_b`` (=
    ``plaintext XOR _p``) and ``_p`` (the pad), so even reading one slot yields only garbage.

    ``_buf`` and ``_pad`` are **honeypot properties**: any read of them — including the
    ``object.__getattribute__(s, "_buf")`` form that used to bypass the class — fires the
    reveal guard and (under enforcement) raises. This closes the known buffer-read PoC.

    **Honest limit.** The real slots ``_b`` / ``_p`` still exist and can be read with
    ``object.__getattribute__(s, "_b")`` by anyone who reads this (open-source) file — it is
    bar-raising against naive/automated extraction, not an absolute guarantee. The only value
    that never exists in the client process is a ``[proxy]`` secret.
    """

    __slots__ = ("_b", "_p", "_label", "_wiped")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("SecretString cannot be subclassed")

    def __init__(self, value: str, label: str = "secret") -> None:
        raw = value.encode("utf-8")
        pad = bytearray(os.urandom(len(raw))) if raw else bytearray()
        buf = bytearray(b ^ p for b, p in zip(raw, pad, strict=True))  # plaintext XOR pad
        _try_mlock(buf)  # pin to RAM — no swap to disk
        _try_mlock(pad)
        object.__setattr__(self, "_b", buf)
        object.__setattr__(self, "_p", pad)
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_wiped", False)

    # ── Buffer honeypots ───────────────────────────────────────────────────
    # Reading ``s._buf`` / ``s._pad`` is a reveal-gate / monitor bypass — a normal caller never
    # touches these. Exposing them as *properties* (data descriptors) means the guard fires even
    # for ``object.__getattribute__(s, "_buf")``, which the old __slots__ layout let through.
    # The SDK's own internals read the real slots ``_b`` / ``_p`` directly, so they don't trip it.

    @property
    def _buf(self) -> bytearray:
        _guard_reveal("buffer_read")
        return object.__getattribute__(self, "_b")

    @property
    def _pad(self) -> bytearray:
        _guard_reveal("buffer_read")
        return object.__getattribute__(self, "_p")

    # ── Memory wipe ────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Zero the secret bytes in memory and unpin from RAM. After this, use() raises RuntimeError."""
        for name in ("_b", "_p"):
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
        # Under enforcement, str()/print() of the sealed wrapper raises (loud); otherwise masks.
        if _enforce:
            _raise_extraction("str")
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
                    object.__getattribute__(self, "_b"),
                    object.__getattribute__(self, "_p"),
                ),
                _reconstruct(
                    object.__getattribute__(other, "_b"),
                    object.__getattribute__(other, "_p"),
                ),
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash(
            _reconstruct(
                object.__getattribute__(self, "_b"),
                object.__getattribute__(self, "_p"),
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
            object.__getattribute__(self, "_b"),
            object.__getattribute__(self, "_p"),
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
        return len(object.__getattribute__(self, "_b"))

    @property
    def label(self) -> str:
        """Optional label set at decrypt time (e.g. env var name)."""
        return object.__getattribute__(self, "_label")
