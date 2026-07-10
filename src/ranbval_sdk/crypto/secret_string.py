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

This module is intentionally just the sealed value type. Its concerns live in siblings:
:mod:`ranbval_sdk.crypto.memory` (mlock), :mod:`ranbval_sdk.crypto.enforcement` (guards +
reveal notifier), and :mod:`ranbval_sdk.crypto.output_guards` (opt-in print patching).
"""

from __future__ import annotations

import hmac
import os

from ranbval_sdk.crypto import enforcement, memory


class _ProtectedStr(str):
    """
    str subclass returned by SecretString.use().

    IS a real str so third-party SDKs (openai, anthropic, httpx, etc.) can use it in string
    operations and f-string header construction without any changes. All *display* paths are
    blocked so the value cannot be printed, logged, or repr'd accidentally::

        print(secret.use())        →  [ranbval:secret]  (or raises under enforcement)
        repr(secret.use())         →  SecretString(***)

    SDK-internal usage still works: ``f"Bearer {x}"`` and str concat use the real underlying str
    value. The naive extraction spellings (iterate / encode / slice / str) are guarded — see
    :mod:`ranbval_sdk.crypto.enforcement`.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> _ProtectedStr:
        return str.__new__(cls, value)

    def __str__(self) -> str:
        # Under enforcement, str()/print()/'%s' raise instead of masking — a loud failure so an
        # accidental (or deliberate) str-dump is caught. With enforcement off, it masks as before.
        # Honest limit: the *base* str.__str__(self) call skips this method entirely and returns
        # the real value — the str type is immutable, so that path cannot be intercepted.
        if enforcement.is_enforced():
            enforcement.raise_extraction("str")
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        # repr stays masked even under enforcement: error reporters (Sentry) and debuggers repr()
        # locals, and raising there would break error reporting itself.
        return "SecretString(***)"

    def __format__(self, spec: str) -> str:
        # str.__format__ calls str(self) internally, hitting __str__ — which would mask/raise and
        # break SDK f-string headers. Reconstruct via the *base* str.__getitem__ (NOT self[:],
        # which hits our blocking __getitem__), so f"Bearer {key}" works while external slicing
        # stays blocked. print(x) (which calls __str__ directly) remains masked.
        return format(str.__getitem__(self, slice(None)), spec)

    def __getitem__(self, key):
        # Slicing / indexing (``val[:]``, ``val[0]``) reads the plaintext out character by
        # character — an extraction path. Guarded (raises under enforcement). The SDK's own
        # f-string path uses the base str.__getitem__ (see __format__), so headers are unaffected.
        # Honest limit: ``str.__getitem__(val, ...)`` on the base class still bypasses this.
        enforcement.guard_reveal("slice")
        return str.__getitem__(self, key)

    def __iter__(self):
        # Character-by-character iteration is the signature of an in-memory extraction
        # (``''.join(ch for ch in key.use())``, ``list(...)``, a comprehension) — a legitimate SDK
        # never iterates an API key. Guarded. f-strings hit __format__ (slices), so no false alarm.
        enforcement.guard_reveal("iteration")
        return super().__iter__()

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        # ``val.encode()`` turns the secret into raw bytes — an extraction path. Guarded. Some
        # signers/drivers (AWS SigV4, some DB drivers) encode the credential legitimately — if one
        # trips this, call set_enforcement(False). (Header building hits __format__, not this.)
        enforcement.guard_reveal("encode")
        return super().encode(encoding, errors)

    # Serialization is a real accidental-leak path: error reporters (Sentry) pickle locals,
    # celery/multiprocessing pickle task args, disk/redis caches pickle values. Refuse it so the
    # plaintext can never ride out that way. copy() is allowed (str is immutable → self).
    def __copy__(self) -> _ProtectedStr:
        return self

    def __deepcopy__(self, memo: object) -> _ProtectedStr:
        return self

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("Ranbval secret cannot be pickled (it would expose the plaintext).")


def _reconstruct(buf: bytearray, pad: bytearray) -> bytes:
    """XOR-unmask the stored buffer back to plaintext bytes. Module-level (not a method) so a
    caller cannot reveal a secret via ``s.<method>()`` — the SDK reads the slots with
    ``object.__getattribute__`` and calls this internally."""
    return bytes(b ^ p for b, p in zip(buf, pad, strict=True))


# Set by :mod:`ranbval_sdk.config.reveal`. Called with the secret's label inside ``.use()``; it
# raises if that secret is restricted to a reveal scope and we are not inside one.
_reveal_gate: object = None


def set_reveal_gate(fn: object) -> None:
    """Register (or clear with ``None``) the reveal-scope gate ``fn(label)`` used by ``.use()``."""
    global _reveal_gate
    _reveal_gate = fn


class SecretString:
    """Holds a decrypted secret in memory, XOR-masked with a per-instance random pad.

    The plaintext is never stored as-is: the real bytes live in the private slots ``_b`` (=
    ``plaintext XOR _p``) and ``_p`` (the pad), so even reading one slot yields only garbage.

    ``_buf`` and ``_pad`` are **honeypot properties**: any read of them — including the
    ``object.__getattribute__(s, "_buf")`` form that used to bypass the class — fires the reveal
    guard and (under enforcement) raises. This closes the known buffer-read PoC.

    **Honest limit.** The real slots ``_b`` / ``_p`` still exist and can be read with
    ``object.__getattribute__(s, "_b")`` by anyone who reads this (open-source) file — it is
    bar-raising against naive/automated extraction, not an absolute guarantee. The only value
    that never exists in the client process is a ``PROXY_`` secret.
    """

    __slots__ = ("_b", "_p", "_label", "_wiped")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("SecretString cannot be subclassed")

    def __init__(self, value: str, label: str = "secret") -> None:
        raw = value.encode("utf-8")
        pad = bytearray(os.urandom(len(raw))) if raw else bytearray()
        buf = bytearray(b ^ p for b, p in zip(raw, pad, strict=True))  # plaintext XOR pad
        memory.try_mlock(buf)  # pin to RAM — no swap to disk
        memory.try_mlock(pad)
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
        enforcement.guard_reveal("buffer_read")
        return object.__getattribute__(self, "_b")

    @property
    def _pad(self) -> bytearray:
        enforcement.guard_reveal("buffer_read")
        return object.__getattribute__(self, "_p")

    # ── Memory wipe ────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Zero the secret bytes in memory and unpin from RAM. After this, use() raises RuntimeError."""
        for name in ("_b", "_p"):
            b = object.__getattribute__(self, name)
            memory.try_munlock(b)  # unpin before zeroing
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
        if enforcement.is_enforced():
            enforcement.raise_extraction("str")
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        return "SecretString(***)"

    def __format__(self, _format_spec: str) -> str:
        return "[ranbval:secret]"

    def __bytes__(self) -> bytes:
        return b"[ranbval:secret]"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretString):
            if object.__getattribute__(self, "_wiped") or object.__getattribute__(other, "_wiped"):
                return False
            # Deobfuscate both (each has its own pad) and compare in constant time. Read the slots
            # via object.__getattribute__ so we don't trip our own buffer-read guard.
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

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("SecretString is immutable")

    # Refuse serialization and duplication. A slotted object would otherwise pickle its bytes
    # straight into a cache/queue/error report, and a deepcopy would scatter extra plaintext
    # copies through memory. Both are blocked.
    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("SecretString cannot be pickled (it would expose the secret).")

    def __copy__(self) -> SecretString:
        raise TypeError("SecretString cannot be copied (it would duplicate the secret).")

    def __deepcopy__(self, memo: object) -> SecretString:
        raise TypeError("SecretString cannot be deep-copied (it would duplicate the secret).")

    # ── Only explicit access point ─────────────────────────────────────────

    def use(self) -> _ProtectedStr:
        """
        Return the secret value for use in API calls, headers, etc.

        Returns a _ProtectedStr — a str subclass that works identically to a plain str inside any
        SDK or HTTP client, but cannot be printed, repr'd, or accidentally logged::

            client = openai.OpenAI(api_key=secret.use())  # correct
            print(secret.use())                           # → [ranbval:secret] (or raises)

        Raises RuntimeError if the secret has been wiped or tampered with. Every call is recorded
        in the audit log (label + caller, no secret value).
        """
        if type(self).use is not SecretString.use:
            raise RuntimeError("SecretString.use() has been tampered with")
        if object.__getattribute__(self, "_wiped"):
            raise RuntimeError("SecretString has been wiped and cannot be used again")
        label = object.__getattribute__(self, "_label")
        # Reveal gate: if this secret is restricted to explicit reveal scopes, refuse to produce
        # the plaintext outside one (allow .use() at exactly one approved line, block elsewhere).
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
