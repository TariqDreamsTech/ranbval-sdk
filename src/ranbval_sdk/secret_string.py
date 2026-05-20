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


class SecretString:
    """Holds a decrypted secret in a mutable bytearray; zeroes memory on wipe/context-exit."""

    __slots__ = ("_buf", "_label", "_wiped")

    def __init__(self, value: str, label: str = "secret") -> None:
        object.__setattr__(self, "_buf", bytearray(value.encode("utf-8")))
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_wiped", False)

    # ── Memory wipe ────────────────────────────────────────────────────────

    def wipe(self) -> None:
        """Zero the secret bytes in memory. After this, use() raises RuntimeError."""
        buf = object.__getattribute__(self, "_buf")
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
        Raises RuntimeError if the secret has already been wiped.

        Example:
            client = openai.OpenAI(api_key=secret.use())
        """
        if object.__getattribute__(self, "_wiped"):
            raise RuntimeError("SecretString has been wiped and cannot be used again")
        return object.__getattribute__(self, "_buf").decode("utf-8")

    def __len__(self) -> int:
        """Length of the secret in bytes (safe — does not reveal content)."""
        return len(object.__getattribute__(self, "_buf"))

    @property
    def label(self) -> str:
        """Optional label set at decrypt time (e.g. env var name)."""
        return object.__getattribute__(self, "_label")
