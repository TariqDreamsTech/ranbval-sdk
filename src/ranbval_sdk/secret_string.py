"""
SecretString — a string wrapper that never exposes its value via print/str/repr/format/log.

The decrypted secret is held in memory but blocked from accidental exposure:
    print(secret)       →  [ranbval:secret]
    str(secret)         →  [ranbval:secret]
    repr(secret)        →  SecretString(***)
    f"{secret}"         →  [ranbval:secret]
    logging.info(secret)→  [ranbval:secret]
    json.dumps(secret)  →  TypeError (not serializable — intentional)

To actually use the value (pass to an API, header, etc.):
    secret.use()        →  returns the raw str (only call point)
"""

from __future__ import annotations


class SecretString:
    """Holds a decrypted secret and refuses to expose it via any display path."""

    __slots__ = ("_value", "_label")

    def __init__(self, value: str, label: str = "secret") -> None:
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_label", label)

    # ── All display paths are blocked ──────────────────────────────────────

    def __str__(self) -> str:
        return "[ranbval:secret]"

    def __repr__(self) -> str:
        return "SecretString(***)"

    def __format__(self, format_spec: str) -> str:
        return "[ranbval:secret]"

    def __bytes__(self) -> bytes:
        return b"[ranbval:secret]"

    # Prevent accidental == comparison that leaks value
    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretString):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    # Block attribute setting — immutable
    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SecretString is immutable")

    # ── Only explicit access point ─────────────────────────────────────────

    def use(self) -> str:
        """
        Return the raw secret value for use in API calls, headers, etc.
        This is the only way to access the plaintext — call deliberately.

        Example:
            client = openai.OpenAI(api_key=secret.use())
        """
        return object.__getattribute__(self, "_value")

    def __len__(self) -> int:
        """Length of the secret (safe — does not reveal content)."""
        return len(object.__getattribute__(self, "_value"))

    @property
    def label(self) -> str:
        """Optional label set at decrypt time (e.g. env var name)."""
        return object.__getattribute__(self, "_label")
