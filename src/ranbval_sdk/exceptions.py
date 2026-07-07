"""Exception hierarchy for the Ranbval SDK.

Every error the SDK raises derives from :class:`RanbvalError`, so callers can catch
the whole family with ``except RanbvalError``. Each specific error **also** subclasses
the built-in it historically replaced (``ValueError`` / ``KeyError`` / ``PermissionError``),
so existing ``except ValueError`` / ``except KeyError`` / ``except PermissionError`` code
keeps working unchanged.

    from ranbval_sdk import RanbvalError, RanbvalDecryptError

    try:
        key = decrypt_key("OPENAI_API_KEY")
    except RanbvalDecryptError:      # precise
        ...
    except RanbvalError:             # anything from the SDK
        ...
"""

from __future__ import annotations


class RanbvalError(Exception):
    """Base class for every error raised by the Ranbval SDK."""


class RanbvalDecryptError(RanbvalError, ValueError):
    """A vault token could not be decrypted (bad project secret, corrupt token, or expired)."""


class MissingKeyError(RanbvalError, KeyError):
    """An expected environment variable or vault token is absent (raised by attribute/item access)."""


class RanbvalConfigError(RanbvalError, ValueError):
    """A value is missing or misconfigured: env var not set, no project secret, or wrong project prefix."""


class RepoNotAllowedError(RanbvalError, PermissionError):
    """The current git remote is not in the project's allowlist, so decryption is refused."""


class RepoPolicyError(RanbvalError, PermissionError):
    """The repository policy could not be loaded or verified before decryption."""


class ProxyError(RanbvalError, RuntimeError):
    """The Ranbval secure proxy rejected the request or could not be reached."""


__all__ = [
    "RanbvalError",
    "RanbvalDecryptError",
    "MissingKeyError",
    "RanbvalConfigError",
    "RepoNotAllowedError",
    "RepoPolicyError",
    "ProxyError",
]
