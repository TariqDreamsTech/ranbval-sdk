"""Exception hierarchy for the Ranbval SDK.

Every error the SDK raises derives from :class:`RanbvalError`, so callers can catch
the whole family with ``except RanbvalError``. Each specific error **also** subclasses
the built-in it historically replaced (``ValueError`` / ``KeyError`` / ``PermissionError``),
so existing ``except ValueError`` / ``except KeyError`` / ``except PermissionError`` code
keeps working unchanged.

    from ranbval_sdk import RanbvalError, RanbvalDecryptError

    try:
        key = decrypt_key("OPENAI_API_KEY")
    except RanbvalDecryptError as err:   # precise
        log.error("decrypt failed", code=err.code, **err.context)
    except RanbvalError:                 # anything from the SDK
        ...

Structured context
------------------
Every error carries an optional machine-readable ``code`` and a ``context`` dict, so
callers can branch/log/emit metrics without parsing the human message string::

    except RanbvalError as err:
        metrics.increment("ranbval.error", tags={"code": err.code})

Note on multiple inheritance: because these also subclass built-ins, a bare
``except ValueError`` will now also catch Ranbval decrypt/config errors. That is
intentional (drop-in compatibility) — catch :class:`RanbvalError` when you want only
the SDK's own errors.
"""

from __future__ import annotations

from typing import Any


class RanbvalError(Exception):
    """Base class for every error raised by the Ranbval SDK.

    Args:
        message: Human-readable, actionable description.
        code: Stable machine-readable slug for programmatic handling
            (e.g. ``"decrypt_failed"``, ``"repo_denied"``). Never changes wording-side.
        **context: Structured fields describing the failure (e.g. ``env_var=...``,
            ``origin=...``) — safe to log; never contains secret plaintext.
    """

    #: Default code used when a subclass does not pass one explicitly.
    default_code: str = "ranbval_error"

    def __init__(
        self, message: str = "", *, code: str | None = None, **context: Any
    ) -> None:
        super().__init__(message)
        self.code = code or self.default_code
        self.context: dict[str, Any] = context


class RanbvalDecryptError(RanbvalError, ValueError):
    """A vault token could not be decrypted (bad project secret, corrupt token, or expired)."""

    default_code = "decrypt_failed"


class MissingKeyError(RanbvalError, KeyError):
    """An expected environment variable or vault token is absent (raised by attribute/item access)."""

    default_code = "missing_key"

    def __str__(self) -> str:
        # ``KeyError.__str__`` wraps its argument in ``repr()`` (adds quotes), which
        # produces ugly messages like ``"'OPENAI_KEY is not set'"``. Bypass it so the
        # message reads naturally wherever ``str(err)`` is used.
        return self.args[0] if self.args else ""


class RanbvalConfigError(RanbvalError, ValueError):
    """A value is missing or misconfigured: env var not set, no project secret, or wrong project prefix."""

    default_code = "config_error"


class RepoNotAllowedError(RanbvalError, PermissionError):
    """The current git remote is not in the project's allowlist, so decryption is refused."""

    default_code = "repo_denied"


class RepoPolicyError(RanbvalError, PermissionError):
    """The repository policy could not be loaded or verified before decryption."""

    default_code = "repo_policy_unavailable"


class ProxyError(RanbvalError, RuntimeError):
    """The Ranbval secure proxy rejected the request or could not be reached."""

    default_code = "proxy_error"


__all__ = [
    "RanbvalError",
    "RanbvalDecryptError",
    "MissingKeyError",
    "RanbvalConfigError",
    "RepoNotAllowedError",
    "RepoPolicyError",
    "ProxyError",
]
