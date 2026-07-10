"""The base error every Ranbval exception derives from — with a machine-readable ``code`` and a
structured ``context`` dict so callers can branch/log/emit metrics without parsing the message."""

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

    def __init__(self, message: str = "", *, code: str | None = None, **context: Any) -> None:
        super().__init__(message)
        self.code = code or self.default_code
        self.context: dict[str, Any] = context
