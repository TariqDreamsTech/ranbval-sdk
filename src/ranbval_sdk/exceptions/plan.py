"""Plan-limit errors.

Raised when the control plane refuses a call because the project's plan is spent — not because
anything is broken. Kept separate from ProxyError so callers can tell "you have run out" apart from
"the proxy is down", and can back off or upgrade instead of retrying into a wall.

The limit itself is enforced server-side. The SDK runs on the customer's machine, so a check it
performs is a check it can remove; this type exists to make the server's answer legible, not to
police anything locally.
"""

from __future__ import annotations

from ranbval_sdk.exceptions.base import RanbvalError


class PlanLimitError(RanbvalError, RuntimeError):
    """The project's plan allowance is exhausted (HTTP 429/402 from Ranbval).

    Attributes:
        used:      how much of the allowance has been consumed
        limit:     the allowance for the current plan
        period:    the billing window, e.g. ``"2026-07"``
        plan:      the plan key, e.g. ``"free"``
        kind:      which allowance — ``"requests"``, ``"secrets"`` or ``"projects"``
    """

    default_code = "plan_limit_reached"

    def __init__(
        self,
        message: str,
        *,
        used: int | None = None,
        limit: int | None = None,
        period: str | None = None,
        plan: str | None = None,
        kind: str | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message, code=code or self.default_code)
        self.used = used
        self.limit = limit
        self.period = period
        self.plan = plan
        self.kind = kind
