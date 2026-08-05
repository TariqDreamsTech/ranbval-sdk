"""Resolve the control-plane host, and refuse to let the environment redirect it.

Every server-side control in this product — the repo allowlist above all — is only as trustworthy
as the server being asked. Reading the host from ``RANBVAL_HOST`` without constraint meant that
anyone who could set an environment variable could point the SDK at a server of their own, have it
answer ``{"enforce_allowlist": false}``, and walk past the allowlist. Demonstrated, not theorised:
a nine-line local HTTP server was enough.

That is the same weakness this project has already removed twice — a security control that an
attacker able to set the environment can switch off for free. ``RANBVAL_ALLOW_COMMITTABLE_SECRET``
and the guard opt-outs are different in kind: they weaken a *local* tripwire. This one silently
replaces the authority the tripwires defer to.

So the rule here is:

- **No configuration at all → the official host.** The common case needs nothing.
- **A host passed in code** (``load_ranbval(host=...)``, ``proxy_request(host_url=...)``) → honoured.
  Code is the same trust boundary as the SDK itself; someone who can edit it has already won.
- **``RANBVAL_HOST`` pointing somewhere else → refused**, unless the *code* has said that is
  allowed by calling :func:`allow_host_override`. A self-hosted deployment writes that line once;
  an attacker holding only the environment cannot.
"""

from __future__ import annotations

import os

from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.exceptions import RanbvalConfigError

#: Set only from code, never from the environment — that asymmetry is the whole point.
_override_allowed: bool = False


def allow_host_override(allowed: bool = True) -> None:
    """Permit ``RANBVAL_HOST`` to name a host other than the official one.

    For self-hosted or on-premise control planes. Call it in your application code, before the
    first decrypt::

        from ranbval_sdk import allow_host_override
        allow_host_override()          # we run our own control plane

    Deliberately not an environment variable or a ``.ranbval`` key: both are settable by anyone
    who can influence the process, and this is the switch that decides which server gets to say
    whether a decrypt is allowed.
    """
    global _override_allowed
    _override_allowed = bool(allowed)


def is_host_override_allowed() -> bool:
    """True when the code has opted in to a non-default ``RANBVAL_HOST``."""
    return _override_allowed


def _normalise(host: str) -> str:
    return host.strip().rstrip("/").lower()


def resolve_host(explicit: str | None = None) -> str:
    """Return the control-plane host to use, refusing an unapproved environment redirect.

    ``explicit`` is a host passed in code and is always honoured.
    """
    if explicit and explicit.strip():
        return explicit.strip().rstrip("/")

    env = (os.environ.get("RANBVAL_HOST") or "").strip()
    if not env:
        return DEFAULT_RANBVAL_HOST

    if _normalise(env) == _normalise(DEFAULT_RANBVAL_HOST) or _override_allowed:
        return env.rstrip("/")

    raise RanbvalConfigError(
        f"RANBVAL_HOST is set to {env!r}, which is not the Ranbval control plane "
        f"({DEFAULT_RANBVAL_HOST}). Refusing to use it.\n"
        "The host decides whether a decrypt is permitted — the repo allowlist is answered by "
        "whichever server is asked — so an environment variable must not be able to redirect it. "
        "If you genuinely run your own control plane, say so in code, once:\n"
        "    from ranbval_sdk import allow_host_override\n"
        "    allow_host_override()\n"
        "Code is a boundary an attacker holding only the environment cannot cross.",
        code="host_not_allowed",
    )
