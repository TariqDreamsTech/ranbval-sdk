"""Fetch a project's env-set from the Ranbval control plane over HTTPS.

Owner auth is the project secret itself (``ranbval-proj-…``) — the same secret that decrypts the
tokens. The response carries the env vars exactly as they would sit in a ``.ranbval`` file:
``SECRET_``/``PROXY_`` values are still encrypted ``ranbval.*`` tokens, ``PUBLIC_`` values are
plaintext. Nothing here decrypts anything.
"""

from __future__ import annotations

import json
import os
import urllib.request

from ranbval_sdk._internal import transport as _transport
from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.exceptions import RanbvalConfigError


def _host(host: str | None) -> str:
    return (host or os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).rstrip("/")


def _credential(project_secret: str | None, api_key: str | None) -> dict:
    """Owner uses project_secret; developer uses api_key. Exactly one is required."""
    if project_secret and project_secret.strip():
        return {"project_secret": project_secret.strip()}
    if api_key and api_key.strip():
        return {"api_key": api_key.strip()}
    raise RanbvalConfigError(
        "remote needs a project_secret (owner) or api_key (developer).",
        code="remote_no_secret",
    )


def _post(url: str, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with _transport.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = "Invalid credential." if e.code == 403 else f"HTTP {e.code}"
        raise RanbvalConfigError(f"{url}: {detail}", code="remote_fetch_failed") from e
    except Exception as e:
        raise RanbvalConfigError(
            f"Could not reach the Ranbval control plane at {url}: {e}",
            code="remote_unreachable",
        ) from e


#: The same variables that select a local ``.ranbval.{mode}`` file also select the remote stage —
#: one idea ("which stage am I running in"), one variable.
_ENV_VARS = ("RANBVAL_ENV", "ENVIRONMENT", "ENV")


def _environment(environment: str | None) -> str | None:
    """The stage to pull: explicit arg → ``RANBVAL_ENV`` → ``ENVIRONMENT`` → ``ENV``.

    Unlike the local mode there is **no** ``development`` default: ``None`` means "let the server
    use the project's first environment", so a project that never named its stages still works.
    """
    if environment and str(environment).strip():
        return str(environment).strip().lower()
    for key in _ENV_VARS:
        v = os.environ.get(key)
        if v and str(v).strip():
            return str(v).strip().lower()
    return None


def fetch_env_set(
    *,
    project_secret: str | None = None,
    api_key: str | None = None,
    environment: str | None = None,
    host: str | None = None,
    timeout: float = 10.0,
) -> dict[str, str]:
    """Return ``{name: value}`` for every env var in **one environment** of the project.

    ``environment`` selects the stage — ``"development"``, ``"staging"``, ``"production"``, … —
    and defaults to ``RANBVAL_ENV``, then to the project's first environment. Only that stage's
    values come back, so a developer machine never receives production credentials.

    Owner authenticates with ``project_secret``; a developer with ``api_key``. Raises
    :class:`RanbvalConfigError` on auth failure or an unreachable control plane.
    """
    payload = _credential(project_secret, api_key)
    env = _environment(environment)
    if env:
        payload["environment"] = env
    body = _post(f"{_host(host)}/api/envs/pull", payload, timeout)
    envs = body.get("envs") or []
    return {e["name"]: e["value"] for e in envs if e.get("name")}


def push_env(
    name: str,
    value: str,
    *,
    project_secret: str | None = None,
    api_key: str | None = None,
    environment: str | None = None,
    host: str | None = None,
    timeout: float = 10.0,
) -> dict:
    """Add a ``PUBLIC_`` env to one environment, attributed to the caller (owner or developer).

    ``environment`` defaults to ``RANBVAL_ENV``, then the project's first stage. Only ``PUBLIC_``
    names are accepted — ``SECRET_``/``PROXY_`` keys are created in the dashboard (encrypted
    server-side). Returns ``{name, kind, added_by}``.
    """
    payload = {"name": name, "value": value, **_credential(project_secret, api_key)}
    env = _environment(environment)
    if env:
        payload["environment"] = env
    return _post(f"{_host(host)}/api/envs/add", payload, timeout)


def plan_status(
    *,
    project_secret: str | None = None,
    api_key: str | None = None,
    host: str | None = None,
    timeout: float = 10.0,
) -> dict:
    """What plan this project is on, what it allows, and how much is used this month.

    ::

        {"plan": "free", "plan_name": "Free", "has_active_subscription": False,
         "limits": {"projects": 1, "secrets": 5, "requests_month": 1000},
         "usage":  {"projects": 1, "secrets": 3, "requests_month": 412,
                    "requests_remaining": 588, "period": "2026-07"}}

    ``None`` for a limit means unlimited on this plan.

    This is for visibility — showing usage in your own tooling, or warning before a job runs into a
    cap. It is not a permission check: every limit is enforced by the server on the call itself, so
    there is nothing to be gained by consulting this first, and nothing lost by skipping it.
    """
    payload = _credential(project_secret, api_key)
    return _post(f"{_host(host)}/api/envs/plan-status", payload, timeout)
