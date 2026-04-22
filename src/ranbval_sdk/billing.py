"""
Check vault owner's Ranbval subscription plan before using a secret.

Calls GET /api/public/billing-status?client_salt=... on the password manager.
No auth token required — the client_salt (from the encrypted token) is the identity.

Usage
-----
    from ranbval_sdk.billing import assert_plan_active, fetch_billing_status

    # raise BillingError if vault is locked / trial expired / no active plan
    assert_plan_active(client_salt="abc123")

    # or just inspect
    info = fetch_billing_status(client_salt="abc123")
    print(info["plan_key"], info["request_limit_month"])
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ranbval_sdk.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk import http_tls


class BillingError(PermissionError):
    """Raised when the vault owner's plan does not permit the current operation."""


def fetch_billing_status(
    client_salt: str,
    *,
    host_url: str | None = None,
) -> dict[str, Any]:
    """
    Return billing/plan info for the vault owner identified by *client_salt*.

    Keys returned:
        plan_key              str | None   — "starter" / "growth" / "pro" / "enterprise"
        plan_name             str | None   — human-readable plan name
        subscription_status   str | None   — billing-provider status (e.g. "active", "alive")
        has_active_subscription bool
        trial_active          bool
        trial_expired         bool
        trial_ends_at         str | None   — ISO datetime
        vault_locked          bool         — True → no access at all
        request_limit_month   int | None
        secrets_limit         int | None

    When the Ranbval backend has billing disabled (env
    ``RANBVAL_BILLING_DISABLED=true``), the response always reports
    ``vault_locked=false`` and ``has_active_subscription=true`` so this call
    becomes a no-op gate.

    Raises:
        BillingError   — session not found (404) or server error
        OSError        — network / TLS failure
    """
    host = (host_url or os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).rstrip("/")
    qs = urllib.parse.urlencode({"client_salt": client_salt})
    url = f"{host}/api/public/billing-status?{qs}"
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with http_tls.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if e.code == 404:
            raise BillingError(
                "Ranbval: session not found for this client salt. "
                "Check RANBVAL_HOST and that the token belongs to an active project."
            ) from e
        raise BillingError(
            f"Ranbval: billing-status check failed (HTTP {e.code}). {body}"
        ) from e
    except urllib.error.URLError as e:
        raise OSError(
            f"Ranbval: could not reach {host!r} to check billing status: {e}"
        ) from e


def assert_plan_active(
    client_salt: str,
    *,
    host_url: str | None = None,
    skip_env: str = "RANBVAL_SKIP_BILLING_CHECK",
) -> dict[str, Any]:
    """
    Fetch billing status and raise ``BillingError`` when the vault is locked.

    Vault is locked when:
      - ``vault_locked`` is True  (trial expired with no active plan)
      - No active subscription AND trial is not running

    Returns the billing dict on success so callers can inspect plan limits.

    **Default is no-op (no network call).** While the Ranbval backend is
    running with ``RANBVAL_BILLING_DISABLED=true`` (current default), there is
    nothing to enforce, so this function returns an empty dict immediately.
    To re-enable strict enforcement on the SDK side, set
    ``RANBVAL_ENFORCE_BILLING=1`` in the consuming app's environment.

    ``RANBVAL_SKIP_BILLING_CHECK=1`` also forces a bypass (legacy escape hatch).
    """
    enforce = (os.environ.get("RANBVAL_ENFORCE_BILLING") or "").strip().lower()
    if enforce not in ("1", "true", "yes", "on"):
        # Billing is server-side disabled by default — no need to spend a
        # round-trip per decrypt to be told the vault is unlocked.
        return {}

    skip = (os.environ.get(skip_env) or "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        return {}

    info = fetch_billing_status(client_salt, host_url=host_url)

    if info.get("vault_locked"):
        plan = info.get("plan_key") or "none"
        raise BillingError(
            f"Ranbval: vault is locked — your trial has expired and there is no active subscription "
            f"(current plan: {plan}). "
            "Subscribe at https://www.ranbval.com to restore access."
        )

    has_sub = info.get("has_active_subscription", False)
    trial_active = info.get("trial_active", False)
    trial_expired = info.get("trial_expired", False)

    if not has_sub and not trial_active:
        if trial_expired:
            raise BillingError(
                "Ranbval: your free trial has ended. "
                "Subscribe at https://www.ranbval.com to continue using this vault."
            )
        raise BillingError(
            "Ranbval: no active subscription or trial found for this vault. "
            "Subscribe at https://www.ranbval.com."
        )

    return info


def plan_limits(
    client_salt: str,
    *,
    host_url: str | None = None,
) -> dict[str, Any]:
    """
    Convenience: return just the plan limits for the vault owner.

    Returns a dict with keys:
        plan_key, plan_name, request_limit_month, secrets_limit
    Returns empty dict if billing enforcement is off (default), the check is
    skipped, or the call fails silently.
    """
    enforce = (os.environ.get("RANBVAL_ENFORCE_BILLING") or "").strip().lower()
    if enforce not in ("1", "true", "yes", "on"):
        return {}
    skip = (os.environ.get("RANBVAL_SKIP_BILLING_CHECK") or "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        return {}
    try:
        info = fetch_billing_status(client_salt, host_url=host_url)
        return {
            "plan_key": info.get("plan_key"),
            "plan_name": info.get("plan_name"),
            "request_limit_month": info.get("request_limit_month"),
            "secrets_limit": info.get("secrets_limit"),
        }
    except Exception:
        return {}
