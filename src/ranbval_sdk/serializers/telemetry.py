"""Serialize a usage event into the ``/api/telemetry`` request body.

:func:`build_telemetry_payload` shapes the top-level payload; :func:`build_security_metadata`
shapes its nested ``security`` block. Both are **pure shaping** — the caller gathers the live
client context (see :func:`ranbval_sdk.telemetry.context.collect_client_context`) and passes it
in. Only a non-reversible token salt and this metadata are sent — never plaintext.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def build_security_metadata(
    *,
    context: Mapping[str, Any],
    event_kind: str,
    transport: str,
    ci_environment: bool,
    roundtrip_ms: float | None = None,
) -> dict[str, Any]:
    """Shape the ``security`` block from a gathered client ``context`` plus per-event fields."""
    sec: dict[str, Any] = {
        "event_kind": event_kind,
        "sdk_version": context.get("sdk_version", ""),
        "client_platform": context.get("client_platform", ""),
        "python_version": context.get("python_version", ""),
        "transport": transport,
        "vault_token_format": "ranbval",
        "git_branch": context.get("git_branch"),
        "git_email": context.get("git_email"),
        "timezone": context.get("timezone", ""),
        "device_id": context.get("device_id", ""),
        "ci_environment": bool(ci_environment),
    }
    if roundtrip_ms is not None:
        sec["roundtrip_ms"] = round(float(roundtrip_ms), 2)  # decrypt latency
    return sec


def build_telemetry_payload(
    *,
    client_salt: str,
    machine_name: str,
    repo_path: str,
    git_url: str | None,
    model_used: str,
    prompt_tokens: int,
    completion_tokens: int,
    item_count: int,
    context: Mapping[str, Any],
    event_kind: str,
    transport: str,
    ci_environment: bool,
    roundtrip_ms: float | None = None,
) -> dict[str, Any]:
    """Shape the full ``/api/telemetry`` request body from already-gathered values."""
    return {
        "client_salt": client_salt,
        "machine_name": machine_name,
        "repo_path": repo_path,
        "git_url": git_url,
        "model_used": model_used,
        "prompt_tokens": int(prompt_tokens),
        "completion_tokens": int(completion_tokens),
        # Adaptive-sampling weight: this event represents `item_count` actual uses.
        # The control plane multiplies by this to reconstruct true totals.
        "item_count": max(1, int(item_count)),
        "security": build_security_metadata(
            context=context,
            event_kind=event_kind,
            transport=transport,
            ci_environment=ci_environment,
            roundtrip_ms=roundtrip_ms,
        ),
    }
