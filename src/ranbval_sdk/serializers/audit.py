"""Shape of a SecretString-access audit record.

One entry per ``.use()`` call: which credential (``label``), when (``timestamp``), and the
caller site (``file:line``). The secret value itself is never part of this shape.
"""

from __future__ import annotations

from typing import TypedDict


class AuditEntry(TypedDict):
    label: str
    timestamp: float
    caller: str


def build_audit_entry(*, label: str, timestamp: float, caller: str) -> AuditEntry:
    """Shape one audit record from already-gathered values."""
    return AuditEntry(label=label, timestamp=timestamp, caller=caller)
