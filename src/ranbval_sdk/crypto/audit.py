"""
Thread-safe audit log for SecretString access.

Every .use() call is recorded with label, timestamp, and caller location.
The secret value itself is NEVER logged.

Usage::

    from ranbval_sdk.audit import get_audit_log, clear_audit_log

    log = get_audit_log()
    # [{"label": "OPENAI_KEY", "timestamp": 1716000000.0, "caller": "app.py:42"}]
"""

from __future__ import annotations

import contextlib
import threading
import time
import traceback
from collections.abc import Iterator

# The record shape lives in the serializers package; re-exported here so
# ``from ranbval_sdk.crypto.audit import AuditEntry`` keeps working.
from ranbval_sdk.serializers.audit import AuditEntry, build_audit_entry

_lock = threading.Lock()
_log: list[AuditEntry] = []

# How many frames of ranbval_sdk internals to skip when finding the real caller.
_SDK_PACKAGE = "ranbval_sdk"


def record_access(label: str) -> None:
    """Record one .use() call. Called internally by SecretString.use()."""
    stack = traceback.extract_stack()
    caller = "unknown"
    # Walk from innermost outward; skip frames inside ranbval_sdk itself.
    for frame in reversed(stack):
        if _SDK_PACKAGE not in frame.filename:
            caller = f"{frame.filename}:{frame.lineno}"
            break
    with _lock:
        _log.append(build_audit_entry(label=label, timestamp=time.time(), caller=caller))


def get_audit_log() -> list[AuditEntry]:
    """Return a snapshot of all recorded accesses (no secrets, metadata only)."""
    with _lock:
        return list(_log)


def clear_audit_log() -> None:
    """Clear the in-memory audit log."""
    with _lock:
        _log.clear()


@contextlib.contextmanager
def audit_scope() -> Iterator[list[AuditEntry]]:
    """Capture just the secret accesses that happen inside a ``with`` block.

    Yields a list that is populated on exit with the entries recorded during the
    block — handy for tests and debugging ("which secrets did this code touch?")::

        with audit_scope() as accesses:
            client = OpenAI(api_key=vault.reveal("OPENAI_API_KEY"))
        assert [e["label"] for e in accesses] == ["OPENAI_API_KEY"]
    """
    with _lock:
        start = len(_log)
    captured: list[AuditEntry] = []
    try:
        yield captured
    finally:
        with _lock:
            captured.extend(_log[start:])
