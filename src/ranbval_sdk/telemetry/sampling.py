"""Adaptive usage aggregation for high-volume telemetry.

A hot loop can call ``decrypt_key()`` thousands of times a second for the *same* credential
from the *same* repo. Sending a full POST every time is pure waste — nothing new is happening.
This module keeps telemetry cheap **without letting it be suppressed** (usage is never turned
off, only aggregated):

- **First use of a credential is sent immediately (100%)** — the "this key started being used
  from this machine/repo" signal is never dropped.
- **Repeats just increment a local counter — no network per call.** Same context → ``count++``.
- **A background flusher sends one aggregated event per credential every ~30s** (and a final
  flush at process exit), each carrying an ``item_count`` weight. The control plane multiplies
  by ``item_count`` to reconstruct the true totals (the App Insights / OpenCensus approach).

The result: send-rate stays bounded (≈ one event per active credential per interval) no matter
how hot the decrypt loop is, yet no usage is ever lost. The interval is a fixed constant — a
rate limiter, not a user opt-out.
"""

from __future__ import annotations

import atexit
import threading
import time

# One aggregated flush per active credential per this many seconds. Fixed — not a user
# opt-out; telemetry cannot be disabled, only aggregated.
_FLUSH_INTERVAL_SEC = 30.0


class AdaptiveSampler:
    """Send the first use of each credential immediately; aggregate repeats and flush on a timer."""

    def __init__(self, flush_interval_sec: float = _FLUSH_INTERVAL_SEC) -> None:
        self._interval = flush_interval_sec
        self._lock = threading.Lock()
        self._seen: set[str] = (
            set()
        )  # credentials sent at least once this run (first-seen = 100%)
        self._pending: dict[str, int] = {}  # unsent repeat counts per credential
        self._flusher_started = False

    def decide(self, key: str) -> int:
        """Return ``item_count`` to send inline now (1 on first use), or 0 to just count locally."""
        with self._lock:
            self._ensure_flusher()
            if key not in self._seen:
                self._seen.add(key)
                return 1  # first use → send a full event immediately
            # Same credential again → just increment the counter, no network.
            self._pending[key] = self._pending.get(key, 0) + 1
            return 0

    def flush_pending(self) -> list[tuple[str, int]]:
        """Return and clear every unsent ``(key, count)`` aggregate."""
        with self._lock:
            items = [(k, c) for k, c in self._pending.items() if c > 0]
            self._pending.clear()
            return items

    # -- background flushing --------------------------------------------------
    def _ensure_flusher(self) -> None:
        """Start the daemon flush loop on first use (called under ``self._lock``)."""
        if self._flusher_started:
            return
        self._flusher_started = True
        threading.Thread(target=self._flush_loop, daemon=True).start()

    def _flush_loop(self) -> None:
        while True:
            time.sleep(self._interval)
            _emit_aggregates(self.flush_pending())


def _emit_aggregates(items: list[tuple[str, int]], *, background: bool = True) -> None:
    """POST one aggregated usage event per ``(credential, count)`` pair."""
    if not items:
        return
    from ranbval_sdk.telemetry.client import emit_telemetry

    for key, count in items:
        try:
            emit_telemetry(
                client_salt=key,
                item_count=count,
                model_used="secret.access",
                event_kind="platform.invocation",
                background=background,
            )
        except Exception:
            pass


#: Process-wide singleton used by the auto-report path in ``crypto.cipher``.
usage_sampler = AdaptiveSampler()


@atexit.register
def _flush_on_exit() -> None:
    """Best-effort flush so no usage is lost when the process ends.

    Two halves, and only the first one used to exist:
      1. aggregated repeats, sent synchronously here;
      2. the FIRST use of each credential, which was already dispatched on a daemon thread and would
         otherwise be killed mid-POST by interpreter shutdown. That is the event a canary fires on.
    """
    _emit_aggregates(usage_sampler.flush_pending(), background=False)

    from ranbval_sdk.telemetry.client import flush_inflight

    flush_inflight()


__all__ = ["AdaptiveSampler", "usage_sampler"]
