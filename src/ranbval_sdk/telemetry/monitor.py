"""Opt-in monitoring of secret *access* — makes it visible WHO revealed a secret,
from WHERE, and (heuristically) whether it may have been exfiltrated.

This is **not prevention.** A trusted party who can decrypt can always extract the
plaintext — no library can stop that. What this does is make every reveal *visible and
attributable*, so a trusted party's misuse leaves a trace on your Live Monitor:

- Every ``SecretString.use()`` is classified by call context:
  ``app`` (a real ``.py`` file) · ``exec`` (``python -c`` / ``exec``) · ``repl`` (``<stdin>``)
  · ``notebook`` (IPython/Jupyter). Anything but ``app`` is flagged ``suspicious`` — a normal
  application never reveals a secret from a REPL or ``python -c``.
- Optionally (``watch_exfil=True``), a ``sys.addaudithook`` flags a **file write** or a
  **subprocess** that happens right after a ``.use()`` as a *possible exfiltration*.

Honest limits: this is heuristic (a correlated file-write is a hint, not proof), it is
process-global (like any audit hook), and it cannot see purely in-memory theft that never
leaves the process. It catches the exfil methods that actually happen (``python -c``/REPL,
write-to-file, pipe-to-subprocess); it is not a DLP/EDR replacement.

Usage::

    from ranbval_sdk import install_access_monitor
    install_access_monitor()                    # telemeter suspicious access to the Live Monitor
    install_access_monitor(on_event=my_handler) # or handle events yourself
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from typing import Any

# A file-write / subprocess within this window after a .use() is treated as a
# possible exfiltration. Network is deliberately excluded — a legitimate API call
# is itself a network connection right after .use(), so it can't be distinguished.
_EXFIL_WINDOW_SEC = 0.25

_lock = threading.Lock()
_recent_use: dict[int, float] = {}  # thread id -> monotonic time of last .use()
_on_event: Callable[[dict[str, Any]], None] | None = None
_audit_hook_installed = False
_installed = False


def classify_context(caller: str) -> str:
    """Classify a ``"file:line"`` caller into ``app`` | ``exec`` | ``repl`` | ``notebook``."""
    filename = caller.rsplit(":", 1)[0] if ":" in caller else caller
    if filename.startswith("<ipython-") or "ipykernel" in filename:
        return "notebook"
    if filename == "<stdin>":
        return "repl"
    if filename.startswith("<"):  # <string> (python -c), <console>, <exec>, …
        return "exec"
    return "app"


def _dispatch(event: dict[str, Any]) -> None:
    """Send one monitoring event to the user handler, or telemeter it by default."""
    handler = _on_event
    if handler is not None:
        try:
            handler(event)
        except Exception:
            pass
        return
    _default_telemeter(event)


def _default_telemeter(event: dict[str, Any]) -> None:
    """Default handler: report the signal to the Live Monitor (best-effort)."""
    try:
        import os

        from ranbval_sdk.telemetry.client import emit_telemetry

        # Tie the signal to the credential when the label is an env var holding a token.
        label = event.get("label") or ""
        emit_telemetry(
            vault_token_env=label if os.environ.get(label, "").startswith("ranbval.") else None,
            model_used=event["kind"],
            event_kind=event["kind"],
            background=True,
        )
    except Exception:
        pass


def _on_use(label: str, caller: str) -> None:
    """Fired on every SecretString.use() (via the audit notifier)."""
    with _lock:
        _recent_use[threading.get_ident()] = time.monotonic()
    context = classify_context(caller)
    if context != "app":
        _dispatch(
            {"kind": "secret.suspicious_access", "label": label, "caller": caller, "context": context}
        )


def _on_reveal(method: str) -> None:
    """Fired when a revealed value is manipulated as an in-memory extraction (e.g. iterated)."""
    _dispatch({"kind": "secret.possible_exfil", "method": method})


def _audit_hook(event: str, args: tuple) -> None:
    """Correlate a file-write / subprocess that closely follows a .use()."""
    if event == "open":
        mode = str(args[1]) if len(args) > 1 and args[1] else ""
        if not any(flag in mode for flag in ("w", "a", "x", "+")):
            return
        method = "file_write"
    elif event in ("subprocess.Popen", "os.system", "os.exec"):
        method = "subprocess"
    else:
        return
    tid = threading.get_ident()
    with _lock:
        last = _recent_use.get(tid)
    if last is not None and (time.monotonic() - last) < _EXFIL_WINDOW_SEC:
        with _lock:
            _recent_use.pop(tid, None)  # one signal per use, avoid a storm
        _dispatch({"kind": "secret.possible_exfil", "method": method})


def install_access_monitor(
    *,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    watch_exfil: bool = True,
) -> None:
    """Turn on secret-access monitoring (opt-in; safe to call more than once).

    Args:
        on_event: called with each signal dict (keys: ``kind`` and context fields). When
            omitted, signals are telemetered to the Live Monitor by default.
        watch_exfil: also install a ``sys.addaudithook`` that flags file-write / subprocess
            right after a ``.use()`` as a possible exfiltration. Process-global; set ``False``
            to only classify access context.
    """
    global _on_event, _installed, _audit_hook_installed
    _on_event = on_event

    from ranbval_sdk.crypto.audit import set_access_notifier
    from ranbval_sdk.crypto.secret_string import set_reveal_notifier

    set_access_notifier(_on_use)
    set_reveal_notifier(_on_reveal)  # catches in-memory iteration (join / list / comprehension)

    if watch_exfil and not _audit_hook_installed:
        sys.addaudithook(_audit_hook)  # cannot be removed once added — hence the guard
        _audit_hook_installed = True

    _installed = True


def uninstall_access_monitor() -> None:
    """Stop classifying access (the audit hook cannot be removed, but goes idle)."""
    global _on_event, _installed
    from ranbval_sdk.crypto.audit import set_access_notifier
    from ranbval_sdk.crypto.secret_string import set_reveal_notifier

    set_access_notifier(None)
    set_reveal_notifier(None)
    _on_event = None
    _installed = False


__all__ = ["install_access_monitor", "uninstall_access_monitor", "classify_context"]
