"""Tests for the opt-in secret-access monitor (context + exfil correlation)."""

from __future__ import annotations

import os
import tempfile

import pytest

from ranbval_sdk import (
    SecretString,
    install_access_monitor,
    uninstall_access_monitor,
)
from ranbval_sdk.telemetry.monitor import classify_context


@pytest.fixture
def monitor_events():
    events: list[dict] = []
    install_access_monitor(on_event=events.append, watch_exfil=True)
    yield events
    uninstall_access_monitor()


def test_classify_context():
    assert classify_context("/app/main.py:42") == "app"
    assert classify_context("<string>:5") == "exec"  # python -c / exec()
    assert classify_context("<stdin>:1") == "repl"
    assert classify_context("<ipython-input-3>:1") == "notebook"
    assert classify_context("unknown") == "app"


def test_app_context_not_flagged(monitor_events):
    # A .use() from this test file (a real .py) is "app" — must NOT be flagged suspicious.
    SecretString("sk-demo").use()
    assert not any(e["kind"] == "secret.suspicious_access" for e in monitor_events)


def test_possible_exfil_on_file_write(monitor_events):
    s = SecretString("sk-demo")
    s.use()
    path = os.path.join(tempfile.mkdtemp(), "stolen.txt")
    with open(path, "w") as f:  # write right after .use()
        f.write("x")
    assert any(
        e["kind"] == "secret.possible_exfil" and e["method"] == "file_write"
        for e in monitor_events
    )


def test_no_exfil_without_recent_use(monitor_events):
    # A file write with no preceding .use() must not be flagged.
    path = os.path.join(tempfile.mkdtemp(), "plain.txt")
    with open(path, "w") as f:
        f.write("x")
    assert not any(e["kind"] == "secret.possible_exfil" for e in monitor_events)


def test_inmemory_iteration_detected(monitor_events):
    # The exact bypass an agent uses: ''.join(ch for ch in key.use()).
    val = SecretString("sk-super-secret").use()
    stolen = "".join(ch for ch in val)
    assert stolen == "sk-super-secret"  # real value still returned — nothing breaks
    assert any(
        e["kind"] == "secret.possible_exfil" and e["method"] == "iteration"
        for e in monitor_events
    )


def test_list_iteration_detected(monitor_events):
    val = SecretString("sk-x").use()
    assert list(val) == ["s", "k", "-", "x"]
    assert any(e["method"] == "iteration" for e in monitor_events)


def test_fstring_no_false_alarm(monitor_events):
    # Legitimate SDK header construction must NOT be flagged.
    val = SecretString("sk-real").use()
    assert f"Bearer {val}" == "Bearer sk-real"
    assert not any(e["kind"] == "secret.possible_exfil" for e in monitor_events)


def test_iteration_not_flagged_when_monitor_off():
    # No monitor installed → iteration works normally, no notifier called.
    val = SecretString("sk-x").use()
    assert "".join(ch for ch in val) == "sk-x"  # must not raise / must work


def test_buffer_read_detected(monitor_events):
    # Naive s._buf / s._pad access (a reveal-gate/monitor bypass) is now flagged.
    s = SecretString("sk-secret", label="DB")
    _ = s._buf
    assert any(e.get("method") == "buffer_read" for e in monitor_events)


def test_plaintext_bytes_method_removed():
    # The convenience _plaintext_bytes() reveal method must no longer exist.
    s = SecretString("sk-secret")
    assert not hasattr(s, "_plaintext_bytes")


def test_explicit_getattribute_bypass_is_silent(monitor_events):
    # Honest floor: object.__getattribute__(s,'_buf') bypasses the class → undetectable.
    s = SecretString("sk-secret")
    _ = object.__getattribute__(s, "_buf")
    assert not any(e.get("method") == "buffer_read" for e in monitor_events)


def test_uninstall_stops_notifications():
    events: list[dict] = []
    install_access_monitor(on_event=events.append, watch_exfil=False)
    uninstall_access_monitor()
    SecretString("sk-demo").use()
    # audit notifier cleared → no new events after uninstall
    assert events == []
