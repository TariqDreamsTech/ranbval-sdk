"""Tests for the opt-in secret-access monitor (context + exfil correlation)."""

from __future__ import annotations

import os
import tempfile

import pytest

from ranbval_sdk import (
    RanbvalSecurityError,
    SecretString,
    install_access_monitor,
    is_enforced,
    set_enforcement,
    uninstall_access_monitor,
)
from ranbval_sdk.telemetry.monitor import classify_context


@pytest.fixture
def monitor_events():
    # These tests exercise DETECTION (the value is still returned and an event fires), so
    # enforcement is turned off here; the raise-on-extraction behaviour is tested separately
    # in the enforcement section below.
    events: list[dict] = []
    set_enforcement(False)
    install_access_monitor(on_event=events.append, watch_exfil=True)
    yield events
    uninstall_access_monitor()
    set_enforcement(True)


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
    # Enforcement is independent of the monitor, so to show "no notifier called" we turn it off.
    # With enforcement off AND no monitor, iteration works normally and nothing is reported.
    set_enforcement(False)
    try:
        val = SecretString("sk-x").use()
        assert "".join(ch for ch in val) == "sk-x"  # must not raise / must work
    finally:
        set_enforcement(True)


def test_buffer_read_detected(monitor_events):
    # Naive s._buf / s._pad access (a reveal-gate/monitor bypass) is now flagged.
    s = SecretString("sk-secret", label="DB")
    _ = s._buf
    assert any(e.get("method") == "buffer_read" for e in monitor_events)


def test_plaintext_bytes_method_removed():
    # The convenience _plaintext_bytes() reveal method must no longer exist.
    s = SecretString("sk-secret")
    assert not hasattr(s, "_plaintext_bytes")


def test_object_getattribute_buf_now_fires(monitor_events):
    # _buf/_pad are now honeypot properties, so even object.__getattribute__(s,"_buf") — the
    # form that used to bypass the class — fires the buffer_read signal.
    s = SecretString("sk-secret")
    _ = object.__getattribute__(s, "_buf")
    assert any(e.get("method") == "buffer_read" for e in monitor_events)


def test_real_slot_bypass_is_silent(monitor_events):
    # Honest floor moved, not closed: the REAL slot object.__getattribute__(s,'_b') still reads
    # the (XOR-masked) buffer with no signal — anyone reading this open-source file finds it.
    s = SecretString("sk-secret")
    _ = object.__getattribute__(s, "_b")
    assert not any(e.get("method") == "buffer_read" for e in monitor_events)


def test_uninstall_stops_notifications():
    events: list[dict] = []
    install_access_monitor(on_event=events.append, watch_exfil=False)
    uninstall_access_monitor()
    SecretString("sk-demo").use()
    # audit notifier cleared → no new events after uninstall
    assert events == []


# ── Enforcement (strict by default) ───────────────────────────────────────────


@pytest.fixture
def enforced():
    """Guarantee enforcement is ON for the test and restored afterwards."""
    set_enforcement(True)
    yield
    set_enforcement(True)


def test_enforced_by_default():
    assert is_enforced() is True


def test_iteration_raises_by_default(enforced):
    val = SecretString("sk-super-secret").use()
    with pytest.raises(RanbvalSecurityError):
        "".join(ch for ch in val)


def test_list_iteration_raises_by_default(enforced):
    val = SecretString("sk-x").use()
    with pytest.raises(RanbvalSecurityError):
        list(val)


def test_encode_raises_by_default(enforced):
    val = SecretString("sk-secret").use()
    with pytest.raises(RanbvalSecurityError):
        val.encode()


def test_buffer_read_raises_by_default(enforced):
    s = SecretString("sk-secret", label="DB")
    with pytest.raises(RanbvalSecurityError):
        _ = s._buf


def test_object_getattribute_buf_raises_under_enforcement(enforced):
    # _buf is a honeypot property, so even the object.__getattribute__ form raises now.
    s = SecretString("sk-secret")
    with pytest.raises(RanbvalSecurityError):
        object.__getattribute__(s, "_buf")


def test_slice_raises_by_default(enforced):
    val = SecretString("sk-secret").use()
    with pytest.raises(RanbvalSecurityError):
        _ = val[:]


def test_index_raises_by_default(enforced):
    val = SecretString("sk-secret").use()
    with pytest.raises(RanbvalSecurityError):
        _ = val[0]


def test_fstring_never_raises_under_enforcement(enforced):
    # Legitimate SDK header construction must keep working — __format__ uses base str.__getitem__.
    val = SecretString("sk-real").use()
    assert f"Bearer {val}" == "Bearer sk-real"
    assert "{}".format(val) == "sk-real"  # noqa: UP032 — deliberately exercising str.format path


def test_str_raises_by_default(enforced):
    # str()/print()/'%s' raise under enforcement (loud) instead of masking.
    val = SecretString("sk-real").use()
    with pytest.raises(RanbvalSecurityError):
        str(val)
    with pytest.raises(RanbvalSecurityError):
        _ = "%s" % val  # noqa: UP031


def test_wrapper_str_raises_by_default(enforced):
    with pytest.raises(RanbvalSecurityError):
        str(SecretString("sk-real"))


def test_repr_still_masks_under_enforcement(enforced):
    # repr must NOT raise (error reporters / debuggers repr locals).
    val = SecretString("sk-real").use()
    assert repr(val) == "SecretString(***)"
    assert repr(SecretString("x")) == "SecretString(***)"


def test_honest_floor_still_open_under_enforcement(enforced):
    # The documented, unblockable in-process bypasses must still return the real value (we do
    # not fake-guard them): base str methods and the real buffer slot.
    s = SecretString("sk-real")
    val = s.use()
    assert str.__str__(val) == "sk-real"  # cannot block — str type is immutable
    assert str.__getitem__(val, slice(None)) == "sk-real"  # base getitem bypasses our override
    assert object.__getattribute__(s, "_b") is not None  # real slot still readable
    # And the SDK-critical real-value paths must keep working (or the product breaks):
    assert f"Bearer {val}" == "Bearer sk-real"
    assert "Bearer " + val == "Bearer sk-real"


def test_set_enforcement_off_restores_legacy_behaviour():
    set_enforcement(False)
    try:
        val = SecretString("sk-x").use()
        assert "".join(ch for ch in val) == "sk-x"  # returns the value, no raise
        assert val.encode() == b"sk-x"
        assert val[:] == "sk-x"  # slicing allowed again
        s = SecretString("sk-y")
        assert s._buf is not None  # buffer read allowed again
    finally:
        set_enforcement(True)
