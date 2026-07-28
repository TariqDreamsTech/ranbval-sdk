"""enforcement_scope narrows the unguarded window instead of killing enforcement process-wide."""

from __future__ import annotations

import pytest

from ranbval_sdk import SecretString, enforcement_scope, is_enforced, set_enforcement
from ranbval_sdk.exceptions import RanbvalSecurityError


@pytest.fixture(autouse=True)
def _strict():
    set_enforcement(True)
    yield
    set_enforcement(True)


def test_guards_are_relaxed_inside_and_restored_after():
    # Uses slicing, not encode(): encode is a handoff method now (see test_access_monitor), so
    # it is allowed either way and would not prove the scope did anything.
    s = SecretString("sk-live-abc123", label="TEST_KEY")

    with pytest.raises(RanbvalSecurityError):
        s.use()[:]

    with enforcement_scope(False):
        assert is_enforced() is False
        assert s.use()[:] == "sk-live-abc123"

    assert is_enforced() is True
    with pytest.raises(RanbvalSecurityError):
        s.use()[:]


def test_previous_setting_is_restored_not_hardcoded_to_true():
    set_enforcement(False)
    with enforcement_scope(True):
        assert is_enforced() is True
    assert is_enforced() is False  # restored to what it was, not forced back on


def test_setting_is_restored_when_the_block_raises():
    with pytest.raises(ValueError):
        with enforcement_scope(False):
            raise ValueError("boom")
    assert is_enforced() is True


def test_scopes_nest_and_unwind_in_order():
    with enforcement_scope(False):
        with enforcement_scope(True):
            assert is_enforced() is True
        assert is_enforced() is False
    assert is_enforced() is True
