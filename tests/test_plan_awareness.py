"""What the SDK knows about the customer's plan — and what it deliberately does not do with it.

The design constraint worth restating: the SDK runs on the customer's machine. Any limit it checks
locally is a limit they can delete, so nothing here refuses a call. The server enforces; this code
only makes the server's answer legible.
"""

import json
import urllib.error

import pytest

import ranbval_sdk
from ranbval_sdk import PlanLimitError
from ranbval_sdk.integrations import proxy


def _http_error(code, detail):
    return urllib.error.HTTPError(
        url="https://api.secret.ranbval.com/api/execute",
        code=code,
        msg="err",
        hdrs=None,
        fp=__import__("io").BytesIO(json.dumps({"detail": detail}).encode()),
    )


def test_plan_status_is_exported():
    assert callable(ranbval_sdk.plan_status)


def test_a_spent_allowance_raises_a_plan_error_not_a_proxy_error(monkeypatch):
    """429 means "you have run out", which a caller may want to handle — not "the proxy is broken"."""
    detail = {
        "error": "request_limit_reached",
        "message": "You have used all 1,000 proxy requests included in your plan this month.",
        "used": 1001,
        "limit": 1000,
        "period": "2026-07",
    }

    def boom(*_a, **_k):
        raise _http_error(429, detail)

    monkeypatch.setattr(proxy.urllib.request, "urlopen", boom)

    with pytest.raises(PlanLimitError) as e:
        proxy.proxy_request("tok", "https://api.example.com/v1", body={"model": "x"}, api_key="rk_test", project_secret="ps_test")

    err = e.value
    assert (err.used, err.limit, err.period) == (1001, 1000, "2026-07")
    assert err.kind == "requests"
    assert err.code == "request_limit_reached"
    # The message a developer sees is the server's sentence, not a stringified dict.
    assert "1,000 proxy requests" in str(err)
    assert "{" not in str(err)


def test_a_plan_error_is_still_catchable_as_a_ranbval_error():
    """Existing `except RanbvalError` blocks must keep working."""
    assert issubclass(PlanLimitError, ranbval_sdk.RanbvalError)


def test_other_proxy_failures_stay_proxy_errors(monkeypatch):
    """A 500 is not a billing problem; it must not be dressed up as one."""
    def boom(*_a, **_k):
        raise _http_error(500, "upstream exploded")

    monkeypatch.setattr(proxy.urllib.request, "urlopen", boom)

    with pytest.raises(proxy.ProxyError):
        proxy.proxy_request("tok", "https://api.example.com/v1", body={"model": "x"}, api_key="rk_test", project_secret="ps_test")


def test_plan_status_reports_but_never_blocks(monkeypatch):
    """Knowing you are at the cap does not stop the SDK from trying — the server decides."""
    spent = {
        "plan": "free",
        "limits": {"requests_month": 1000, "secrets": 5, "projects": 1},
        "usage": {"requests_month": 1000, "requests_remaining": 0, "period": "2026-07"},
    }
    monkeypatch.setattr(
        "ranbval_sdk.remote.client._post", lambda *_a, **_k: spent
    )
    status = ranbval_sdk.plan_status(project_secret="ps_test")
    assert status["usage"]["requests_remaining"] == 0

    # ...and a proxy call is still attempted rather than short-circuited locally.
    called = {"n": 0}

    def fake_urlopen(*_a, **_k):
        called["n"] += 1
        raise _http_error(500, "upstream")

    monkeypatch.setattr(proxy.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(proxy.ProxyError):
        proxy.proxy_request("tok", "https://api.example.com/v1", body={"model": "x"}, api_key="rk_test", project_secret="ps_test")
    assert called["n"] == 1
