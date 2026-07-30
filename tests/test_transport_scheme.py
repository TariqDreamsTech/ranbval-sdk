"""The transport must not open anything but http(s).

`urlopen` honours `file:`, `ftp:` and any registered custom scheme. Because the host is taken
from configuration (`RANBVAL_HOST`, a `host_url=` argument), an attacker who can set that could
otherwise make the SDK read local files. Found by bandit (B310) and fixed rather than suppressed.
"""

from __future__ import annotations

import urllib.request

import pytest

from ranbval_sdk._internal.transport import urlopen
from ranbval_sdk.exceptions import RanbvalConfigError


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.invalid/x",
        "data:text/plain,hello",
        "gopher://example.invalid/",
    ],
)
def test_non_http_schemes_are_refused(url):
    with pytest.raises(RanbvalConfigError) as exc:
        urlopen(urllib.request.Request(url), timeout=1)
    assert exc.value.code == "disallowed_url_scheme"


def test_a_schemeless_url_never_reaches_the_guard():
    # urllib.request.Request rejects it at construction, so the guard is not the layer that
    # handles this case — asserted so the parametrised list above is not silently incomplete.
    with pytest.raises(ValueError):
        urllib.request.Request("no-scheme-at-all")


@pytest.mark.parametrize("url", ["https://example.invalid/x", "http://127.0.0.1:1/x"])
def test_http_and_https_get_past_the_scheme_check(url):
    # They must not be refused by *us*; reaching the network and failing there is the pass
    # condition, since these tests do not depend on an external host being up.
    with pytest.raises(Exception) as exc:  # noqa: B017 — any network error is fine
        urlopen(urllib.request.Request(url), timeout=1)
    assert not isinstance(exc.value, RanbvalConfigError)
