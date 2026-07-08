"""Enforce project-allowlisted git remotes before decrypting Ranbval keys.

Provenance enforcement, not cryptography: normalize the local ``git remote origin``, fetch the
project's allowlist from the control plane, and refuse decryption when the origin is not allowed.
The check is server-controlled and cannot be skipped on the client.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from ranbval_sdk._internal import transport
from ranbval_sdk.exceptions import RepoNotAllowedError, RepoPolicyError

# Short-lived, in-process cache of the repo policy keyed by (host, client_salt). A hot
# decrypt loop would otherwise make one blocking HTTP round-trip per call; caching bounds
# that to one fetch per credential per TTL while still re-checking regularly. Kept short so
# dashboard allowlist changes take effect quickly.
_POLICY_TTL_SEC = 60.0
_policy_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_policy_lock = threading.Lock()


def normalize_git_remote_url(url: str | None) -> str | None:
    if not url or not isinstance(url, str):
        return None
    u = url.strip().rstrip("/")
    if not u:
        return None
    if u.lower().endswith(".git"):
        u = u[:-4]
    ul = u.lower()
    if ul.startswith("git@"):
        at = u.find("@")
        colon = u.find(":", at)
        if colon == -1:
            return ul
        host = u[at + 1 : colon].strip().lower()
        path = u[colon + 1 :].strip().strip("/").lower()
        return f"https://{host}/{path}"
    parsed = urlparse(u)
    # Use parsed.hostname (strips userinfo like tokens/passwords) instead of
    # parsed.netloc which includes "token@host" — CI systems inject tokens into
    # the remote URL (e.g. https://ghp_TOKEN@github.com/org/repo) which would
    # otherwise never match the allowlist entry "https://github.com/org/repo".
    host = (parsed.hostname or "").lower()
    if not host:
        return ul
    port = f":{parsed.port}" if parsed.port else ""
    path = (parsed.path or "").strip("/").lower()
    if path.endswith(".git"):
        path = path[:-4]
    scheme = (parsed.scheme or "https").lower()
    return f"{scheme}://{host}{port}/{path}"


def get_git_remote_origin() -> str | None:
    try:
        import subprocess

        out = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None


def _origin_allowed(origin: str, allowed: list[str]) -> bool:
    g = normalize_git_remote_url(origin)
    if not g:
        return False
    norms = {normalize_git_remote_url(x) for x in allowed if x}
    norms.discard(None)
    return g in norms


def _fetch_repo_policy_uncached(ranbval_host: str, client_salt: str) -> dict:
    base = ranbval_host.rstrip("/")
    qs = urllib.parse.urlencode({"client_salt": client_salt})
    url = f"{base}/api/public/repo-policy?{qs}"
    req = urllib.request.Request(
        url, method="GET", headers={"Accept": "application/json"}
    )
    with transport.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_repo_policy(ranbval_host: str, client_salt: str) -> dict:
    """Fetch (and briefly cache) the project's repo policy for ``client_salt``.

    Results are cached per ``(host, salt)`` for ``_POLICY_TTL_SEC`` so repeated decrypts of
    the same credential don't each pay a network round-trip. Errors are never cached.
    """
    cache_key = (ranbval_host.rstrip("/"), client_salt)
    now = time.time()
    with _policy_lock:
        hit = _policy_cache.get(cache_key)
        if hit is not None and (now - hit[0]) < _POLICY_TTL_SEC:
            return hit[1]

    policy = _fetch_repo_policy_uncached(ranbval_host, client_salt)

    with _policy_lock:
        _policy_cache[cache_key] = (time.time(), policy)
    return policy


def assert_repo_allowed_for_decrypt(ranbval_host: str, client_salt: str) -> None:
    """
    Enforce the project's repo allowlist before decryption.

    The policy is fetched from the Ranbval control plane and cannot be bypassed on the
    client: if the project has any ``allowed_repos``, decryption proceeds only when
    ``git remote origin`` matches one of them (https / ssh / .git normalized). This is a
    mandatory, server-controlled check — there is no local skip.
    """
    try:
        policy = fetch_repo_policy(ranbval_host, client_salt)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RepoPolicyError(
                "Ranbval: unknown session for this key (repo policy could not be loaded). "
                "Check RANBVAL_HOST and that this token belongs to a valid project session."
            ) from e
        raise RepoPolicyError(
            f"Ranbval: could not load repo policy (HTTP {e.code}). Check RANBVAL_HOST."
        ) from e
    except urllib.error.URLError as e:
        raise RepoPolicyError(
            f"Ranbval: could not reach {ranbval_host!r} to verify allowed repositories: {e}"
        ) from e

    if not policy.get("enforce_allowlist"):
        return

    allowed = policy.get("allowed_repos") or []
    origin = get_git_remote_origin()
    if not origin:
        raise RepoNotAllowedError(
            "Ranbval: this key may only be used from an allowlisted Git repository, "
            "but no `git remote origin` was found. Work inside a clone of an allowed repo "
            "(run `git remote -v` to confirm)."
        )

    if not _origin_allowed(origin, allowed):
        raise RepoNotAllowedError(
            "Ranbval: you are not allowed to use this key from this repository. "
            f"Current origin is {origin!r}. Add this URL (or its GitHub https/ssh equivalent) "
            "to Allowed repositories in the Ranbval dashboard for this project."
        )
