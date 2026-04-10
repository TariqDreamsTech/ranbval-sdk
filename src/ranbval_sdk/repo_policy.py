"""Enforce project allowlisted git remotes before decrypting Ranbval keys."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

from ranbval_sdk import http_tls


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
    if not parsed.netloc:
        return ul
    path = (parsed.path or "").strip("/").lower()
    if path.endswith(".git"):
        path = path[:-4]
    scheme = (parsed.scheme or "https").lower()
    host = parsed.netloc.lower()
    return f"{scheme}://{host}/{path}"


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


def fetch_repo_policy(ranbval_host: str, client_salt: str) -> dict:
    base = ranbval_host.rstrip("/")
    qs = urllib.parse.urlencode({"client_salt": client_salt})
    url = f"{base}/api/public/repo-policy?{qs}"
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    with http_tls.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode("utf-8"))


def assert_repo_allowed_for_decrypt(ranbval_host: str, client_salt: str) -> None:
    """
    If the project has any allowed_repos, refuse to proceed unless
    `git remote origin` matches one of them (https / ssh / .git normalized).
    Set RANBVAL_SKIP_REPO_CHECK=1 to bypass (local dev only).
    """
    skip = (os.environ.get("RANBVAL_SKIP_REPO_CHECK") or "").strip().lower()
    if skip in ("1", "true", "yes", "on"):
        return
    try:
        policy = fetch_repo_policy(ranbval_host, client_salt)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise PermissionError(
                "Ranbval: unknown session for this key (repo policy could not be loaded). "
                "Check RANBVAL_HOST and that this token belongs to a valid project session."
            ) from e
        raise PermissionError(
            f"Ranbval: could not load repo policy (HTTP {e.code}). Check RANBVAL_HOST."
        ) from e
    except urllib.error.URLError as e:
        raise PermissionError(
            f"Ranbval: could not reach {ranbval_host!r} to verify allowed repositories: {e}"
        ) from e

    if not policy.get("enforce_allowlist"):
        return

    allowed = policy.get("allowed_repos") or []
    origin = get_git_remote_origin()
    if not origin:
        raise PermissionError(
            "Ranbval: this key may only be used from an allowlisted Git repository, "
            "but no `git remote origin` was found. Work inside a clone of an allowed repo "
            "(run `git remote -v` to confirm)."
        )

    if not _origin_allowed(origin, allowed):
        raise PermissionError(
            "Ranbval: you are not allowed to use this key from this repository. "
            f"Current origin is {origin!r}. Add this URL (or its GitHub https/ssh equivalent) "
            "to Allowed repositories in the Ranbval dashboard for this project."
        )
