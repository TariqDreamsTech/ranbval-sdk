"""Provenance & access policy — server-controlled checks the SDK enforces before decryption.

Distinct from cryptography (see :mod:`ranbval_sdk.crypto`): this package decides *whether* a
credential may be used here, not *how* it is decrypted. Today that is the git-remote allowlist
(:mod:`ranbval_sdk.policy.repo`); future policy dimensions (IP, time windows) would live here too.
"""

from ranbval_sdk.policy.repo import (
    assert_repo_allowed_for_decrypt,
    fetch_repo_policy,
    get_git_remote_origin,
    normalize_git_remote_url,
)

__all__ = [
    "assert_repo_allowed_for_decrypt",
    "fetch_repo_policy",
    "get_git_remote_origin",
    "normalize_git_remote_url",
]
