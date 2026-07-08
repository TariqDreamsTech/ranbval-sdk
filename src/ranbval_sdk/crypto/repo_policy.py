"""Backwards-compatibility shim.

Repo-allowlist enforcement moved to :mod:`ranbval_sdk.policy.repo` (it is provenance policy,
not cryptography). This module re-exports it so ``from ranbval_sdk.crypto.repo_policy import …``
keeps working.
"""

from ranbval_sdk.policy.repo import (
    _origin_allowed,
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
    "_origin_allowed",
]
