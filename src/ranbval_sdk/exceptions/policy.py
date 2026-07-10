"""Provenance / repo-allowlist policy errors.

Mirrors :mod:`ranbval_sdk.policy`.
"""

from __future__ import annotations

from ranbval_sdk.exceptions.base import RanbvalError


class RepoNotAllowedError(RanbvalError, PermissionError):
    """The current git remote is not in the project's allowlist, so decryption is refused."""

    default_code = "repo_denied"


class RepoPolicyError(RanbvalError, PermissionError):
    """The repository policy could not be loaded or verified before decryption."""

    default_code = "repo_policy_unavailable"
