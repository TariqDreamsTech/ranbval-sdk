"""Parse the Ranbval vault-token wire format.

Token shape: ``ranbval.<salt>.<blob>.<label>``. Only the non-reversible ``<salt>`` segment
is ever needed off-token (it identifies the credential to the control plane); the ciphertext
is never parsed here.
"""

from __future__ import annotations


def salt_from_ranbval_token(raw: str) -> str | None:
    """Return the client-salt segment from ``ranbval.<salt>.<cipher>.<label>`` or ``None``."""
    if not raw or not str(raw).startswith("ranbval."):
        return None
    parts = str(raw).split(".")
    if len(parts) < 2:
        return None
    return parts[1]
