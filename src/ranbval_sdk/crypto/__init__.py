"""Cryptography and sealed-secret handling.

- :mod:`~ranbval_sdk.crypto.cipher` — AES-256-GCM vault-token decrypt + project-secret resolution.
- :mod:`~ranbval_sdk.crypto.secret_string` — the sealed :class:`SecretString` value type.
- :mod:`~ranbval_sdk.crypto.audit` — in-memory log of every ``SecretString.use()``.
"""

from ranbval_sdk.crypto.audit import (
    audit_scope,
    clear_audit_log,
    get_audit_log,
    record_access,
)
from ranbval_sdk.crypto.cipher import decrypt_key, derive_key, safe_decrypt
from ranbval_sdk.crypto.secret_string import (
    SecretString,
    install_output_guards,
    is_enforced,
    set_enforcement,
)

__all__ = [
    "safe_decrypt",
    "decrypt_key",
    "derive_key",
    "SecretString",
    "install_output_guards",
    "set_enforcement",
    "is_enforced",
    "get_audit_log",
    "clear_audit_log",
    "audit_scope",
    "record_access",
]
