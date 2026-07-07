"""AES-256-GCM vault-token cryptography and project-secret resolution.

Owns the decrypt path: parse a ``ranbval.{salt}.{blob}.ahsan`` token, derive the key
with PBKDF2-HMAC-SHA256 from the project secret + token salt, and AES-256-GCM-decrypt it
into a sealed :class:`~ranbval_sdk.crypto.secret_string.SecretString`. Also resolves the
project secret for an env var by prefix convention and keeps secrets out of ``os.environ``.
"""

import base64
import hmac
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ranbval_sdk.crypto.secret_string import SecretString
from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.exceptions import RanbvalConfigError, RanbvalDecryptError
from ranbval_sdk.crypto.repo_policy import assert_repo_allowed_for_decrypt

# PBKDF2-HMAC-SHA256 work factor. This value is part of the key derivation and is
# NOT encoded in the token, so it MUST stay in lock-step with the Ranbval control
# plane and the Node SDK — changing it here alone makes every existing vault token
# undecryptable. Raising it toward the OWASP-2023 figure (600_000) requires a
# coordinated, versioned-token migration across the server + both SDKs.
PBKDF2_ITERATIONS = 100_000

# Module-level store: project secrets keyed by prefix (e.g. "MYAPP", "RANBVAL").
# Populated by _store_project_secret(); os.environ entry is deleted immediately after.
# Attacker reading os.environ will not find RANBVAL_PROJECT_SECRET here.
_secret_store: dict[str, SecretString] = {}


def _store_project_secret(key: str, value: str) -> None:
    """Move a project secret from os.environ into the in-memory store and delete from env."""
    _secret_store[key] = SecretString(value)
    os.environ.pop(key, None)


def _recall_project_secret(key: str) -> str:
    """Return the stored secret value, or empty string if not found."""
    s = _secret_store.get(key)
    return s.use() if s is not None else ""


def derive_key(password: str, salt_str: str) -> bytes:
    """Derive a 32-byte AES key from the project secret and the token's 10-char salt."""
    salt = salt_str.encode() if salt_str else b"fallback-salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def _enforce_repo_allowlist_if_configured(client_salt: str) -> None:
    """Load policy from RANBVAL_HOST; when allowlist is non-empty, require matching git origin."""
    host = (os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).strip()
    assert_repo_allowed_for_decrypt(host, client_salt)


def safe_decrypt(copy_token: str, project_secret: str) -> SecretString:
    """
    Decrypt a Ranbval vault token using your project secret.

    ``project_secret`` is the ``ranbval-proj-…`` key shown once when you create a project
    (or regenerated from the dashboard under Project Secrets).

    Returns a SecretString — the plaintext is NEVER exposed via print/str/repr/logs.
    To actually pass the value to an API or SDK:

        secret = safe_decrypt(token, project_secret)
        client = openai.OpenAI(api_key=secret.use())   # ← only access point
    """
    packet_segments = copy_token.split(".")

    # FORMAT: ranbval . noise10 . blob . ahsan (4 parts)
    if len(packet_segments) != 4:
        # Compatibility: old 5-part format
        if len(packet_segments) == 5:
            header, noise, salt, blob, tail = packet_segments
            if not hmac.compare_digest(header, "ranbval"):
                raise RanbvalDecryptError(
                    "Corrupted cryptographic token identifier or signature matrix"
                )
            _enforce_repo_allowlist_if_configured(noise)
            key = derive_key(project_secret, salt)
            b64_payload = blob
        else:
            raise RanbvalDecryptError(
                f"E2E packet fragmentation error: expected 4 segments, got {len(packet_segments)}"
            )
    else:
        header = packet_segments[0]
        noise_salt = packet_segments[1]
        b64_payload = packet_segments[2]
        tail_sig = packet_segments[3]

        if not hmac.compare_digest(header, "ranbval") or not hmac.compare_digest(
            tail_sig, "ahsan"
        ):
            raise RanbvalDecryptError(
                "Corrupted cryptographic token identifier or signature matrix"
            )

        _enforce_repo_allowlist_if_configured(noise_salt)
        key = derive_key(project_secret, noise_salt)

    # 2. Decode payload (IV + Ciphertext)
    try:
        # Add padding if needed
        pad = "=" * (-len(b64_payload) % 4)
        # Use urlsafe_b64decode to handle tokens containing '-' and '_'
        packed = base64.urlsafe_b64decode(b64_payload + pad)
        iv = packed[:12]
        ciphertext = packed[12:]

        # 3. Decrypt payload
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
        plaintext = decrypted.decode("utf-8")

        # TTL check — format: "actual_secret\nranbval-expiry:1234567890"
        # Backward compatible: old tokens without expiry line work unchanged.
        if "\nranbval-expiry:" in plaintext:
            body, _, expiry_line = plaintext.rpartition("\nranbval-expiry:")
            try:
                expiry_ts = int(expiry_line.strip())
                if time.time() > expiry_ts:
                    raise RanbvalDecryptError(
                        "Vault token has expired. "
                        "Generate a new one from the Ranbval dashboard."
                    )
            except ValueError as ttl_err:
                if "expired" in str(ttl_err):
                    raise
                # Malformed expiry line — treat as no TTL (safe fallback)
                body = plaintext
            plaintext = body

        return SecretString(plaintext)
    except (ValueError, KeyError):
        raise
    except Exception as e:
        raise RanbvalDecryptError(
            "Decryption failed! Did you provide the correct E2E vault secret?"
        ) from e


def _migrate_from_env(key: str) -> str:
    """If key is in os.environ, move it to the secret store and return its value."""
    value = os.environ.get(key, "").strip()
    if value:
        _store_project_secret(key, value)  # deletes from os.environ immediately
    return value


def _find_project_secret_for(env_var: str) -> str:
    """
    Auto-discover the project secret for *env_var* using the prefix convention.

    Resolution order:
    1. ``{PREFIX}_PROJECT_SECRET``  where PREFIX is the longest matching env-var prefix
       e.g. ``MYAPP_OPENAI_KEY`` → looks for ``MYAPP_PROJECT_SECRET``
    2. ``RANBVAL_PROJECT_SECRET``   — global fallback / single-project setups

    On first access: migrates any matching os.environ entry into the in-memory
    secret store and removes it from os.environ so it is no longer readable there.

    Raises ``ValueError`` if nothing is found.
    """
    parts = env_var.upper().split("_")
    for i in range(len(parts) - 1, 0, -1):
        candidate = "_".join(parts[:i]) + "_PROJECT_SECRET"
        value = _recall_project_secret(candidate) or _migrate_from_env(candidate)
        if value:
            return value

    # Global fallback
    fallback = _recall_project_secret("RANBVAL_PROJECT_SECRET") or _migrate_from_env(
        "RANBVAL_PROJECT_SECRET"
    )
    if fallback:
        return fallback

    prefix_hint = parts[0] + "_PROJECT_SECRET"
    raise RanbvalConfigError(
        f"No project secret found for {env_var!r}. "
        f"Add {prefix_hint} (or RANBVAL_PROJECT_SECRET) to your .ranbval file."
    )


def decrypt_key(env_var: str) -> SecretString:
    """
    Read a vault token from ``env_var`` and decrypt it — project secret discovered automatically.

    Convention: name your env vars with a project prefix and store the matching project
    secret under ``{PREFIX}_PROJECT_SECRET``. Works for any number of projects in one file::

        # .ranbval
        MYAPP_PROJECT_SECRET=ranbval-proj-xxx
        MYAPP_OPENAI_KEY=ranbval.xxx.…ahsan

        BILLING_PROJECT_SECRET=ranbval-proj-yyy
        BILLING_STRIPE_KEY=ranbval.yyy.…ahsan

        # app.py
        from ranbval_sdk import load_ranbval, decrypt_key
        load_ranbval()
        openai_key = decrypt_key("MYAPP_OPENAI_KEY")    # finds MYAPP_PROJECT_SECRET
        stripe_key = decrypt_key("BILLING_STRIPE_KEY")  # finds BILLING_PROJECT_SECRET

    If the value is not a vault token (does not start with ``ranbval.``), it is returned
    as-is wrapped in SecretString — so plain keys and vault tokens are handled the same way.

    Raises:
        ValueError  — env var missing, no project secret found, or decryption failed
    """
    token = os.environ.get(env_var, "").strip()
    if not token:
        raise RanbvalConfigError(
            f"{env_var!r} is not set. Add it to your .ranbval file or environment."
        )

    # Plain (non-vault) key — return as-is
    if not token.startswith("ranbval."):
        return SecretString(token)

    project_secret = _find_project_secret_for(env_var)
    return safe_decrypt(token, project_secret)
