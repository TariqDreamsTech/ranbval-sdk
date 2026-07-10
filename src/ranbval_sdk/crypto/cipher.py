"""AES-256-GCM vault-token cryptography and project-secret resolution.

Owns the decrypt path: parse a ``ranbval.{salt}.{blob}.ahsan`` token, derive the key
with PBKDF2-HMAC-SHA256 from the project secret + token salt, and AES-256-GCM-decrypt it
into a sealed :class:`~ranbval_sdk.crypto.secret_string.SecretString`. Also resolves the
project secret for an env var by prefix convention and keeps secrets out of ``os.environ``.
"""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.crypto.secret_string import SecretString
from ranbval_sdk.exceptions import RanbvalConfigError, RanbvalDecryptError
from ranbval_sdk.policy.repo import assert_repo_allowed_for_decrypt

# Fixed marker that prefixes every vault token: ``ranbval.<salt>.<blob>.<label>``.
# It identifies the wire format — it is public and carries no security by itself
# (integrity comes from AES-256-GCM, not from this marker).
_TOKEN_MARKER = "ranbval"

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
    # The project secret arrives as a _ProtectedStr (from get_project_key → .use()). Call the
    # base str.encode directly so this SDK-internal key derivation is not tripped by extraction
    # enforcement — same deliberate-internal-read pattern the value type uses elsewhere.
    return kdf.derive(str.encode(password))


def _enforce_repo_allowlist_if_configured(client_salt: str) -> None:
    """Load policy from RANBVAL_HOST; when allowlist is non-empty, require matching git origin."""
    host = (os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).strip()
    assert_repo_allowed_for_decrypt(host, client_salt)


@dataclass(frozen=True)
class _ParsedToken:
    """The decrypt-relevant parts of a vault token: the credential salt and the ciphertext blob."""

    salt: str
    blob: str


def _parse_token(token: str) -> _ParsedToken:
    """Split ``ranbval.<salt>.<blob>.<label>`` into its parts.

    The trailing ``<label>`` is an opaque, human-readable tag (e.g. ``ahsan``, ``stripe``);
    it is not validated because it carries no cryptographic meaning. The 5-part form is the
    legacy layout kept for backward compatibility. Any other shape is a format error.
    """
    parts = token.split(".")
    if parts[0] != _TOKEN_MARKER:
        raise RanbvalDecryptError(
            "Invalid token: not a Ranbval vault token "
            "(expected it to start with 'ranbval.').",
            code="invalid_token_format",
        )
    if len(parts) == 4:  # ranbval.<salt>.<blob>.<label>
        return _ParsedToken(salt=parts[1], blob=parts[2])
    if len(parts) == 5:  # legacy: ranbval.<noise>.<salt>.<blob>.<label>
        return _ParsedToken(salt=parts[2], blob=parts[3])
    raise RanbvalDecryptError(
        f"Invalid token format: expected 'ranbval.<salt>.<blob>.<label>', "
        f"got {len(parts)} dot-separated segments.",
        code="invalid_token_format",
    )


def _strip_expiry_and_check_ttl(plaintext: str) -> str:
    """Enforce an optional TTL line and return the secret body.

    Layout: ``"<secret>\\nranbval-expiry:<unix_ts>"``. Tokens without the line are
    returned unchanged (backward compatible); a malformed expiry line is treated as
    "no TTL" rather than a hard failure.
    """
    if "\nranbval-expiry:" not in plaintext:
        return plaintext
    body, _, expiry_line = plaintext.rpartition("\nranbval-expiry:")
    try:
        expiry_ts = int(expiry_line.strip())
    except ValueError:
        return body  # malformed expiry — safe fallback: ignore the TTL
    if time.time() > expiry_ts:
        raise RanbvalDecryptError(
            "Vault token has expired. Generate a new one from the Ranbval dashboard.",
            code="token_expired",
        )
    return body


def safe_decrypt(
    copy_token: str, project_secret: str, *, label: str = "secret"
) -> SecretString:
    """
    Decrypt a Ranbval vault token using your project secret.

    ``project_secret`` is the ``ranbval-proj-…`` key shown once when you create a project
    (or regenerated from the dashboard under Project Secrets). ``label`` names the resulting
    secret (used by the audit log and by reveal scopes); ``decrypt_key`` passes the env-var name.

    Returns a SecretString — the plaintext is NEVER exposed via print/str/repr/logs.
    To actually pass the value to an API or SDK:

        secret = safe_decrypt(token, project_secret)
        client = openai.OpenAI(api_key=secret.use())   # ← only access point
    """
    parsed = _parse_token(copy_token)

    # Provenance gate (server-controlled) runs before any crypto work.
    _enforce_repo_allowlist_if_configured(parsed.salt)

    key = derive_key(project_secret, parsed.salt)
    try:
        pad = "=" * (-len(parsed.blob) % 4)  # restore base64url padding if trimmed
        packed = base64.urlsafe_b64decode(parsed.blob + pad)
        iv, ciphertext = packed[:12], packed[12:]
        plaintext = AESGCM(key).decrypt(iv, ciphertext, None).decode("utf-8")
    except RanbvalDecryptError:
        raise
    except Exception as e:
        # Wrong project secret, tampered ciphertext, or malformed payload all land here.
        raise RanbvalDecryptError(
            "Decryption failed — check that the project secret matches this token "
            "and that the token is not corrupted.",
            code="decrypt_failed",
        ) from e

    return SecretString(_strip_expiry_and_check_ttl(plaintext), label=label)


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

    A key declared under ``PROXY_`` is refused here: its plaintext must never reach the
    client, so use :func:`ranbval_sdk.proxy_request` with :func:`ranbval_sdk.proxy_token`
    instead — the real key is injected server-side and never returned to your process.

    Raises:
        ValueError  — env var missing, no project secret found, or decryption failed;
                      or the key is declared ``PROXY_`` (use ``proxy_request`` instead)
    """
    from ranbval_sdk.config import manifest

    if manifest.is_proxy(env_var):
        raise RanbvalConfigError(
            f"{env_var!r} is a PROXY_ secret — its plaintext must never reach the client. "
            f"Use proxy_request(token=proxy_token({env_var!r}), ...) instead; the real key "
            "is decrypted and injected server-side.",
            code="proxy_only",
        )

    if manifest.is_public(env_var):
        raise RanbvalConfigError(
            f"{env_var!r} is a PUBLIC_ value, not a secret — read it with public({env_var!r}). "
            "decrypt_key() is only for SECRET_ vault tokens.",
            code="not_a_secret",
        )

    token = os.environ.get(env_var, "").strip()
    if not token:
        raise RanbvalConfigError(
            f"{env_var!r} is not set. Add it to your .ranbval file or environment."
        )

    # Plain (non-vault) key — return as-is (labelled by env var for audit / reveal scopes)
    if not token.startswith("ranbval."):
        return SecretString(token, label=env_var)

    project_secret = _find_project_secret_for(env_var)
    started = time.perf_counter()
    secret = safe_decrypt(token, project_secret, label=env_var)
    roundtrip_ms = (time.perf_counter() - started) * 1000.0
    _auto_report_usage(env_var, roundtrip_ms)
    return secret


def _auto_report_usage(env_var: str, roundtrip_ms: float) -> None:
    """Report this decrypt to the Live Monitor automatically — no manual ``emit_telemetry``.

    Usage is adaptively aggregated (first use of a credential is sent immediately with its
    decrypt latency; routine repeats are counted and flushed as one aggregated event carrying an
    ``item_count`` weight). The caller can still call ``emit_telemetry`` directly for richer
    custom events. Any failure here never affects decryption.
    """
    try:
        from ranbval_sdk.telemetry.client import emit_telemetry, salt_from_ranbval_token
        from ranbval_sdk.telemetry.sampling import usage_sampler

        salt = salt_from_ranbval_token(os.environ.get(env_var, ""))
        if not salt:
            return
        item_count = usage_sampler.decide(salt)
        if item_count <= 0:
            return  # counted locally; flushed as an aggregate later
        emit_telemetry(
            client_salt=salt,
            model_used="secret.access",
            event_kind="platform.invocation",
            item_count=item_count,
            roundtrip_ms=roundtrip_ms,
            background=True,
        )
    except Exception:
        pass
