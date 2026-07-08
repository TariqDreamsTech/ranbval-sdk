"""Universal secure-client factory.

:func:`build_secure_client` subclasses **your** vendor SDK class (OpenAI, Anthropic,
Stripe, …) so the API key is decrypted at construction and usage telemetry fires on the
patched method — Ranbval ships zero vendor dependencies. :func:`secure_client` (in
``integrations.factory``) is the one-call convenience wrapper over this.
"""

from __future__ import annotations

import os
import warnings
from typing import Any

from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.crypto import safe_decrypt


def _report_invocation(salt: str, model: str, host_url: str) -> None:
    """Report one auto-patched SDK call — aggregated through the shared usage sampler.

    Uses the same adaptive sampling as ``decrypt_key`` (first use sent immediately, repeats
    counted and flushed as one aggregated event) so a hot call loop doesn't spawn a thread
    and a POST per call. Best-effort: any failure is swallowed.
    """
    try:
        from ranbval_sdk.telemetry.settings import telemetry_disabled

        if telemetry_disabled():
            return

        from ranbval_sdk.telemetry.client import emit_telemetry
        from ranbval_sdk.telemetry.sampling import usage_sampler

        item_count = usage_sampler.decide(salt)
        if item_count <= 0:
            return  # counted locally; flushed as an aggregate later
        emit_telemetry(
            client_salt=salt,
            model_used=model,
            host_url=host_url,
            event_kind="platform.invocation",
            item_count=item_count,
            background=True,
        )
    except Exception:
        pass


def build_secure_client(
    sdk_class: type[Any],
    env_var: str,
    key_kwarg: str,
    method_path_to_patch: str | None = None,
) -> type[Any]:
    """
    Build a secure subclass wrapping ANY Python SDK class.

    The returned class decrypts the API key from ``env_var`` exactly when constructed,
    injects it via ``key_kwarg``, and — if ``method_path_to_patch`` is given — reports
    aggregated telemetry each time that method is called::

        SecureAnthropic = build_secure_client(
            anthropic.Anthropic, env_var="ANTHROPIC_API_KEY", key_kwarg="api_key",
        )
        client = SecureAnthropic()
    """

    class SecurePlatformProxy(sdk_class):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            encoded_key = os.environ.get(env_var, "")
            host = os.environ.get("RANBVAL_HOST", DEFAULT_RANBVAL_HOST)

            if not encoded_key:
                raise ValueError(f"No {env_var} found or provided.")

            secret = self._resolve_project_secret()

            if encoded_key.startswith("ranbval."):
                if not secret:
                    raise ValueError(
                        f"Found encoded vault token for {env_var} but "
                        "RANBVAL_PROJECT_SECRET is missing. "
                        "Set it in .ranbval or your environment."
                    )
                decrypted_key = safe_decrypt(encoded_key, secret)
                kwargs[key_kwarg] = decrypted_key.use()
                super().__init__(*args, **kwargs)

                self._ranbval_salt = encoded_key.split(".")[1]
                self._ranbval_host = host
                if method_path_to_patch:
                    self._patch_methods(method_path_to_patch)
            else:
                super().__init__(*args, **kwargs)
                self._ranbval_salt = None

        @staticmethod
        def _resolve_project_secret() -> str:
            """Read RANBVAL_PROJECT_SECRET, honouring the legacy RANBVAL_VAULT_SECRET alias."""
            secret = (os.environ.get("RANBVAL_PROJECT_SECRET") or "").strip()
            if secret:
                return secret
            legacy = (os.environ.get("RANBVAL_VAULT_SECRET") or "").strip()
            if legacy:
                warnings.warn(
                    "RANBVAL_VAULT_SECRET is deprecated; rename it to RANBVAL_PROJECT_SECRET.",
                    DeprecationWarning,
                    stacklevel=3,
                )
            return legacy

        def _patch_methods(self, path: str) -> None:
            parts = path.split(".")
            target_obj: Any = self
            for part in parts[:-1]:
                target_obj = getattr(target_obj, part, None)
                if target_obj is None:
                    return

            orig_method = getattr(target_obj, parts[-1], None)
            if not callable(orig_method):
                return

            model = f"{sdk_class.__name__} API"

            def patched_method(*args: Any, **kwargs: Any) -> Any:
                res = orig_method(*args, **kwargs)
                if self._ranbval_salt:
                    _report_invocation(self._ranbval_salt, model, self._ranbval_host)
                return res

            setattr(target_obj, parts[-1], patched_method)

    return SecurePlatformProxy
