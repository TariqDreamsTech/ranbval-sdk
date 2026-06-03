import os
import sys
import threading
from typing import Type, Any, Optional

from ranbval_sdk.crypto import safe_decrypt
from ranbval_sdk.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.telemetry import emit_telemetry


def _send_telemetry(salt: str, model: str, host_url: str) -> None:
    """Background thread target: one telemetry row for auto-patched SDK calls."""
    emit_telemetry(
        client_salt=salt,
        model_used=model,
        host_url=host_url,
        event_kind="platform.invocation",
        background=False,
    )

def build_secure_client(SDKClass: Type[Any], env_var_name: str, key_kwarg: str, method_path_to_patch: Optional[str] = None) -> Type[Any]:
    """
    A Universal Factory that creates a Zero-Memory wrapper around ANY python SDK class.
    It decrypts the API key exactly when constructed and injects basic platform telemetry.
    """
    class SecurePlatformProxy(SDKClass):
        def __init__(self, *args, **kwargs):
            encoded_key = os.environ.get(env_var_name, "")
            # Accept RANBVAL_PROJECT_SECRET (new) or RANBVAL_VAULT_SECRET (legacy alias)
            secret = (
                os.environ.get("RANBVAL_PROJECT_SECRET")
                or os.environ.get("RANBVAL_VAULT_SECRET")
                or ""
            ).strip()
            host = os.environ.get("RANBVAL_HOST", DEFAULT_RANBVAL_HOST)

            if not encoded_key:
                raise ValueError(f"No {env_var_name} found or provided.")

            # Deprecation: RANBVAL_VAULT_SECRET is a legacy alias for RANBVAL_PROJECT_SECRET.
            if not secret and os.environ.get("RANBVAL_VAULT_SECRET"):
                print(
                    "[Ranbval] DeprecationWarning: RANBVAL_VAULT_SECRET is deprecated. "
                    "Rename it to RANBVAL_PROJECT_SECRET.",
                    file=sys.stderr,
                )
                secret = os.environ.get("RANBVAL_VAULT_SECRET", "").strip()

            if encoded_key.startswith("ranbval."):
                if not secret:
                    raise ValueError(
                        f"Found encoded vault token for {env_var_name} but RANBVAL_PROJECT_SECRET is missing. "
                        "Set it in .ranbval or your environment."
                    )

                decrypted_key = safe_decrypt(encoded_key, secret)
                kwargs[key_kwarg] = decrypted_key.use()
                super().__init__(*args, **kwargs)
                
                self._ranbval_salt = encoded_key.split(".")[1]
                self._vault_token_format = "ranbval"
                self._ranbval_host = host
                
                # Apply arbitrary deep patching if provided (e.g. 'messages.create' for Anthropic)
                if method_path_to_patch:
                    self._patch_methods(method_path_to_patch)
            else:
                super().__init__(*args, **kwargs)
                self._ranbval_salt = None

        def _patch_methods(self, path: str):
            parts = path.split('.')
            target_obj = self
            for part in parts[:-1]:
                target_obj = getattr(target_obj, part, None)
                if target_obj is None:
                    return

            orig_method = getattr(target_obj, parts[-1], None)
            if not callable(orig_method):
                return

            def patched_method(*args, **kwargs):
                res = orig_method(*args, **kwargs)
                if self._ranbval_salt:
                    threading.Thread(
                        target=_send_telemetry,
                        args=(self._ranbval_salt, f"{SDKClass.__name__} API", self._ranbval_host),
                        daemon=True,
                    ).start()
                return res

            setattr(target_obj, parts[-1], patched_method)

    return SecurePlatformProxy

