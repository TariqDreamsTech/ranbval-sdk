import os
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
            secret = os.environ.get("RANBVAL_VAULT_SECRET", "ranbval")
            host = os.environ.get("RANBVAL_HOST", DEFAULT_RANBVAL_HOST)
            
            if not encoded_key:
                raise ValueError(f"No {env_var_name} found or provided.")
                
            if encoded_key.startswith("ranbval."):
                if not secret:
                    raise ValueError(f"Found encoded Vault key for {env_var_name} but RANBVAL_VAULT_SECRET is missing!")
                
                # Zero-Memory Decryption
                decrypted_key = safe_decrypt(encoded_key, secret)
                
                # Dynamically set the exact keyword argument this specific SDK expects
                kwargs[key_kwarg] = decrypted_key
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
                target_obj = getattr(target_obj, part)
                
            orig_method = getattr(target_obj, parts[-1])
            
            def patched_method(*args, **kwargs):
                res = orig_method(*args, **kwargs)
                if self._ranbval_salt:
                    # Fire basic platform telemetry in the background
                    threading.Thread(
                        target=_send_telemetry,
                        args=(self._ranbval_salt, f"{SDKClass.__name__} API", self._ranbval_host),
                        daemon=True
                    ).start()
                return res
                
            setattr(target_obj, parts[-1], patched_method)

    return SecurePlatformProxy

