import os
import sys
import threading
import json
import socket
import time
import urllib.request
from urllib.parse import urlparse
from typing import Type, Any, Optional

from ranbval_sdk.crypto import safe_decrypt
from ranbval_sdk.defaults import DEFAULT_RANBVAL_HOST, warn_telemetry_send_failed

def _get_git_remote() -> str | None:
    try:
        import subprocess
        return subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return None

def _get_git_branch() -> str | None:
    try:
        import subprocess
        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return None

def _sdk_version() -> str:
    try:
        from importlib.metadata import version
        return version("ranbval-sdk")
    except Exception:
        return ""

def _send_telemetry(salt: str, model: str, host_url: str):
    """Fire-and-forget telemetry specifically for generic platform invocations (no token counts)."""
    try:
        repo_path = os.getcwd()
        machine_name = socket.gethostname()
        git_url = _get_git_remote()
        
        parsed = urlparse(host_url)
        transport = (parsed.scheme or "http").lower()
        ci_environment = any(
            os.environ.get(k)
            for k in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL")
        )
        
        sec = {
            "event_kind": "platform.invocation",
            "sdk_version": _sdk_version(),
            "client_platform": sys.platform,
            "python_version": sys.version.split()[0],
            "transport": transport,
            "vault_token_format": "ranbval",
            "git_branch": _get_git_branch(),
            "ci_environment": bool(ci_environment),
        }

        payload = {
            "client_salt": salt,
            "machine_name": machine_name,
            "repo_path": repo_path,
            "git_url": git_url,
            "model_used": model, # E.g., "api.anthropic.com" or "api.stripe.com"
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "security": sec,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{host_url}/api/telemetry",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                print(f"\n[Ranbval] Platform Telemetry Synced: {model}")
    except Exception as e:
        warn_telemetry_send_failed(host_url, e)

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

