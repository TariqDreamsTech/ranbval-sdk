import os
import sys
import threading
from queue import SimpleQueue

import openai

from ranbval_sdk.crypto import safe_decrypt
from ranbval_sdk.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.repo_policy import assert_repo_allowed_for_decrypt

_telemetry_queue: SimpleQueue | None = None
_telemetry_queue_lock = threading.Lock()


def _telemetry_enabled() -> bool:
    v = (os.environ.get("RANBVAL_TELEMETRY") or "1").strip().lower()
    return v not in ("0", "false", "no", "off")


def _ensure_telemetry_worker_started() -> None:
    global _telemetry_queue
    if _telemetry_queue is not None:
        return
    with _telemetry_queue_lock:
        if _telemetry_queue is None:
            _telemetry_queue = SimpleQueue()
            threading.Thread(
                target=_telemetry_worker_loop,
                daemon=True,
                name="ranbval-telemetry-worker",
            ).start()


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        return version("ranbval-sdk")
    except Exception:
        return ""


def _telemetry_worker_loop() -> None:
    import json
    import socket
    import time
    import urllib.request
    from urllib.parse import urlparse

    def get_git_remote():
        try:
            import subprocess

            return subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except Exception:
            return None

    def get_git_branch():
        try:
            import subprocess

            return subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except Exception:
            return None

    q = _telemetry_queue
    assert q is not None
    while True:
        client, model, response = q.get()
        usage = getattr(response, "usage", None)
        prompt_tokens = (
            getattr(usage, "prompt_tokens", 0) if usage is not None else 0
        )
        completion_tokens = (
            getattr(usage, "completion_tokens", 0) if usage is not None else 0
        )
        try:
            repo_path = os.getcwd()
            machine_name = socket.gethostname()
            git_url = get_git_remote()
            host = os.environ.get("RANBVAL_HOST", DEFAULT_RANBVAL_HOST)
            parsed = urlparse(host)
            transport = (parsed.scheme or "http").lower()
            ci_environment = any(
                os.environ.get(k)
                for k in (
                    "CI",
                    "GITHUB_ACTIONS",
                    "GITLAB_CI",
                    "BUILDKITE",
                    "CIRCLECI",
                    "JENKINS_URL",
                )
            )
            sec = {
                "event_kind": "llm.completion",
                "sdk_version": _sdk_version(),
                "client_platform": sys.platform,
                "python_version": sys.version.split()[0],
                "transport": transport,
                "vault_token_format": getattr(client, "_vault_token_format", "ranbval"),
                "git_branch": get_git_branch(),
                "ci_environment": bool(ci_environment),
            }
            prev_rt = client._telemetry_roundtrip_ms
            if prev_rt is not None:
                sec["roundtrip_ms"] = prev_rt

            payload = {
                "client_salt": client._ranbval_salt,
                "machine_name": machine_name,
                "repo_path": repo_path,
                "git_url": git_url,
                "model_used": model,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "security": sec,
            }

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{host}/api/telemetry",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    resp.read()
                    client._telemetry_roundtrip_ms = int(
                        (time.perf_counter() - t0) * 1000
                    )
                    print(
                        f"\n[Ranbval] Telemetry Synced: {model} "
                        f"({prompt_tokens}+{completion_tokens} tokens)"
                    )
        except Exception:
            pass


class SecureOpenAI(openai.OpenAI):
    """
    A drop-in replacement for `openai.OpenAI` that intercepts
    Ranbval (rbv1.*) encoded API keys from .env or args, decrypts
    them entirely in-memory at runtime, and seamlessly initializes
    the standard OpenAI client.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._telemetry_roundtrip_ms = None
        encoded_key = os.environ.get("OPENAI_API_KEY", "")
        secret = os.environ.get("RANBVAL_VAULT_SECRET", "ranbval")
        host = os.environ.get("RANBVAL_HOST", DEFAULT_RANBVAL_HOST)

        if not encoded_key:
            raise ValueError("No OPENAI_API_KEY found or provided.")

        if encoded_key.startswith("ranbval."):
            if not secret:
                raise ValueError(
                    "You supplied an Encrypted Ranbval Token but no RANBVAL_VAULT_SECRET "
                    "was found in .env or passed as an argument."
                )

            parts = encoded_key.split(".")
            if len(parts) < 2:
                raise ValueError("Invalid Ranbval token format.")
            client_salt = parts[1]
            assert_repo_allowed_for_decrypt(host, client_salt)

            decrypted_key = safe_decrypt(encoded_key, secret)

            super().__init__(api_key=decrypted_key, **kwargs)
            self._ranbval_salt = client_salt
            self._vault_token_format = "ranbval"
            self._patch_completions()
        else:
            super().__init__(api_key=encoded_key, **kwargs)
            self._ranbval_salt = None
            self._vault_token_format = "legacy_sk"

    def _patch_completions(self):
        telem_on = _telemetry_enabled()
        if telem_on:
            _ensure_telemetry_worker_started()

        original_create = self.chat.completions.create
        q = _telemetry_queue

        def patched_create(*args, **kwargs):
            # Read model before the network call so the post-response path is minimal.
            model = kwargs.get("model", "unknown")
            res = original_create(*args, **kwargs)
            if self._ranbval_salt and telem_on:
                q.put((self, model, res))
            return res

        self.chat.completions.create = patched_create
