"""
Ranbval SDK — keep API secrets out of plaintext config.

- ``load_ranbval()``    load layered .ranbval* files into os.environ
- ``safe_decrypt()``   decrypt a vault token locally (with repo allowlist)
- ``decrypt_key()``    decrypt by env var name — auto-discovers project secret from prefix
- ``proxy_request()``  route any HTTP request through Ranbval secure proxy (secret never local)
- ``emit_telemetry()`` log a request to the Ranbval Live Monitor
"""

from ranbval_sdk.crypto import safe_decrypt, decrypt_key
from ranbval_sdk.proxy import proxy_request, aproxy_request, ProxyError

from ranbval_sdk.dot_ranbval import (
    find_ranbval_directory,
    find_ranbval_file,
    get_project_key,
    load_ranbval,
    resolve_ranbval_mode,
    # High-level, ergonomic config access
    Vault,
    env,
    inject,
    secrets,
    iter_secrets,
    Secret,
    SecretConfig,
    SecretProvider,
)

from ranbval_sdk.telemetry import emit_telemetry, aemit_telemetry, track, tracked

from ranbval_sdk.secret_string import SecretString

from ranbval_sdk.audit import get_audit_log, clear_audit_log, audit_scope

from .integrations.factory import secure_client
from .integrations.universal import build_secure_client

__all__ = [
    # Core
    "emit_telemetry",
    "safe_decrypt",
    "decrypt_key",
    "load_ranbval",
    "get_project_key",
    "find_ranbval_file",
    "find_ranbval_directory",
    "resolve_ranbval_mode",
    # Secret wrapper
    "SecretString",
    # HTTP integrations
    "build_secure_client",
    "secure_client",
    # Secure proxy
    "proxy_request",
    "aproxy_request",
    "ProxyError",
    # Telemetry ergonomics
    "track",
    "tracked",
    "aemit_telemetry",
    # Audit
    "get_audit_log",
    "clear_audit_log",
    "audit_scope",
    # High-level ergonomic API
    "Vault",
    "env",
    "inject",
    "secrets",
    "iter_secrets",
    "Secret",
    "SecretConfig",
    "SecretProvider",
]
