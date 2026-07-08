"""Ranbval SDK — keep API secrets out of plaintext config.

Encrypted vault tokens live in your ``.ranbval`` file; the SDK decrypts them only at the
moment of use and never lets the plaintext reach a ``print``, log, or ``repr``.

Public API, grouped by concern (each name re-exported from its home subpackage):

- **Config** (:mod:`ranbval_sdk.config`) — ``load_ranbval``, ``get_project_key``,
  ``find_ranbval_file``, ``find_ranbval_directory``, ``resolve_ranbval_mode``.
- **Access** (:mod:`ranbval_sdk.config.access`) — ``Vault``, ``env``, ``inject``,
  ``secrets``, ``iter_secrets``, ``public``, ``public_config``, ``is_public``,
  ``Secret``, ``SecretConfig``, ``SecretProvider``.
- **Crypto** (:mod:`ranbval_sdk.crypto`) — ``safe_decrypt``, ``decrypt_key``,
  ``SecretString``, ``get_audit_log``, ``clear_audit_log``, ``audit_scope``.
- **Telemetry** (:mod:`ranbval_sdk.telemetry`) — ``emit_telemetry``, ``aemit_telemetry``,
  ``track``, ``tracked``.
- **Integrations** (:mod:`ranbval_sdk.integrations`) — ``secure_client``, ``build_secure_client``.
- **Secure proxy** (:mod:`ranbval_sdk.integrations.proxy`) — ``proxy_request``, ``aproxy_request``.
- **Exceptions** (:mod:`ranbval_sdk.exceptions`) — ``RanbvalError`` and its subclasses.

Basic use::

    from ranbval_sdk import load_ranbval, decrypt_key
    load_ranbval()
    client = openai.OpenAI(api_key=decrypt_key("OPENAI_API_KEY").use())
"""

from ranbval_sdk.config import (
    Secret,
    SecretConfig,
    SecretProvider,
    Vault,
    env,
    find_ranbval_directory,
    find_ranbval_file,
    get_project_key,
    inject,
    is_public,
    iter_secrets,
    load_ranbval,
    public,
    public_config,
    resolve_ranbval_mode,
    secrets,
)
from ranbval_sdk.crypto import (
    SecretString,
    audit_scope,
    clear_audit_log,
    decrypt_key,
    get_audit_log,
    safe_decrypt,
)
from ranbval_sdk.exceptions import (
    MissingKeyError,
    ProxyError,
    RanbvalConfigError,
    RanbvalDecryptError,
    RanbvalError,
    RepoNotAllowedError,
    RepoPolicyError,
)
from ranbval_sdk.integrations.factory import secure_client
from ranbval_sdk.integrations.proxy import aproxy_request, proxy_request
from ranbval_sdk.integrations.universal import build_secure_client
from ranbval_sdk.telemetry import aemit_telemetry, emit_telemetry, track, tracked

__version__ = "1.4.1"

__all__ = [
    # Config
    "load_ranbval",
    "get_project_key",
    "find_ranbval_file",
    "find_ranbval_directory",
    "resolve_ranbval_mode",
    # Access
    "Vault",
    "env",
    "inject",
    "secrets",
    "iter_secrets",
    "public",
    "public_config",
    "is_public",
    "Secret",
    "SecretConfig",
    "SecretProvider",
    # Crypto
    "safe_decrypt",
    "decrypt_key",
    "SecretString",
    "get_audit_log",
    "clear_audit_log",
    "audit_scope",
    # Telemetry
    "emit_telemetry",
    "aemit_telemetry",
    "track",
    "tracked",
    # Integrations
    "secure_client",
    "build_secure_client",
    # Secure proxy
    "proxy_request",
    "aproxy_request",
    # Exceptions
    "RanbvalError",
    "RanbvalDecryptError",
    "RanbvalConfigError",
    "MissingKeyError",
    "RepoNotAllowedError",
    "RepoPolicyError",
    "ProxyError",
]
