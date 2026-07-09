"""Ranbval SDK — keep API secrets out of plaintext config.

Encrypted vault tokens live in your ``.ranbval`` file; the SDK decrypts them only at the
moment of use and never lets the plaintext reach a ``print``, log, or ``repr``.

Public API, grouped by concern (each name re-exported from its home subpackage):

- **Config** (:mod:`ranbval_sdk.config`) — ``load_ranbval``, ``get_project_key``,
  ``find_ranbval_file``, ``find_ranbval_directory``, ``resolve_ranbval_mode``.
- **Access** (:mod:`ranbval_sdk.config.access`) — ``Vault``, ``env``, ``inject``,
  ``secrets``, ``iter_secrets``, ``public``, ``public_config``, ``is_public``,
  ``is_proxy``, ``proxy_token``, ``Secret``, ``SecretConfig``, ``SecretProvider``.
- **Crypto** (:mod:`ranbval_sdk.crypto`) — ``safe_decrypt``, ``decrypt_key``,
  ``SecretString``, ``get_audit_log``, ``clear_audit_log``, ``audit_scope``.
- **Telemetry** (:mod:`ranbval_sdk.telemetry`) — ``emit_telemetry``, ``aemit_telemetry``,
  ``track``, ``tracked``.
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
    is_proxy,
    is_public,
    iter_secrets,
    load_ranbval,
    proxy_token,
    public,
    public_config,
    require_reveal_scope,
    resolve_ranbval_mode,
    reveal_scope,
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
from ranbval_sdk.integrations.proxy import aproxy_request, proxy_request
from ranbval_sdk.telemetry import (
    aemit_telemetry,
    emit_telemetry,
    install_access_monitor,
    track,
    tracked,
    uninstall_access_monitor,
)

__version__ = "2.2.0"

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
    "is_proxy",
    "proxy_token",
    "reveal_scope",
    "require_reveal_scope",
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
    "install_access_monitor",
    "uninstall_access_monitor",
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
