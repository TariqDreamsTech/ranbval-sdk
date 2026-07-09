"""Configuration: loading ``.ranbval`` files and accessing the values in them.

- :mod:`~ranbval_sdk.config.loader` — parse and merge layered ``.ranbval*`` files into the env.
- :mod:`~ranbval_sdk.config.access` — imperative access (``Vault``, ``inject``, ``secrets``).
- :mod:`~ranbval_sdk.config.declarative` — class-based access (``Secret``, ``SecretConfig``).
"""

from ranbval_sdk.config.access import (
    SecretProvider,
    Vault,
    env,
    inject,
    is_proxy,
    is_public,
    iter_secrets,
    proxy_token,
    public,
    public_config,
    secrets,
)
from ranbval_sdk.config.declarative import Secret, SecretConfig
from ranbval_sdk.config.loader import (
    find_ranbval_directory,
    find_ranbval_file,
    get_project_key,
    load_ranbval,
    resolve_ranbval_mode,
)
from ranbval_sdk.config.reveal import (
    clear_reveal_requirements,
    require_reveal_scope,
    reveal_scope,
)

__all__ = [
    "load_ranbval",
    "get_project_key",
    "find_ranbval_file",
    "find_ranbval_directory",
    "resolve_ranbval_mode",
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
    "clear_reveal_requirements",
    "Secret",
    "SecretConfig",
    "SecretProvider",
]
