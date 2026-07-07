"""Configuration: loading ``.ranbval`` files and accessing the values in them.

- :mod:`~ranbval_sdk.config.loader` — parse and merge layered ``.ranbval*`` files into the env.
- :mod:`~ranbval_sdk.config.access` — ergonomic access (``Vault``, ``inject``, ``secrets``, ``Secret``).
"""

from ranbval_sdk.config.access import (
    Secret,
    SecretConfig,
    SecretProvider,
    Vault,
    env,
    inject,
    iter_secrets,
    secrets,
)
from ranbval_sdk.config.loader import (
    find_ranbval_directory,
    find_ranbval_file,
    get_project_key,
    load_ranbval,
    resolve_ranbval_mode,
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
    "Secret",
    "SecretConfig",
    "SecretProvider",
]
