"""Declarative secret configuration — the class-based access style.

Complements the imperative API in :mod:`ranbval_sdk.config.access` (``Vault`` / ``inject`` /
``secrets``): here you *declare* a config class whose fields are :class:`Secret` descriptors,
decrypted lazily and cached per subclass. Both styles resolve through the same
``config.access._resolve`` so behavior and sealing defaults stay identical.

::

    class Config(SecretConfig):
        openai = Secret("OPENAI_API_KEY")
        stripe = Secret("STRIPE_KEY", reveal=True)   # plaintext str

    Config.openai   # -> SecretString (cached on the class)
    Config.stripe   # -> plaintext str
"""

from __future__ import annotations

from typing import Any, ClassVar

from ranbval_sdk.config.access import _ensure_env_loaded, _resolve
from ranbval_sdk.crypto.secret_string import SecretString


class Secret:
    """Descriptor for declaring a secret on a config class — decrypted lazily, cached.

    ::

        class Config(SecretConfig):
            openai = Secret("OPENAI_API_KEY")
            stripe = Secret("STRIPE_KEY", reveal=True)   # plaintext str

        Config.openai        # -> SecretString (cached on the class)
        Config.stripe        # -> plaintext str
    """

    __slots__ = ("env_var", "reveal", "attr")

    def __init__(self, env_var: str, *, reveal: bool = False):
        self.env_var = env_var
        self.reveal = reveal
        self.attr = env_var

    def __set_name__(self, owner: type, name: str) -> None:
        self.attr = name

    def __get__(self, obj: Any, owner: type | None = None) -> Any:
        holder = owner if owner is not None else type(obj)
        _ensure_env_loaded()
        store = holder._secret_cache
        if self.env_var not in store:
            store[self.env_var] = _resolve(self.env_var, reveal=False)
        value = store[self.env_var]
        if self.reveal and isinstance(value, SecretString):
            return value.use()
        return value


class SecretConfig:
    """Base for declarative secret config classes; each subclass gets its own cache."""

    _secret_cache: ClassVar[dict[str, Any]] = {}
    _secret_fields: ClassVar[tuple[str, ...]] = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls._secret_cache = {}
        cls._secret_fields = tuple(
            name for name, value in vars(cls).items() if isinstance(value, Secret)
        )
