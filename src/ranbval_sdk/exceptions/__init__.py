"""Exception hierarchy for the Ranbval SDK.

Every error the SDK raises derives from :class:`RanbvalError`, so callers can catch the whole
family with ``except RanbvalError``. Each specific error **also** subclasses the built-in it
historically replaced (``ValueError`` / ``KeyError`` / ``PermissionError``), so existing
``except ValueError`` / ``except KeyError`` / ``except PermissionError`` code keeps working.

    from ranbval_sdk import RanbvalError, RanbvalDecryptError

    try:
        key = decrypt_key("SECRET_OPENAI_KEY")
    except RanbvalDecryptError as err:   # precise
        log.error("decrypt failed", code=err.code, **err.context)
    except RanbvalError:                 # anything from the SDK
        ...

Structured context
------------------
Every error carries an optional machine-readable ``code`` and a ``context`` dict, so callers can
branch/log/emit metrics without parsing the human message string::

    except RanbvalError as err:
        metrics.increment("ranbval.error", tags={"code": err.code})

The classes are grouped by the subsystem they belong to (mirroring the package layout) and
re-exported here, so ``from ranbval_sdk.exceptions import RanbvalConfigError`` is unchanged:

- :mod:`~ranbval_sdk.exceptions.base`   — :class:`RanbvalError`
- :mod:`~ranbval_sdk.exceptions.config` — :class:`RanbvalConfigError`, :class:`MissingKeyError`
- :mod:`~ranbval_sdk.exceptions.crypto` — :class:`RanbvalDecryptError`, :class:`RanbvalSecurityError`
- :mod:`~ranbval_sdk.exceptions.policy` — :class:`RepoNotAllowedError`, :class:`RepoPolicyError`
- :mod:`~ranbval_sdk.exceptions.proxy`  — :class:`ProxyError`
"""

from ranbval_sdk.exceptions.base import RanbvalError
from ranbval_sdk.exceptions.config import MissingKeyError, RanbvalConfigError
from ranbval_sdk.exceptions.crypto import RanbvalDecryptError, RanbvalSecurityError
from ranbval_sdk.exceptions.policy import RepoNotAllowedError, RepoPolicyError
from ranbval_sdk.exceptions.proxy import ProxyError

__all__ = [
    "RanbvalError",
    "RanbvalConfigError",
    "MissingKeyError",
    "RanbvalDecryptError",
    "RanbvalSecurityError",
    "RepoNotAllowedError",
    "RepoPolicyError",
    "ProxyError",
]
