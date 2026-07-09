"""Usage telemetry for the Ranbval Live Monitor.

- :mod:`~ranbval_sdk.telemetry.client` — build and POST a usage event (sync + async).
- :mod:`~ranbval_sdk.telemetry.decorators` — ``@track`` / ``tracked()`` ergonomic wrappers.

Only a non-reversible token salt and coarse metadata are sent — never plaintext secrets.
"""

from ranbval_sdk.telemetry.client import (
    aemit_telemetry,
    emit_telemetry,
    salt_from_ranbval_token,
)
from ranbval_sdk.telemetry.decorators import track, tracked
from ranbval_sdk.telemetry.monitor import (
    classify_context,
    install_access_monitor,
    uninstall_access_monitor,
)

__all__ = [
    "emit_telemetry",
    "aemit_telemetry",
    "salt_from_ranbval_token",
    "track",
    "tracked",
    "install_access_monitor",
    "uninstall_access_monitor",
    "classify_context",
]
