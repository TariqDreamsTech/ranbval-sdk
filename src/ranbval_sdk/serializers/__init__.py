"""Wire (de)serializers — one module per payload shape.

Everything that turns SDK data into an outbound request body, or parses a Ranbval
wire format back into a value, lives here (instead of being inlined in the client that
sends it):

- :mod:`telemetry` — the ``/api/telemetry`` usage event (payload + nested security metadata)
- :mod:`proxy` — the ``/api/execute`` secure-proxy request body
- :mod:`token` — parse a ``ranbval.<salt>.<blob>.<label>`` vault token
- :mod:`audit` — the shape of a SecretString-access audit record

Callers (``telemetry.client``, ``integrations.proxy``, ``crypto.audit``) do the I/O and gather
live values, then hand them to a builder here for shaping. Keeping the shaping separate makes
the exact wire/record contract easy to find and change in one place.
"""

from ranbval_sdk.serializers.audit import AuditEntry, build_audit_entry
from ranbval_sdk.serializers.proxy import build_proxy_payload
from ranbval_sdk.serializers.telemetry import (
    build_security_metadata,
    build_telemetry_payload,
)
from ranbval_sdk.serializers.token import salt_from_ranbval_token

__all__ = [
    "build_telemetry_payload",
    "build_security_metadata",
    "build_proxy_payload",
    "salt_from_ranbval_token",
    "AuditEntry",
    "build_audit_entry",
]
