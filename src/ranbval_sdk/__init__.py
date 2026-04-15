"""
Ranbval SDK — keep API secrets out of plaintext config.

- ``load_ranbval()``    load layered .ranbval* files into os.environ
- ``safe_decrypt()``   decrypt a vault token (checks repo allowlist + active plan)
- ``emit_telemetry()`` log a request to the Ranbval Live Monitor
- ``assert_plan_active()`` verify vault owner has an active subscription/trial
- ``fetch_billing_status()`` inspect plan, limits, trial state by client salt
- ``plan_limits()``    get request/secret limits for the active plan
"""

from ranbval_sdk.crypto import safe_decrypt

from ranbval_sdk.dot_ranbval import (
    find_ranbval_directory,
    find_ranbval_file,
    load_ranbval,
    resolve_ranbval_mode,
)

from ranbval_sdk.telemetry import emit_telemetry

from ranbval_sdk.billing import (
    BillingError,
    assert_plan_active,
    fetch_billing_status,
    plan_limits,
)

from ranbval_sdk.secret_string import SecretString

from .integrations.factory import secure_client
from .integrations.universal import build_secure_client

__all__ = [
    # Core
    "emit_telemetry",
    "safe_decrypt",
    "load_ranbval",
    "find_ranbval_file",
    "find_ranbval_directory",
    "resolve_ranbval_mode",
    # Billing / plan checks
    "BillingError",
    "assert_plan_active",
    "fetch_billing_status",
    "plan_limits",
    # Secret wrapper
    "SecretString",
    # HTTP integrations
    "build_secure_client",
    "secure_client",
]
