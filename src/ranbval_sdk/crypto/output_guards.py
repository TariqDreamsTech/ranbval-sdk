"""Opt-in global output guards: make ``print(secret.use())`` raise instead of masking.

Patching ``builtins.print`` / ``sys.stdout.write`` is invasive (it can surprise other libraries,
test capture, and REPLs), so this is **off by default** — ``SecretString``/``_ProtectedStr``
already mask themselves via ``__str__``/``__repr__`` without any global patching. Enable with
``load_ranbval(guard_stdout=True)`` or by calling :func:`install_output_guards` directly.
"""

from __future__ import annotations

import builtins
import sys

from ranbval_sdk.crypto.secret_string import _ProtectedStr

_GUARD_INSTALLED = False
_orig_print = builtins.print
_orig_stdout_write: object = None

_ERR = (
    "Ranbval: cannot output a protected secret. "
    "Pass it directly to the SDK — e.g. OpenAI(api_key=key.use())"
)


def _guarded_print(*args: object, **kwargs: object) -> None:
    # Guard the accidental leak that actually happens in practice: print(key.use()) or print(x)
    # where x = key.use(). The value is masked by __str__ regardless; this turns the mistake into
    # a loud PermissionError instead of a silent "[ranbval:secret]".
    for arg in args:
        if isinstance(arg, _ProtectedStr):
            raise PermissionError(_ERR)
    _orig_print(*args, **kwargs)


def _make_guarded_write(original_write):
    def _guarded_write(s: str) -> int:
        if isinstance(s, _ProtectedStr):
            raise PermissionError(_ERR)
        return original_write(s)

    return _guarded_write


def install_output_guards() -> None:
    """Patch ``builtins.print`` / ``sys.stdout.write`` so passing a revealed secret straight to
    them raises ``PermissionError`` instead of masking the plaintext. Opt-in; safe to call twice."""
    global _GUARD_INSTALLED, _orig_stdout_write
    if _GUARD_INSTALLED:
        return
    builtins.print = _guarded_print
    _orig_stdout_write = sys.stdout.write
    sys.stdout.write = _make_guarded_write(sys.stdout.write)
    _GUARD_INSTALLED = True
