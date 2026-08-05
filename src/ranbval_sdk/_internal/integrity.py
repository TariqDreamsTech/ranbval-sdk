"""Detect a modified installation of this package.

Everything else in this SDK guards a *secret*. This guards the *code that guards the secret* —
because a dependency, a postinstall script, or anyone with write access to ``site-packages`` can
edit the installed files and every other control becomes decorative. Patching four lines is enough:
that was measured earlier in this project, and it is why this exists.

How it works: the build records a SHA-256 for every shipped ``.py`` file in ``_manifest.py``. At
the first decrypt, each file is re-hashed and compared. A mismatch names the file.

Content is hashed after normalising line endings, so a checkout or install that rewrites CRLF is
not reported as tampering. Nothing else is normalised — whitespace and comments are part of the
file, and a manifest that ignored them could be satisfied by code that is not the code shipped.

**What this is worth, stated plainly.** It raises the cost of quietly editing an installed package
and it catches the realistic case: a compromised dependency rewriting a file to steal reveals. It
is *not* a wall. Someone who can edit ``secret_string.py`` can also edit this file, or regenerate
the manifest, or delete the call. No in-process check survives an attacker with write access to
the process's own code — the same limit that applies to every guard here.

What makes it more than theatre is that a failure is **reported to the control plane** alongside
the decrypt that triggered it. An attacker who defeats the local check still has to defeat the
reporting, and a machine that stops reporting healthy integrity is itself a signal you can see.

A mismatch **raises**. There is no flag to soften it, and deliberately so: a modified installation
defeats every other control in this package, so "carry on with a warning" is not a defensible
default, and a switch to turn it off would be reachable by exactly the code it is meant to catch.

The build regenerates the manifest and CI verifies it is current, so a mismatch means the files on
disk are not the files that were published.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent

#: Verified once per process; re-hashing every module on every decrypt would be wasteful and
#: would not catch anything the first check missed.
_checked = False


def file_digest(path: Path) -> str:
    """SHA-256 of a source file, with line endings normalised to ``\\n``."""
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _load_manifest() -> dict[str, str] | None:
    """The digests recorded at build time, or ``None`` when the package ships without one."""
    try:
        from ranbval_sdk._internal._manifest import FILE_DIGESTS
    except ImportError:
        return None
    return FILE_DIGESTS


def verify(*, force: bool = False) -> list[str]:
    """Return the relative paths whose contents no longer match the build manifest.

    An empty list means every recorded file is intact, or that no manifest shipped (a source
    checkout, an editable install) — in which case there is nothing to compare against and the
    absence is not itself evidence of tampering.
    """
    manifest = _load_manifest()
    if not manifest:
        return []

    changed: list[str] = []
    for rel, expected in manifest.items():
        path = _PACKAGE_ROOT / rel
        if not path.is_file():
            changed.append(f"{rel} (missing)")
            continue
        if file_digest(path) != expected:
            changed.append(rel)
    if force:
        _reset()
    return changed


def _reset() -> None:
    """Test helper — allow the once-per-process check to run again."""
    global _checked
    _checked = False


def check_once() -> None:
    """Verify the installation the first time a secret is decrypted.

    Called from ``SecretString.use()``. Silent when intact, when no manifest shipped, or after the
    first call.
    """
    global _checked
    if _checked:
        return
    _checked = True

    changed = verify()
    if not changed:
        return

    listed = ", ".join(sorted(changed)[:5])
    more = "" if len(changed) <= 5 else f" (+{len(changed) - 5} more)"
    message = (
        f"Ranbval: this installation has been modified — {listed}{more} no longer matches the "
        "published build. Something with write access to site-packages has edited the SDK, which "
        "is enough to defeat every other protection here. Reinstall from a trusted source:\n"
        "    pip install --force-reinstall ranbval-sdk"
    )

    # Report before raising, so the Live Monitor records it even if the caller then crashes. An
    # attacker who defeats the local check still has to defeat this, and a machine that stops
    # reporting healthy integrity is itself visible.
    try:
        from ranbval_sdk.telemetry.monitor import notify_integrity_failure

        notify_integrity_failure(changed)
    except Exception:  # nosec B110
        # Never let reporting break the caller — the warning below is the local signal.
        pass

    from ranbval_sdk.exceptions import RanbvalSecurityError

    raise RanbvalSecurityError(message, code="installation_modified")
