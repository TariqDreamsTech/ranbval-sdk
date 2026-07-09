"""Ranbval SDK — security features self-test.

Run:  PYTHONPATH=src python3 security_demo.py

Exercises every security control added, printing PASS/FAIL for each. Uses SecretString
directly so it needs no network / no real Ranbval project.
"""

import copy
import os
import pickle

import ranbval_sdk as r
from ranbval_sdk import (
    SecretString,
    install_access_monitor,
    require_reveal_scope,
    reveal_scope,
    uninstall_access_monitor,
)
from ranbval_sdk.config.reveal import clear_reveal_requirements
from ranbval_sdk.exceptions import RanbvalConfigError

P, F = "  ✅", "  ❌"


def check(name, cond):
    print((P if cond else F) + f" {name}")


def _raises(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


def _raises_code(fn, code):
    try:
        fn()
        return False
    except RanbvalConfigError as e:
        return e.code == code


# ── 1. Masking — accidental leaks are blocked ────────────────────────────────
print("\n1) MASKING (SecretString hides itself)")
s = SecretString("sk-super-secret", label="OPENAI")
check("str(s) masked", str(s) == "[ranbval:secret]")
check("repr(s) masked (what Sentry captures)", repr(s) == "SecretString(***)")
check("f'{s}' masked", f"{s}" == "[ranbval:secret]")
check("'%s' % s masked", "%s" % s == "[ranbval:secret]")  # noqa: UP031
check("len(s) safe (only length)", len(s) == len("sk-super-secret"))

# ── 2. Serialization refused — can't leak via Sentry/celery/cache ─────────────
print("\n2) NO SERIALIZATION (can't ride out via pickle/copy)")
check("pickle.dumps(s) → TypeError", _raises(lambda: pickle.dumps(s), TypeError))
check("copy.deepcopy(s) → TypeError", _raises(lambda: copy.deepcopy(s), TypeError))

# ── 3. Buffer obfuscation — reading _buf directly = garbage ───────────────────
print("\n3) BUFFER OBFUSCATION (internal buffer is XOR-masked)")
raw = bytes(object.__getattribute__(s, "_buf"))
check(
    "_buf direct read is NOT plaintext",
    b"super" not in raw and raw != b"sk-super-secret",
)
check(".use() still reconstructs real value", s.use() == "sk-super-secret")

# ── 4. Reveal scopes — .use() only inside an approved block ───────────────────
print("\n4) REVEAL SCOPES (.use() only where you allow)")
require_reveal_scope("DB_PASSWORD")
db = SecretString("Ahsan07248988@", label="DB_PASSWORD")
with reveal_scope("DB_PASSWORD"):
    check("inside reveal_scope → real value", db.use() == "Ahsan07248988@")
check("outside scope → blocked", _raises_code(lambda: db.use(), "reveal_out_of_scope"))
check("unrelated secret still works", SecretString("x", label="OTHER").use() == "x")
clear_reveal_requirements()

# ── 5. Access monitor — extraction attempts are detected ──────────────────────
print("\n5) ACCESS MONITOR (detects extraction)")
events = []
install_access_monitor(on_event=events.append, watch_exfil=True)
val = SecretString("sk-demo").use()
events.clear()
_ = "".join(ch for ch in val)  # the join/iteration steal trick
check("iteration (join) detected", any(e.get("method") == "iteration" for e in events))
events.clear()
_ = val.encode()
check("encode() detected", any(e.get("method") == "encode" for e in events))
events.clear()
open(
    os.path.join(os.getcwd(), ".rb_demo_tmp"), "w"
).close()  # file write right after .use()
check(
    "file write after .use() detected",
    any(e.get("method") == "file_write" for e in events),
)
events.clear()
_ = f"Bearer {val}"  # legitimate SDK header
check(
    "legit f-string NOT a false alarm",
    not any(e.get("kind") == "secret.possible_exfil" for e in events),
)
os.path.exists(".rb_demo_tmp") and os.remove(".rb_demo_tmp")
uninstall_access_monitor()

# ── 6. Telemetry has NO client-side off switch ────────────────────────────────
print("\n6) TELEMETRY ALWAYS ON (leak detection can't be disabled)")
import ranbval_sdk.telemetry.settings as settings

check("no telemetry_disabled() switch", not hasattr(settings, "telemetry_disabled"))

# ── 7. Three sections + accessor policy (needs a .ranbval; shown as API check) ─
print("\n7) SECTIONS POLICY (public / secrets / proxy accessors exist & enforce)")
check(
    "public / decrypt_key / proxy_token / is_proxy exported",
    all(hasattr(r, n) for n in ("public", "decrypt_key", "proxy_token", "is_proxy")),
)

print("\n(For the [proxy]/[secrets]/[public] behaviour and decrypt_key/proxy flows,")
print(
    " use a real .ranbval — see README 'Three sections' and 'Trusted-party controls'.)"
)
print("\nDone.")
