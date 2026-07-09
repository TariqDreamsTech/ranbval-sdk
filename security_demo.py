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
    set_enforcement,
    uninstall_access_monitor,
)
from ranbval_sdk.config.reveal import clear_reveal_requirements
from ranbval_sdk.exceptions import RanbvalConfigError, RanbvalSecurityError

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


# ── 1. Masking / str-raise — accidental display paths ─────────────────────────
print("\n1) DISPLAY PATHS (str raises under enforcement; masks when off)")
s = SecretString("sk-super-secret", label="OPENAI")
check("str(s) RAISES under enforcement", _raises(lambda: str(s), RanbvalSecurityError))
check("'%s' % s RAISES under enforcement", _raises(lambda: "%s" % s, RanbvalSecurityError))  # noqa: UP031
check("repr(s) masked (what Sentry captures — never raises)", repr(s) == "SecretString(***)")
check("f'{s}' masked (wrapper)", f"{s}" == "[ranbval:secret]")
check("len(s) safe (only length)", len(s) == len("sk-super-secret"))
set_enforcement(False)
check("str(s) masks when enforcement OFF", str(s) == "[ranbval:secret]")
set_enforcement(True)

# ── 2. Serialization refused — can't leak via Sentry/celery/cache ─────────────
print("\n2) NO SERIALIZATION (can't ride out via pickle/copy)")
check("pickle.dumps(s) → TypeError", _raises(lambda: pickle.dumps(s), TypeError))
check("copy.deepcopy(s) → TypeError", _raises(lambda: copy.deepcopy(s), TypeError))

# ── 3. Buffer obfuscation — even the real slot is XOR-masked garbage ───────────
print("\n3) BUFFER OBFUSCATION (internal buffer is XOR-masked)")
# _buf/_pad are honeypot properties (see section 5a); the REAL slot is _b — and even that
# yields only masked garbage without the pad, which is the point of the obfuscation.
raw = bytes(object.__getattribute__(s, "_b"))
check(
    "real _b slot read is NOT plaintext",
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

# ── 5a. Enforcement — extraction attempts are BLOCKED (strict by default) ─────
print("\n5a) ENFORCEMENT (extraction raises RanbvalSecurityError — default ON)")
s5 = SecretString("sk-demo")
val = s5.use()
check("iteration (join) blocked", _raises(lambda: "".join(ch for ch in val), RanbvalSecurityError))
check("encode() blocked", _raises(lambda: val.encode(), RanbvalSecurityError))
check("slice val[:] blocked", _raises(lambda: val[:], RanbvalSecurityError))
check("index val[0] blocked", _raises(lambda: val[0], RanbvalSecurityError))
check("s._buf read blocked", _raises(lambda: SecretString("x")._buf, RanbvalSecurityError))
check(
    "object.__getattribute__(s,'_buf') blocked (honeypot)",
    _raises(lambda: object.__getattribute__(s5, "_buf"), RanbvalSecurityError),
)
check("str(val) blocked", _raises(lambda: str(val), RanbvalSecurityError))
check("legit f-string still works (no raise)", f"Bearer {val}" == "Bearer sk-demo")
check("legit concat still works (no raise)", ("Bearer " + val) == "Bearer sk-demo")
# Honest floor — these CANNOT be blocked in-process (documented), so we don't fake it:
check("str.__str__(val) still bypasses (str type immutable)", str.__str__(val) == "sk-demo")
check("real slot _b still readable (open-source floor)", object.__getattribute__(s5, "_b") is not None)

# ── 5b. Access monitor — with enforcement off, attempts are DETECTED + reported ─
print("\n5b) ACCESS MONITOR (enforcement off → detect + notify)")
set_enforcement(False)
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
set_enforcement(True)  # restore strict default

# ── 6. Telemetry has NO client-side off switch ────────────────────────────────
print("\n6) TELEMETRY ALWAYS ON (leak detection can't be disabled)")
import ranbval_sdk.telemetry.settings as settings  # noqa: E402 — inline for demo readability

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
