"""Tests for mlock, audit log, and Token TTL security features."""

import threading
import time
import unittest

from ranbval_sdk import SecretString
from ranbval_sdk.crypto import cipher as _cipher
from ranbval_sdk.crypto import (
    clear_audit_log,
    derive_key,
    get_audit_log,
    safe_decrypt,
)
from ranbval_sdk.crypto.secret_string import _try_mlock

# Repo-allowlist enforcement now always contacts the control plane (no local skip).
# These unit tests decrypt locally-built tokens with no server, so stub the network
# enforcement to a no-op — this exercises the crypto path without a live backend.
_cipher.assert_repo_allowed_for_decrypt = lambda *args, **kwargs: None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_token(plaintext: str, project_secret: str, expiry_ts: int | None = None) -> str:
    """Build a vault token; optionally embed TTL."""
    import base64
    import os as _os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = "testsalt10"
    key = derive_key(project_secret, salt)
    iv = _os.urandom(12)
    payload = plaintext
    if expiry_ts is not None:
        payload = f"{plaintext}\nranbval-expiry:{expiry_ts}"
    ct = AESGCM(key).encrypt(iv, payload.encode(), None)
    blob = base64.urlsafe_b64encode(iv + ct).decode().rstrip("=")
    return f"ranbval.{salt}.{blob}.ahsan"


# ── mlock tests ───────────────────────────────────────────────────────────────

class TestMlock(unittest.TestCase):
    def test_mlock_does_not_crash(self):
        """mlock should succeed or fail silently — never raise."""
        buf = bytearray(b"secret-value")
        result = _try_mlock(buf)
        self.assertIsInstance(result, bool)

    def test_secret_string_init_with_mlock(self):
        """SecretString initialises normally regardless of mlock support."""
        s = SecretString("my-secret")
        self.assertEqual(s.use(), "my-secret")

    def test_wipe_after_mlock(self):
        """wipe() must work even when mlock succeeded."""
        s = SecretString("wipe-after-lock")
        s.wipe()
        with self.assertRaises(RuntimeError):
            s.use()

    def test_mlock_empty_buffer_safe(self):
        buf = bytearray(b"")
        result = _try_mlock(buf)
        self.assertFalse(result)


# ── Audit log tests ───────────────────────────────────────────────────────────

class TestAuditLog(unittest.TestCase):
    def setUp(self):
        clear_audit_log()

    def test_use_creates_audit_entry(self):
        s = SecretString("audit-test", label="MY_KEY")
        s.use()
        log = get_audit_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["label"], "MY_KEY")

    def test_audit_entry_has_timestamp(self):
        s = SecretString("ts-test", label="TS_KEY")
        before = time.time()
        s.use()
        after = time.time()
        entry = get_audit_log()[0]
        self.assertGreaterEqual(entry["timestamp"], before)
        self.assertLessEqual(entry["timestamp"], after)

    def test_audit_entry_has_caller(self):
        s = SecretString("caller-test", label="CALLER_KEY")
        s.use()
        entry = get_audit_log()[0]
        self.assertIn(":", entry["caller"])   # "file.py:42" format

    def test_audit_never_logs_secret_value(self):
        s = SecretString("super-secret-value", label="SAFE_KEY")
        s.use()
        log = get_audit_log()
        log_str = str(log)
        self.assertNotIn("super-secret-value", log_str)

    def test_multiple_uses_multiple_entries(self):
        s = SecretString("multi", label="MULTI_KEY")
        s.use()
        s.use()
        s.use()
        self.assertEqual(len(get_audit_log()), 3)

    def test_clear_audit_log(self):
        s = SecretString("clear-test", label="CLR_KEY")
        s.use()
        clear_audit_log()
        self.assertEqual(len(get_audit_log()), 0)

    def test_audit_thread_safe(self):
        """Concurrent .use() calls must not corrupt the log."""
        clear_audit_log()
        s = SecretString("thread-test", label="THR_KEY")
        threads = [threading.Thread(target=s.use) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(get_audit_log()), 50)

    def test_wiped_secret_not_logged(self):
        s = SecretString("wipe-no-log", label="WIPE_KEY")
        s.wipe()
        with self.assertRaises(RuntimeError):
            s.use()
        self.assertEqual(len(get_audit_log()), 0)


# ── Token TTL tests ───────────────────────────────────────────────────────────

class TestTokenTTL(unittest.TestCase):
    SECRET = "ranbval-proj-ttl-test-secret-1234"

    def test_valid_token_no_ttl_works(self):
        """Old tokens without TTL must still decrypt normally."""
        token = _build_token("sk-live-abc", self.SECRET, expiry_ts=None)
        result = safe_decrypt(token, self.SECRET)
        self.assertEqual(result.use(), "sk-live-abc")

    def test_valid_token_future_ttl_works(self):
        """Token with future expiry must decrypt successfully."""
        future = int(time.time()) + 86400   # 24 hours from now
        token = _build_token("sk-ttl-valid", self.SECRET, expiry_ts=future)
        result = safe_decrypt(token, self.SECRET)
        self.assertEqual(result.use(), "sk-ttl-valid")

    def test_expired_token_raises(self):
        """Token with past expiry must raise ValueError."""
        past = int(time.time()) - 1   # 1 second ago
        token = _build_token("sk-expired", self.SECRET, expiry_ts=past)
        with self.assertRaises(ValueError, msg="expired"):
            safe_decrypt(token, self.SECRET)

    def test_expired_error_message(self):
        past = int(time.time()) - 3600
        token = _build_token("sk-old", self.SECRET, expiry_ts=past)
        try:
            safe_decrypt(token, self.SECRET)
        except ValueError as e:
            self.assertIn("expired", str(e).lower())

    def test_secret_with_newline_no_ttl(self):
        """Secrets that contain newlines but no TTL marker work correctly."""
        multiline = "line1\nline2\nline3"
        token = _build_token(multiline, self.SECRET, expiry_ts=None)
        result = safe_decrypt(token, self.SECRET)
        self.assertEqual(result.use(), multiline)

    def test_ttl_value_not_in_decrypted_output(self):
        """TTL marker must be stripped from the returned secret."""
        future = int(time.time()) + 9999
        token = _build_token("clean-secret", self.SECRET, expiry_ts=future)
        result = safe_decrypt(token, self.SECRET)
        self.assertEqual(result.use(), "clean-secret")
        self.assertNotIn("ranbval-expiry", result.use())


if __name__ == "__main__":
    unittest.main(verbosity=2)
