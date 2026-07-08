"""Tests for SecretString — bytearray backend, context manager, wipe."""

import json
import unittest

from ranbval_sdk import SecretString


class TestLeakBlocking(unittest.TestCase):
    def setUp(self):
        self.s = SecretString("top-secret-value")

    def test_str_blocked(self):
        self.assertEqual(str(self.s), "[ranbval:secret]")

    def test_repr_blocked(self):
        self.assertEqual(repr(self.s), "SecretString(***)")

    def test_fstring_blocked(self):
        self.assertEqual(f"{self.s}", "[ranbval:secret]")

    def test_bytes_blocked(self):
        self.assertEqual(bytes(self.s), b"[ranbval:secret]")

    def test_json_not_serializable(self):
        with self.assertRaises(TypeError):
            json.dumps(self.s)

    def test_setattr_blocked(self):
        with self.assertRaises(AttributeError):
            self.s._buf = bytearray(b"hacked")

    def test_use_returns_plaintext(self):
        self.assertEqual(self.s.use(), "top-secret-value")

    def test_length_safe(self):
        self.assertEqual(len(self.s), len(b"top-secret-value"))

    def test_label_default(self):
        self.assertEqual(self.s.label, "secret")

    def test_label_custom(self):
        s = SecretString("val", label="OPENAI_KEY")
        self.assertEqual(s.label, "OPENAI_KEY")


class TestByteArrayBackend(unittest.TestCase):
    def test_backend_is_bytearray(self):
        s = SecretString("hello")
        buf = object.__getattribute__(s, "_buf")
        self.assertIsInstance(buf, bytearray)

    def test_wipe_zeroes_memory(self):
        s = SecretString("hello")
        buf = object.__getattribute__(s, "_buf")
        s.wipe()
        # Every byte must be zero after wipe
        self.assertTrue(all(b == 0 for b in buf))

    def test_use_after_wipe_raises(self):
        s = SecretString("hello")
        s.wipe()
        with self.assertRaises(RuntimeError, msg="SecretString has been wiped"):
            s.use()

    def test_double_wipe_safe(self):
        s = SecretString("hello")
        s.wipe()
        s.wipe()  # should not raise


class TestContextManager(unittest.TestCase):
    def test_enter_returns_plaintext(self):
        s = SecretString("my-api-key")
        with s as key:
            self.assertEqual(key, "my-api-key")

    def test_exit_wipes_memory(self):
        s = SecretString("my-api-key")
        buf = object.__getattribute__(s, "_buf")
        with s:
            pass
        self.assertTrue(all(b == 0 for b in buf))

    def test_use_after_context_raises(self):
        s = SecretString("my-api-key")
        with s:
            pass
        with self.assertRaises(RuntimeError):
            s.use()

    def test_wipe_on_exception_in_block(self):
        s = SecretString("my-api-key")
        buf = object.__getattribute__(s, "_buf")
        try:
            with s:
                raise ValueError("simulated error")
        except ValueError:
            pass
        # Must be wiped even when block raises
        self.assertTrue(all(b == 0 for b in buf))

    def test_client_init_pattern(self):
        """Startup pattern: decrypt once, init client, secret wiped."""
        captured_key = None

        class FakeClient:
            def __init__(self, api_key):
                self.api_key = api_key

        s = SecretString("sk-live-abc123")
        with s as key:
            client = FakeClient(api_key=key)
            captured_key = key

        # Block exited — secret wiped
        with self.assertRaises(RuntimeError):
            s.use()
        # Client still holds the key (its own responsibility)
        self.assertEqual(client.api_key, "sk-live-abc123")
        self.assertEqual(captured_key, "sk-live-abc123")


class TestEquality(unittest.TestCase):
    def test_equal_secrets(self):
        a = SecretString("same")
        b = SecretString("same")
        self.assertEqual(a, b)

    def test_unequal_secrets(self):
        a = SecretString("aaa")
        b = SecretString("bbb")
        self.assertNotEqual(a, b)

    def test_wiped_not_equal_to_anything(self):
        a = SecretString("same")
        b = SecretString("same")
        a.wipe()
        self.assertNotEqual(a, b)

    def test_not_equal_to_plain_string(self):
        s = SecretString("hello")
        self.assertEqual(s.__eq__("hello"), NotImplemented)


class TestUnicode(unittest.TestCase):
    def test_unicode_roundtrip(self):
        val = "پاکستان-key-🔑"
        s = SecretString(val)
        self.assertEqual(s.use(), val)

    def test_unicode_wipe(self):
        s = SecretString("پاکستان")
        s.wipe()
        with self.assertRaises(RuntimeError):
            s.use()


if __name__ == "__main__":
    unittest.main(verbosity=2)
