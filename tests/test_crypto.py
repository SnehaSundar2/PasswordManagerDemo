import unittest

from pwmanager import crypto
from pwmanager.exceptions import AuthenticationError, ValidationError
from tests.helpers import FAST_KDF


class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.salt = bytes(range(16))
        self.keys = crypto.derive_keys("correct master password", self.salt, FAST_KDF)

    def test_round_trip_including_unicode(self):
        message = "Bank PIN: 4821 · नमस्ते · ₹".encode("utf-8") * 50
        nonce, ct, tag = crypto.encrypt(self.keys, message, b"header")
        self.assertNotIn(b"PIN", ct)
        self.assertEqual(crypto.decrypt(self.keys, nonce, ct, tag, b"header"), message)

    def test_fresh_nonce_every_time(self):
        a = crypto.encrypt(self.keys, b"same message")
        b = crypto.encrypt(self.keys, b"same message")
        self.assertNotEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])  # identical plaintext never gives identical ciphertext

    def test_key_derivation(self):
        again = crypto.derive_keys("correct master password", self.salt, FAST_KDF)
        self.assertEqual(again, self.keys)
        self.assertNotEqual(crypto.derive_keys("correct master password", bytes(16), FAST_KDF), self.keys)
        self.assertNotEqual(crypto.derive_keys("Correct master password", self.salt, FAST_KDF), self.keys)
        self.assertEqual([len(k) for k in self.keys], [32, 32])

    def test_wrong_key_or_any_tampering_is_detected(self):
        nonce, ct, tag = crypto.encrypt(self.keys, b"secret data", b"hdr")
        wrong = crypto.derive_keys("wrong master password", self.salt, FAST_KDF)
        flipped = bytes([ct[0] ^ 1]) + ct[1:]
        cases = [(wrong, nonce, ct, tag, b"hdr"), (self.keys, nonce, flipped, tag, b"hdr"),
                 (self.keys, nonce, ct, tag[:-1] + b"\x00", b"hdr"), (self.keys, nonce, ct, tag, b"HDR"),
                 (self.keys, nonce[:-1], ct, tag, b"hdr")]
        for keys, n, c, t, h in cases:
            with self.assertRaises(AuthenticationError):
                crypto.decrypt(keys, n, c, t, h)

    def test_unsafe_kdf_settings_rejected(self):
        for kdf in ({"name": "md5", "n": 1024, "r": 8, "p": 1}, {"name": "scrypt", "n": 1000, "r": 8, "p": 1},
                    {"name": "scrypt", "n": 2 ** 8, "r": 8, "p": 1}, {"name": "scrypt", "n": 2 ** 24, "r": 8, "p": 1}):
            with self.assertRaises(ValidationError, msg=kdf):
                crypto.derive_keys("x", self.salt, kdf)


if __name__ == "__main__":
    unittest.main()
