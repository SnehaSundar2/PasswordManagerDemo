"""Encryption for the vault, using only Python's standard library.

    master password ──scrypt(salt)──► 64-byte key ─┬─► 32-byte encryption key
                                                    └─► 32-byte authentication key

    encrypt:  keystream block i = HMAC-SHA256(enc_key, nonce ‖ i)
              ciphertext        = plaintext XOR keystream
              tag               = HMAC-SHA256(auth_key, header ‖ nonce ‖ ciphertext)

    decrypt:  recompute the tag and compare in constant time FIRST; only if it
              matches is the ciphertext decrypted ("encrypt-then-MAC").

scrypt is deliberately slow and memory-hungry, so guessing master passwords
is expensive. A fresh random nonce is used on every save, so the same vault
never produces the same ciphertext twice. A wrong password and a tampered
file are detected the same way: the tag does not match.

DEMO NOTICE: these are standard, well-understood building blocks, but this
code has not been independently audited. Real password managers use audited
libraries (e.g. AES-GCM or ChaCha20-Poly1305 from the `cryptography` package).
"""

import hashlib
import hmac
import secrets

from .exceptions import AuthenticationError, ValidationError

SALT_BYTES = 16
NONCE_BYTES = 16
TAG_BYTES = 32
DEFAULT_KDF = {"name": "scrypt", "n": 2 ** 15, "r": 8, "p": 1}
MAX_SCRYPT_MEMORY = 2 ** 27  # 128 MiB ceiling, rejects absurd parameters from a crafted file


def new_salt():
    return secrets.token_bytes(SALT_BYTES)


def derive_keys(master_password, salt, kdf=None):
    """Return (encryption_key, authentication_key) for a master password and salt."""
    kdf = kdf or DEFAULT_KDF
    if kdf.get("name") != "scrypt":
        raise ValidationError(f"Unsupported key-derivation function: {kdf.get('name')!r}.")
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    if n < 2 ** 10 or n & (n - 1) or not (1 <= r <= 32) or not (1 <= p <= 16) or 128 * n * r > MAX_SCRYPT_MEMORY:
        raise ValidationError("The vault's key-derivation settings are invalid.")
    key = hashlib.scrypt(master_password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                         maxmem=MAX_SCRYPT_MEMORY + 2 ** 20, dklen=64)
    return key[:32], key[32:]


def _keystream(enc_key, nonce, length):
    blocks = []
    for counter in range((length + 31) // 32):
        blocks.append(hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
    return b"".join(blocks)[:length]


def _xor(data, stream):
    return bytes(a ^ b for a, b in zip(data, stream))


def _tag(auth_key, header, nonce, ciphertext):
    return hmac.new(auth_key, header + nonce + ciphertext, hashlib.sha256).digest()


def encrypt(keys, plaintext, header=b""):
    """Return (nonce, ciphertext, tag). `header` is authenticated but not encrypted."""
    enc_key, auth_key = keys
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = _xor(plaintext, _keystream(enc_key, nonce, len(plaintext)))
    return nonce, ciphertext, _tag(auth_key, header, nonce, ciphertext)


def decrypt(keys, nonce, ciphertext, tag, header=b""):
    enc_key, auth_key = keys
    if len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES:
        raise AuthenticationError("Wrong master password, or the vault file has been modified.")
    if not hmac.compare_digest(_tag(auth_key, header, nonce, ciphertext), tag):
        raise AuthenticationError("Wrong master password, or the vault file has been modified.")
    return _xor(ciphertext, _keystream(enc_key, nonce, len(ciphertext)))
