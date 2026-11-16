from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


NONCE_LENGTH = 12
KEY_LENGTH = 32


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    Returns:
        (nonce, ciphertext)
    """

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if len(key) != KEY_LENGTH:
        raise ValueError("key must be 32 bytes")

    nonce = os.urandom(NONCE_LENGTH)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return nonce, ciphertext


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.
    """

    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes")

    if len(key) != KEY_LENGTH:
        raise ValueError("key must be 32 bytes")

    if len(nonce) != NONCE_LENGTH:
        raise ValueError("nonce must be 12 bytes")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, None)