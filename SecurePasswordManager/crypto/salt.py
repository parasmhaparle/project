import secrets

from crypto.key_derivation import SALT_LENGTH


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_LENGTH)