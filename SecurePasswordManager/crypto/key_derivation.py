
from argon2.low_level import (
    Type,
    hash_secret_raw,
)


SALT_LENGTH = 16
KEY_LENGTH = 32


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from the master password.
    """

    if not isinstance(master_password, str):
        raise TypeError("master_password must be a string")

    # Reject empty master passwords.
    if not master_password:
        raise ValueError("master_password cannot be empty")

    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")

    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes")

    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )
