
import os
import sqlite3
from pathlib import Path


# Store the encrypted vault in the Windows user application-data directory.
LOCAL_APP_DATA = Path(
    os.environ.get(
        "LOCALAPPDATA",
        str(Path.home() / "AppData" / "Local"),
    )
)

DB_PATH = LOCAL_APP_DATA / "SecurePasswordManager" / "vault.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def initialize_database():
    connection = get_connection()

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                encrypted_vault BLOB NOT NULL,
                nonce BLOB NOT NULL
            )
            """
        )

        connection.commit()
    finally:
        connection.close()

def create_vault(salt: bytes, nonce: bytes, encrypted_vault: bytes):
    """
    Insert a new vault without replacing an existing vault.
    """

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO vault_metadata
            (id, salt, encrypted_vault, nonce)
            VALUES (1, ?, ?, ?)
            """,
            (salt, encrypted_vault, nonce),
        )

        connection.commit()

    finally:
        connection.close()



def save_vault(salt: bytes, nonce: bytes, encrypted_vault: bytes):
    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO vault_metadata
            (id, salt, encrypted_vault, nonce)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                salt = excluded.salt,
                encrypted_vault = excluded.encrypted_vault,
                nonce = excluded.nonce
            """,
            (salt, encrypted_vault, nonce),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()



def load_vault():
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT salt, encrypted_vault, nonce
            FROM vault_metadata
            WHERE id = 1
            """
        ).fetchone()
    finally:
        connection.close()

    if row is None:
        return None

    return {
        "salt": row[0],
        "ciphertext": row[1],
        "nonce": row[2],
    }


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully.")
