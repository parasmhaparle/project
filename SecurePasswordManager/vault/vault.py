import json
import time
import base64
import os
from pathlib import Path
import tempfile


from credentials.credential import Credential
from crypto.encryption import encrypt, decrypt
from crypto.key_derivation import derive_key
from crypto.salt import generate_salt
from vault.database import (
    initialize_database,
    save_vault,
    load_vault,
    create_vault,
)
from imports.csv_importer import import_csv
from imports.keepass_importer import import_keepass_xml
from crypto.secure_memory import wipe_bytearray

MAX_VAULT_EXPORT_SIZE = 50 * 1024 * 1024  # 50 MB


class Vault:
    def __init__(self):
        initialize_database()

        self.salt = None
        self._key = None
        self._credentials = []
        self._unlocked = False

        self.auto_lock_timeout = 300  # 5 minutes
        self.last_activity = time.monotonic()

    def create(self, master_password: str):
        if load_vault() is not None:
            raise RuntimeError("A vault already exists")

        new_salt = generate_salt()
        new_key = derive_key(master_password, new_salt)

        self.salt = new_salt
        self._key = new_key
        self._credentials = []
        self._unlocked = True

        try:
            plaintext = json.dumps([]).encode("utf-8")
            nonce, ciphertext = encrypt(plaintext, new_key)

            create_vault(new_salt, nonce, ciphertext)
            self.update_activity()

        except Exception:
            self.salt = None
            self._key = None
            self._credentials = []
            self._unlocked = False
            raise


    def add_credential(self, credential: Credential):
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        if not isinstance(credential, Credential):
            raise TypeError("credential must be a Credential object")

        self._credentials.append(credential)

        try:
            self.save_to_database()
        except Exception:
            self._credentials.pop()
            raise

        self.update_activity()


    

    def import_csv_credentials(self, file_path: str) -> int:
        """Import CSV credentials into the unlocked vault.

        Returns the number of credentials imported.
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        # Parse and validate the entire CSV before changing the vault.
        records = import_csv(file_path)

        new_credentials = [
            Credential(
                title=record["title"],
                username=record["username"],
                password=record["password"],
                url=record["url"],
                notes=record["notes"],
            )
            for record in records
        ]

        # Keep existing credentials and append the new ones.
        self._credentials.extend(new_credentials)

        # Replace the existing try/except block with this.
        try:
            self.save_to_database()
        except Exception:
            if new_credentials:
                del self._credentials[-len(new_credentials):]
            raise

        self.update_activity()
        return len(new_credentials)

    def import_keepass_credentials(self, file_path: str) -> int:
        """Import KeePass XML credentials into the unlocked vault.

        Returns the number of credentials imported.
        """
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        # Parse and validate the entire XML before changing the vault.
        records = import_keepass_xml(file_path)

        new_credentials = [
            Credential(
                title=record["title"],
                username=record["username"],
                password=record["password"],
                url=record["url"],
                notes=record["notes"],
            )
            for record in records
        ]

        # Preserve existing credentials.
        self._credentials.extend(new_credentials)

        # Roll back in-memory changes if database saving fails.
        try:
            self.save_to_database()
        except Exception:
            if new_credentials:
                del self._credentials[-len(new_credentials):]
            raise

        self.update_activity()

        return len(new_credentials)




    def delete_credential(self, index: int) -> None:
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("index must be an integer")

        if index < 0 or index >= len(self._credentials):
            raise IndexError("credential index out of range")

        deleted_credential = self._credentials.pop(index)

        try:
            self.save_to_database()
        except Exception:
            self._credentials.insert(index, deleted_credential)
            raise

        self.update_activity()


    def get_credentials(self):
        if not self._unlocked:
            raise RuntimeError("Vault is locked")
        
        self.update_activity()
        return list(self._credentials)

    def lock(self):
        self._credentials.clear()
        self._key = None
        self._unlocked = False
        self.last_activity = time.monotonic()

    def is_auto_lock_expired(self) -> bool:
        if not self._unlocked:
            return False

        return (
            time.monotonic() - self.last_activity
            >= self.auto_lock_timeout
        )

    def update_activity(self):
        if self._unlocked:
            self.last_activity = time.monotonic()

    def export_encrypted(self) -> dict:
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        credential_data = [
            {
                "title": credential.title,
                "username": credential.username,
                "password": credential.password,
                "url": credential.url,
                "notes": credential.notes,
            }
            for credential in self._credentials
        ]

        plaintext = json.dumps(credential_data).encode("utf-8")

        nonce, ciphertext = encrypt(plaintext, self._key)

        self.update_activity()

        return {
            "salt": self.salt,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

    
    def export_to_file(self, file_path: str) -> None:
        """Export the unlocked vault as an encrypted JSON file."""
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("Export file path cannot be empty")

        encrypted_data = self.export_encrypted()

        export_data = {
            "format": "SecurePasswordManager",
            "version": 1,
            "salt": base64.b64encode(
                encrypted_data["salt"]
            ).decode("ascii"),
            "nonce": base64.b64encode(
                encrypted_data["nonce"]
            ).decode("ascii"),
            "ciphertext": base64.b64encode(
                encrypted_data["ciphertext"]
            ).decode("ascii"),
        }

        serialized_data = json.dumps(export_data, indent=2)

        if len(serialized_data.encode("utf-8")) > MAX_VAULT_EXPORT_SIZE:
            raise ValueError(
                "Encrypted vault export exceeds the maximum allowed size"
            )

        destination = Path(file_path)

        temporary_file = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_file = Path(file.name)
                file.write(serialized_data)
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_file, destination)

        except Exception:
            if temporary_file is not None:
                try:
                    temporary_file.unlink(missing_ok=True)
                except OSError:
                    pass

            raise

    
    def import_from_file(self, file_path: str, master_password: str) -> None:
        """Import and decrypt a vault from an encrypted JSON file."""
        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("Import file path cannot be empty")

        source = Path(file_path)

        if not source.is_file():
            raise FileNotFoundError(
                f"Encrypted vault file not found: {source}"
            )

        try:
            with source.open("rb") as file:
                file_contents = file.read(MAX_VAULT_EXPORT_SIZE + 1)

            if len(file_contents) > MAX_VAULT_EXPORT_SIZE:
                raise ValueError(
                    "Encrypted vault import file exceeds the maximum allowed size"
                )

            file_contents = file_contents.decode("utf-8")
            export_data = json.loads(file_contents)

        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Invalid encrypted vault export JSON") from error

        if not isinstance(export_data, dict):
            raise ValueError("Invalid vault export format")

        # Validate the export format and version.
        if export_data.get("format") != "SecurePasswordManager":
            raise ValueError("Unsupported vault export format")

        version = export_data.get("version")

        if type(version) is not int or version != 1:
            raise ValueError("Unsupported vault export version")

        # Validate and decode the encrypted fields.
        try:
            salt_text = export_data["salt"]
            nonce_text = export_data["nonce"]
            ciphertext_text = export_data["ciphertext"]

            if not all(
                isinstance(value, str)
                for value in (salt_text, nonce_text, ciphertext_text)
            ):
                raise ValueError("Invalid encrypted field type")

            encrypted_data = {
                "salt": base64.b64decode(salt_text, validate=True),
                "nonce": base64.b64decode(nonce_text, validate=True),
                "ciphertext": base64.b64decode(
                    ciphertext_text,
                    validate=True,
                ),
            }

        except (KeyError, ValueError, TypeError) as error:
            raise ValueError("Invalid encrypted vault data") from error

        # Validate decoded encryption data.
        if len(encrypted_data["salt"]) != 16:
            raise ValueError("Invalid vault salt length")

        if len(encrypted_data["nonce"]) != 12:
            raise ValueError("Invalid vault nonce length")

        if len(encrypted_data["ciphertext"]) < 16:
            raise ValueError("Invalid vault ciphertext")

        # Decrypt using the supplied master password.
        # This does not write to the existing database.
        self.unlock(master_password, encrypted_data)



    def save_to_database(self):
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        credential_data = [
            {
                "title": credential.title,
                "username": credential.username,
                "password": credential.password,
                "url": credential.url,
                "notes": credential.notes,
            }
            for credential in self._credentials
        ]

        plaintext = json.dumps(credential_data).encode("utf-8")

        nonce, ciphertext = encrypt(plaintext, self._key)

        save_vault(
            salt=self.salt,
            nonce=nonce,
            encrypted_vault=ciphertext,
        )


    def unlock(self, master_password: str, encrypted_data: dict | None = None):
        if encrypted_data is None:
            encrypted_data = load_vault()

            if encrypted_data is None:
                raise RuntimeError("No vault exists")

        # Validate the encrypted data structure before using it.
        if not isinstance(encrypted_data, dict):
            raise ValueError("Invalid encrypted vault data")

        try:
            salt = encrypted_data["salt"]
            nonce = encrypted_data["nonce"]
            ciphertext = encrypted_data["ciphertext"]
        except KeyError as error:
            raise ValueError("Missing encrypted vault data") from error

        # Derive the key and decrypt without changing the current vault state.
        key = derive_key(master_password, salt)
        plaintext = decrypt(ciphertext, key, nonce)

        # Create a mutable copy for best-effort memory cleanup.
        plaintext_buffer = bytearray(plaintext)

        # Release the reference to the immutable plaintext.
        del plaintext

        try:
            # Parse credentials directly from the mutable buffer.
            credential_data = json.loads(plaintext_buffer)

        finally:
            # Overwrite the mutable plaintext buffer.
            wipe_bytearray(plaintext_buffer)

        if not isinstance(credential_data, list):
            raise ValueError("Invalid credential data")

        new_credentials = []

        for item in credential_data:
            if not isinstance(item, dict):
                raise ValueError("Invalid credential entry")

            if not all(
                isinstance(item.get(field), str)
                for field in ("title", "username", "password")
            ):
                raise ValueError("Invalid credential fields")

            url = item.get("url", "")
            notes = item.get("notes", "")

            if not isinstance(url, str) or not isinstance(notes, str):
                raise ValueError("Invalid optional credential fields")

            new_credentials.append(
                Credential(
                    title=item["title"],
                    username=item["username"],
                    password=item["password"],
                    url=url,
                    notes=notes,
                )
            )

        # Update vault state only after successful decryption and validation.
        self.salt = salt
        self._key = key
        self._credentials = new_credentials
        self._unlocked = True
        self.update_activity()




    def search_credentials(self, query: str) -> list[Credential]:
        if not self._unlocked:
            raise RuntimeError("Vault is locked")

        if not isinstance(query, str):
            raise TypeError("query must be a string")

        query = query.strip().lower()

        if not query:
            results = self.get_credentials()
        else:
            results = [
                credential
                for credential in self._credentials
                if (
                    query in credential.title.lower()
                    or query in credential.username.lower()
                    or query in credential.url.lower()
                )
            ]

        self.update_activity()
        return results

