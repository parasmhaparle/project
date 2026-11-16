# Secure Password Manager

## Project Overview

Secure Password Manager is a Python-based desktop application developed to securely store and manage users' login credentials. The application uses modern cryptographic techniques to protect sensitive information and provides a graphical user interface built with Tkinter.

The main objective of this project is to provide a secure and user-friendly way to manage passwords locally.

## Features

- **Secure Vault:** Store and manage login credentials in an encrypted vault.
- **Password Encryption:** Uses AES-256-GCM authenticated encryption.
- **Key Derivation:** Uses Argon2id to derive an encryption key from the master password.
- **Password Generator:** Generate strong and random passwords.
- **Password Strength Checker:** Evaluate password strength using zxcvbn.
- **Breach Checking:** Check passwords against the Have I Been Pwned service.
- **Clipboard Protection:** Automatically clear copied passwords after a limited time.
- **Password Visibility:** Show or hide stored passwords.
- **Import Support:** Import credentials from CSV and KeePass XML files.
- **Vault Protection:** Lock the vault to protect stored credentials when not in use.

## Technologies Used

- Python
- Tkinter
- SQLite
- Argon2id
- AES-256-GCM
- cryptography
- zxcvbn
- Have I Been Pwned API
- defusedxml

## Project Structure

```text
SecurePasswordManager/
│
├── credentials/
├── crypto/
├── imports/
├── password_tools/
├── ui/
├── vault/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation and Execution

### 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Open the Project Folder

```bash
cd SecurePasswordManager
```

### 3. Create a Virtual Environment

```bash
python -m venv .venv
```

### 4. Activate the Virtual Environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
python app.py
```

## Security Information

The application uses AES-256-GCM for authenticated encryption and Argon2id for password-based key derivation. Random salts and nonces are used as part of the cryptographic implementation.

The master password is used to derive the encryption key rather than being stored as the vault password.

Users should keep their master password secure and maintain backups of their encrypted vault.

## Project Purpose

This project was developed as part of an internship project to understand secure password storage, cryptographic implementation, password security practices and desktop application development using Python.

## Disclaimer

This project is intended for educational and academic purposes. It should undergo further security testing and review before being used to store real-world sensitive credentials.
