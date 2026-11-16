# Secure Password Manager

## 1. Project Overview

Secure Password Manager is a Python-based desktop application designed
to help users store and manage login credentials in a local encrypted
vault.

The application provides a graphical user interface built with Tkinter
and uses cryptographic techniques to protect stored credential data.

## 2. Features

-   **Secure Vault:** Store and manage login credentials in an encrypted
    vault.
-   **Password Encryption:** Uses AES-256-GCM authenticated encryption.
-   **Key Derivation:** Uses Argon2id to derive an encryption key from
    the master password.
-   **Password Generator:** Generate strong, random passwords.
-   **Password Strength Checker:** Evaluate password strength using
    zxcvbn.
-   **Password Breach Checking:** Check passwords against the Have I
    Been Pwned service.
-   **Clipboard Protection:** Automatically clear copied passwords after
    a configured time.
-   **Password Visibility:** Show or hide stored passwords.
-   **Import Support:** Import credentials from CSV and KeePass XML
    files.
-   **Vault Protection:** Lock the vault when it is not in use.
-   **Encrypted Backup:** Export and import encrypted vault data.

## 3. Technologies Used

-   Python
-   Tkinter
-   SQLite
-   AES-256-GCM
-   Argon2id
-   `cryptography`
-   `zxcvbn`
-   Have I Been Pwned API
-   `defusedxml`

## 4. Project Structure

``` text
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
├── SecurePasswordManager.exe
├── README.md
└── .gitignore
```

## 5. Installation and Execution

There are two ways to run the Secure Password Manager.

### Method 1: Run the Application Using Python Source Code

Use this method if you want to inspect or run the Python source code.

**Step 1: Get the Project Files**

Choose either option:

-   **Option A --- Clone the repository:** Open a terminal and run the
    following command, replacing the placeholder with your GitHub
    repository URL:

    ``` bash
    git clone YOUR_GITHUB_REPOSITORY_URL
    ```

-   **Option B --- Download the repository:** Open the GitHub
    repository, select **Code → Download ZIP**, and extract the
    downloaded ZIP file.


**Step 2: Open the Project Folder In PowerShell**

``` bash
cd "[projectfolderpath]"
```

**Step 3: Create a Virtual Environment**

``` bash
python -m venv .venv
```

**Step 4: Activate the Virtual Environment**

For Windows PowerShell:

``` powershell
.venv\Scripts\Activate.ps1
```

**Step 5: Install the Required Dependencies**

``` bash
pip install -r requirements.txt
```

**Step 6: Run the Application**

``` bash
python app.py
```

### Method 2: Run the Application Using the Windows Executable

Use this method if you want to run the pre-built Windows application
without setting up the Python environment.

1.  Download the repository ZIP from GitHub, or download
    `SecurePasswordManager.exe` if it is provided separately.
2.  If you downloaded the repository ZIP, extract it and open the
    project folder.
3.  On a compatible Windows computer, locate
    `SecurePasswordManager.exe`.
4.  Double-click the executable to launch the application.

When the executable has been packaged with all required dependencies,
Python and the packages listed in `requirements.txt` do not need to be
installed separately. The executable's operation still depends on
Windows compatibility and the correctness of the build. If it does not
start, use Method 1 or consult the project maintainer.

## 6. Security Implementation

The application uses AES-256-GCM authenticated encryption to protect
stored vault data. Argon2id is used to derive an encryption key from the
master password. A randomly generated salt is used during key
derivation, and a random nonce is generated for encryption operations.

Encrypted vault data is stored using SQLite. Additional security-related
features include password strength evaluation, password breach checking,
automatic clipboard clearing and vault locking.

## 7. Project Objective

This project was developed as part of an internship project to gain
practical experience in:

-   Secure password storage.
-   Cryptographic implementation.
-   Password security practices.
-   Python desktop application development.
-   Database management.
-   Security testing and assessment.

## 8. Disclaimer

This project is intended for educational and academic purposes. Further
security testing and review are recommended before using it to store
real-world sensitive credentials.
