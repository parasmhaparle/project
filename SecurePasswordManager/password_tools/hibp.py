
import hashlib

import requests


HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def check_password_breach(password: str, timeout: int = 5) -> int:
    """
    Return the number of times a password appears in HIBP's
    Pwned Passwords dataset.

    Returns:
        A non-negative integer breach count, or 0 if no match
        is found.

    Raises:
        TypeError: If password is not a string.
        ValueError: If password is empty or timeout is invalid.
        requests.RequestException: If the service request fails.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    password_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = password_hash[:5]
    suffix = password_hash[5:]

    response = requests.get(
        f"{HIBP_RANGE_URL}{prefix}",
        headers={"Add-Padding": "true"},
        timeout=timeout,
    )
    response.raise_for_status()

    for line in response.text.splitlines():
        parts = line.strip().split(":")

        if len(parts) != 2:
            continue

        returned_suffix, count_text = parts

        if returned_suffix.upper() == suffix:
            try:
                return int(count_text)
            except ValueError:
                continue

    return 0
