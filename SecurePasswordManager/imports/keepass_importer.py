
from pathlib import Path

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


MAX_XML_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_XML_ENTRIES = 10_000
MAX_XML_FIELD_SIZE = 100_000


def import_keepass_xml(file_path: str) -> list[dict[str, str]]:
    """Safely read and validate credentials from a KeePass XML export."""

    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("KeePass XML file path cannot be empty")

    source = Path(file_path)

    if not source.is_file():
        raise FileNotFoundError(
            f"KeePass XML file not found: {source}"
        )

    if source.stat().st_size > MAX_XML_SIZE:
        raise ValueError("KeePass XML file is too large")

    try:
        tree = ET.parse(source)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValueError("Invalid KeePass XML file") from exc

    root = tree.getroot()

    if root.tag != "KeePassFile":
        raise ValueError("Invalid KeePass XML root element")

    credentials = []

    entries = root.findall(".//Entry")

    if len(entries) > MAX_XML_ENTRIES:
        raise ValueError(
            f"KeePass XML exceeds the maximum allowed limit "
            f"of {MAX_XML_ENTRIES} entries"
        )

    for entry in entries:

        fields = {}

        for string_element in entry.findall("String"):
            key_element = string_element.find("Key")
            value_element = string_element.find("Value")

            if key_element is None or key_element.text is None:
                continue

            key = key_element.text.strip().lower()

            if not key:
                continue

            value = (
                value_element.text or ""
                if value_element is not None
                else ""
            )

            if len(value) > MAX_XML_FIELD_SIZE:
                raise ValueError(
                    f"KeePass entry contains a field exceeding "
                    f"the maximum allowed length of {MAX_XML_FIELD_SIZE}"
                )

            # Preserve the first occurrence of each field.
            if key not in fields:
                fields[key] = value

        title = fields.get("title", "").strip()
        username = fields.get("username", "").strip()
        password = fields.get("password", "")

        # Skip entries containing no credential data.
        if not any((title, username, password)):
            continue

        if not title:
            raise ValueError(
                "KeePass entry is missing a required title"
            )

        if not username:
            raise ValueError(
                f"KeePass entry '{title}' is missing a username"
            )

        if not password.strip():
            raise ValueError(
                f"KeePass entry '{title}' is missing a password"
            )

        credentials.append({
            "title": title,
            "username": username,
            "password": password,
            "url": fields.get("url", "").strip(),
            "notes": fields.get("notes", "").strip(),
        })

    return credentials
