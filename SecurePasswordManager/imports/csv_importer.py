
import csv
from pathlib import Path


REQUIRED_COLUMNS = {"title", "username", "password"}
OPTIONAL_COLUMNS = {"url", "notes"}

MAX_CSV_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_CSV_FIELD_SIZE = 100_000
MAX_CSV_ROWS = 10_000


def import_csv(file_path: str) -> list[dict[str, str]]:
    """Read and validate credentials from a CSV file.

    Required columns: title, username, password
    Optional columns: url, notes

    Returns validated credential dictionaries.
    Does not modify the vault or database.
    """
    if not isinstance(file_path, str) or not file_path.strip():
        raise ValueError("CSV file path cannot be empty")

    source = Path(file_path)

    if not source.is_file():
        raise FileNotFoundError(f"CSV file not found: {source}")

    if source.stat().st_size > MAX_CSV_FILE_SIZE:
        raise ValueError(
            "CSV file exceeds the maximum allowed size of 5 MB"
        )

    credentials = []

    try:
        with source.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as csv_file:

            reader = csv.DictReader(csv_file, strict=True)

            if not reader.fieldnames:
                raise ValueError(
                    "CSV file is empty or has no header"
                )

            headers = [
                header.strip().lower() if header else ""
                for header in reader.fieldnames
            ]

            if len(headers) != len(set(headers)):
                raise ValueError(
                    "CSV contains duplicate column names"
                )

            missing_columns = REQUIRED_COLUMNS - set(headers)

            if missing_columns:
                missing = ", ".join(sorted(missing_columns))
                raise ValueError(
                    f"Missing required CSV columns: {missing}"
                )

            for row_number, row in enumerate(reader, start=2):

                if row_number - 1 > MAX_CSV_ROWS:
                    raise ValueError(
                        f"CSV file exceeds the maximum allowed "
                        f"limit of {MAX_CSV_ROWS} rows"
                    )

                if None in row:
                    raise ValueError(
                        f"Row {row_number} contains more "
                        "values than the header"
                    )

                for column, value in row.items():
                    if (
                        value is not None
                        and len(value) > MAX_CSV_FIELD_SIZE
                    ):
                        raise ValueError(
                            f"Row {row_number}: column "
                            f"'{column}' exceeds the maximum "
                            "allowed field length"
                        )

                normalized_row = {
                    (key.strip().lower() if key else ""): value
                    for key, value in row.items()
                }

                # Skip completely blank rows.
                if all(
                    value is None or not value.strip()
                    for value in normalized_row.values()
                ):
                    continue

                # Validate required fields.
                for field in REQUIRED_COLUMNS:
                    value = normalized_row.get(field)

                    if value is None or not value.strip():
                        raise ValueError(
                            f"Row {row_number}: "
                            f"'{field}' cannot be empty"
                        )

                credential = {
                    "title": normalized_row["title"].strip(),
                    "username": normalized_row["username"].strip(),
                    "password": normalized_row["password"],
                    "url": (
                        normalized_row.get("url") or ""
                    ).strip(),
                    "notes": (
                        normalized_row.get("notes") or ""
                    ).strip(),
                }

                credentials.append(credential)

    except UnicodeDecodeError as error:
        raise ValueError(
            "CSV file must contain valid UTF-8 text"
        ) from error

    except csv.Error as error:
        raise ValueError(
            f"Malformed CSV file: {error}"
        ) from error

    return credentials
