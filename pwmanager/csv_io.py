"""CSV import (e.g. a browser's saved-passwords export) and export.

Recognised columns (case-insensitive, any order):
    site:      name, site, title, service
    website:   url, website, login_uri
    username:  username, login, email, login_username
    password:  password, login_password
    notes:     note, notes, extra
    tags:      tags, folder, category

Rows that fail validation or duplicate an existing entry are skipped and
reported with their line number. The vault is saved once, at the end.
"""

import csv
from pathlib import Path
from urllib.parse import urlsplit

from .exceptions import PMError, StorageError, ValidationError

ALIASES = {
    "site": ("name", "site", "title", "service"),
    "url": ("url", "website", "login_uri"),
    "username": ("username", "login", "email", "login_username"),
    "password": ("password", "login_password"),
    "notes": ("note", "notes", "extra"),
    "tags": ("tags", "folder", "category"),
}
EXPORT_COLUMNS = ["name", "url", "username", "password", "notes", "tags"]


def _column_map(headers):
    lowered = {h.strip().lower(): h for h in headers if h}
    mapping = {}
    for field, names in ALIASES.items():
        for name in names:
            if name in lowered:
                mapping[field] = lowered[name]
                break
    if "password" not in mapping or not ({"site", "url"} & set(mapping)):
        raise StorageError("The CSV needs a 'password' column and a 'name' or 'url' column "
                           f"(found: {', '.join(headers)}).")
    return mapping


def import_csv(vault, path):
    """Returns (added_count, list_of_messages)."""
    path = Path(path)
    if not path.exists():
        raise StorageError(f"File not found: {path}")
    added, problems = 0, []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                raise StorageError("The CSV file is empty.")
            cols = _column_map(reader.fieldnames)
            for row in reader:
                line = reader.line_num
                if not any((val or "").strip() for val in row.values() if isinstance(val, str)):
                    continue
                get = lambda f: (row.get(cols[f]) or "") if f in cols else ""
                try:
                    site = get("site").strip() or (urlsplit(get("url") if "://" in get("url")
                                                            else "https://" + get("url")).hostname or "")
                    if not site:
                        raise ValidationError("No site name or website address.")
                    vault.add(site, get("username"), get("password"), get("url"), get("notes"),
                              get("tags").replace(";", ","), save=False)
                    added += 1
                except PMError as exc:
                    problems.append(f"Line {line}: {exc}")
    except UnicodeDecodeError:
        raise StorageError("The CSV file is not UTF-8 text.") from None
    except OSError as exc:
        raise StorageError(f"Could not read {path}: {exc.strerror or exc}") from exc
    if added:
        vault.save()
    return added, problems


def export_csv(vault, path):
    """Write every entry, UNENCRYPTED, to a CSV file (for moving to another password manager)."""
    path = Path(path)
    if path.exists():
        raise StorageError(f"{path} already exists; choose a new file name.")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(EXPORT_COLUMNS)
            for e in vault.list():
                writer.writerow([e.site, e.url, e.username, e.password, e.notes, ";".join(e.tags)])
    except OSError as exc:
        raise StorageError(f"Could not write {path}: {exc.strerror or exc}") from exc
    return len(vault.entries)
