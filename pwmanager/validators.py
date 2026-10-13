"""Input validation helpers.

Each function returns a cleaned value or raises ValidationError with a
message that can be shown to the user. Passwords are never trimmed or
changed: spaces inside a password are meaningful.
"""

import re
from urllib.parse import urlsplit

from .exceptions import ValidationError
from .strength import analyse

HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
MASTER_MIN_LENGTH = 12
MAX_TAGS = 5


def _no_control_chars(text, field):
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValidationError(f"{field} contains invalid (control) characters.")
    return text


def clean_text(value, field, max_len, required=False):
    text = " ".join(str(value or "").split())
    if required and not text:
        raise ValidationError(f"{field} cannot be empty.")
    if len(text) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters.")
    return _no_control_chars(text, field)


def validate_site(value):
    return clean_text(value, "Site / service name", 60, required=True)


def validate_username(value):
    return clean_text(value, "Username", 100)


def validate_password(value):
    """An entry's password: required, kept exactly as typed."""
    if value is None or value == "":
        raise ValidationError("Password cannot be empty.")
    if len(value) > 256:
        raise ValidationError("Password must be at most 256 characters.")
    if value != value.strip():
        raise ValidationError("Password starts or ends with a space — probably a copy/paste mistake.")
    return _no_control_chars(value, "Password")


def validate_url(value):
    text = clean_text(value, "Website", 200)
    if not text:
        return ""
    if " " in text:
        raise ValidationError("Website address cannot contain spaces.")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text):
        text = "https://" + text
    parts = urlsplit(text)
    host = parts.hostname or ""
    labels = host.split(".")
    if parts.scheme not in ("http", "https") or len(labels) < 2 or not all(HOST_LABEL.match(l) for l in labels) \
            or not re.fullmatch(r"[A-Za-z]{2,63}", labels[-1]):
        raise ValidationError(f"'{value}' is not a valid website address (e.g. accounts.example.com).")
    return text


def validate_notes(value):
    return clean_text(value, "Notes", 500)


def validate_tags(value):
    """'Work, email ,work' -> ['email', 'work']."""
    if isinstance(value, (list, tuple)):
        value = ",".join(value)
    tags = sorted({t.strip().lower() for t in str(value or "").split(",") if t.strip()})
    if len(tags) > MAX_TAGS:
        raise ValidationError(f"Use at most {MAX_TAGS} tags.")
    for tag in tags:
        if not TAG_PATTERN.match(tag):
            raise ValidationError(f"Tag '{tag}' must be 1-20 letters, digits or hyphens.")
    return tags


def validate_master_password(password, confirm=None):
    """The master password protects everything, so it must be long and strong."""
    if confirm is not None and password != confirm:
        raise ValidationError("The two master passwords do not match.")
    if len(password or "") < MASTER_MIN_LENGTH:
        raise ValidationError(f"The master password must be at least {MASTER_MIN_LENGTH} characters. "
                              "Tip: a passphrase of 5-6 random words is long and easy to remember.")
    validate_password(password)
    strength = analyse(password)
    if strength.score < 3:
        problems = " ".join(strength.warnings + strength.suggestions)
        raise ValidationError(f"The master password is {strength.label.lower()} (score {strength.score}/4). "
                              f"{problems}")
    return password


def validate_entry_id(value):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError("Entry number must be a whole number.") from None
    if number < 1:
        raise ValidationError("Entry number must be at least 1.")
    return number


def validate_int(value, field, low, high):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be a whole number.") from None
    if not low <= number <= high:
        raise ValidationError(f"{field} must be between {low} and {high}.")
    return number
