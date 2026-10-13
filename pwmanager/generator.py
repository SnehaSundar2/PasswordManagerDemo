"""Password and passphrase generation using the `secrets` module (cryptographically secure)."""

import math
import secrets
import string

from .exceptions import ValidationError
from .wordlist import WORDS

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o|`'\"")
SEPARATORS = ("-", ".", "_", " ", "")
_rng = secrets.SystemRandom()


def generate_password(length=16, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=True):
    """Random password with at least one character from every selected set.

    Returns (password, entropy_bits).
    """
    try:
        length = int(length)
    except (TypeError, ValueError):
        raise ValidationError("Length must be a whole number.") from None
    if not 8 <= length <= 128:
        raise ValidationError("Password length must be between 8 and 128.")
    sets = [s for use, s in ((lower, string.ascii_lowercase), (upper, string.ascii_uppercase),
                             (digits, string.digits), (symbols, SYMBOLS)) if use]
    if not sets:
        raise ValidationError("Choose at least one type of character.")
    if avoid_ambiguous:
        sets = ["".join(c for c in s if c not in AMBIGUOUS) for s in sets]
    if length < len(sets):
        raise ValidationError("Length is too short to include every selected character type.")
    alphabet = "".join(sets)
    chars = [secrets.choice(s) for s in sets]                       # guarantee each chosen type
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    _rng.shuffle(chars)
    return "".join(chars), round(length * math.log2(len(alphabet)), 1)


def generate_passphrase(words=6, separator="-", capitalize=False, add_number=False):
    """Random words from the built-in list, e.g. 'maple-river-cloud-tiger-lemon-jazz'.

    Returns (passphrase, entropy_bits).
    """
    try:
        words = int(words)
    except (TypeError, ValueError):
        raise ValidationError("Number of words must be a whole number.") from None
    if not 4 <= words <= 12:
        raise ValidationError("A passphrase should have between 4 and 12 words.")
    if separator not in SEPARATORS:
        raise ValidationError("Separator must be one of: - . _ (space) or nothing.")
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    bits = words * math.log2(len(WORDS))
    if add_number:
        chosen.append(str(secrets.randbelow(100)))
        bits += math.log2(100)
    return separator.join(chosen), round(bits, 1)
