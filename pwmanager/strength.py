"""Password strength analysis.

Instead of only counting character types, the analyser looks for the patterns
attackers try first: common passwords, dictionary words (also in l33t-speak),
the user's own name or site, sequences (abc, 123), keyboard runs (qwerty),
repeats (aaa) and years. Each pattern is "cheap" to guess, so it contributes
only a few bits; the remaining characters contribute log2(pool size) each.

The estimated entropy (in bits) gives a score from 0 (very weak) to 4 (very
strong), an estimated time to crack, and concrete suggestions.
"""

import math
import string
from dataclasses import dataclass, field

from .wordlist import WORD_SET

COMMON_PASSWORDS = (
    "123456 password 123456789 12345678 12345 qwerty 1234567 111111 1234567890 123123 abc123 1234 "
    "password1 iloveyou 1q2w3e4r 000000 qwerty123 zaq12wsx dragon sunshine princess letmein 654321 "
    "monkey 27653 1qaz2wsx 123321 qwertyuiop superman asdfghjkl 112233 welcome admin login football "
    "baseball master shadow michael jennifer hunter 696969 trustno1 freedom whatever starwars passw0rd "
    "charlie batman access 666666 121212 flower hottie loveme zxcvbnm 555555 donald 7777777 987654321 "
    "secret summer winter spring autumn hello hello123 welcome1 admin123 root toor changeme default "
    "guest test test123 pass pass123 india india123 india@123 sairam krishna ganesh cricket 12341234 "
    "abcd1234 qwerty1 password123 iloveyou1 computer internet samsung google apple"
).split()
COMMON_SET = frozenset(COMMON_PASSWORDS)
COMMON_NAMES = frozenset((
    "aarav arjun rahul rohit rohan amit ankit akash ajay vijay vikram suresh ramesh mahesh ganesh dinesh "
    "rajesh rakesh mukesh naresh sanjay sandeep sunil anil kumar ravi raj karthik kiran arun varun tarun "
    "nikhil vishal vivek deepak manoj pradeep praveen naveen harish girish sachin saurabh gaurav abhishek "
    "aditya ashok krishna gopal hari siva shiva murugan senthil balaji venkat srinivas sai ram lakshmi "
    "priya divya kavya ananya aishwarya pooja neha sneha swathi swetha shreya riya diya anjali sonia "
    "meera nisha asha usha geetha sita radha deepa revathi keerthi sowmya sangeetha kavitha anitha sunita "
    "rekha jyothi bhavana pavithra harini nandini madhu archana shalini vidya preethi ramya "
    "john james robert michael william david richard joseph thomas charles mary patricia jennifer linda "
    "elizabeth barbara susan jessica sarah karen daniel matthew anthony mark emma olivia sophia "
).split())
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s",
                      "7": "t", "+": "t", "8": "b", "9": "g"})
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx3edc4rfv", "qazwsxedc")
SYMBOLS = set(string.punctuation)
LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")
SCORE_THRESHOLDS = (28, 36, 60, 80)  # bits needed for scores 1, 2, 3, 4
OFFLINE_GUESSES_PER_SECOND = 1e10   # an attacker with GPUs against a fast, leaked hash


@dataclass
class Strength:
    score: int
    entropy: float
    crack_time: str
    warnings: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)

    @property
    def label(self):
        return LABELS[self.score]


def pool_size(password):
    pool = 0
    pool += 26 if any(c in string.ascii_lowercase for c in password) else 0
    pool += 26 if any(c in string.ascii_uppercase for c in password) else 0
    pool += 10 if any(c in string.digits for c in password) else 0
    pool += 33 if any(c in SYMBOLS or c == " " for c in password) else 0
    pool += 100 if any(ord(c) > 127 for c in password) else 0
    return max(pool, 1)


def format_duration(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 30), ("month", 12), ("year", 100)]
    value = seconds
    for name, size in units:
        if value < size:
            v = int(value)
            return f"{v} {name}{'s' if v != 1 else ''}"
        value /= size
    return "centuries"


def _patterns(password, user_inputs):
    """Candidate guessable segments: (start, end, bits, kind, text)."""
    lower = password.lower()
    leet = lower.translate(LEET)
    n = len(password)
    found = []
    word_bits = math.log2(len(WORD_SET))
    common_bits = math.log2(len(COMMON_SET)) + 1
    inputs = {t.lower() for value in user_inputs for t in _tokens(value) if len(t) >= 3}

    for size in range(min(n, 20), 2, -1):
        for i in range(n - size + 1):
            for variant in {lower[i:i + size], leet[i:i + size]}:
                extra = 1 if password[i:i + size] != lower[i:i + size] else 0  # capitalisation costs ~1 bit
                if variant in inputs:
                    found.append((i, i + size, 2 + extra, "personal", password[i:i + size]))
                elif size >= 3 and variant in COMMON_NAMES:
                    found.append((i, i + size, math.log2(len(COMMON_NAMES)) + extra, "name", password[i:i + size]))
                elif size >= 4 and variant in COMMON_SET:
                    found.append((i, i + size, common_bits + extra, "common", password[i:i + size]))
                elif variant in WORD_SET:
                    found.append((i, i + size, word_bits + extra, "word", password[i:i + size]))

    for i in range(n):  # sequences (abc, 987) and repeats (aaa)
        for kind, step_ok in (("sequence", lambda a, b: abs(ord(b) - ord(a)) == 1), ("repeat", lambda a, b: a == b)):
            j = i + 1
            direction = None
            while j < n and step_ok(lower[j - 1], lower[j]):
                d = ord(lower[j]) - ord(lower[j - 1])
                if kind == "sequence":
                    if direction is None:
                        direction = d
                    elif d != direction:
                        break
                j += 1
            if j - i >= 3:
                bits = math.log2(26) + math.log2(j - i) if kind == "sequence" else \
                    math.log2(pool_size(password[i])) + math.log2(j - i)
                found.append((i, j, bits, kind, password[i:j]))

    for row in KEYBOARD_ROWS:  # keyboard runs, forwards or backwards
        for line in (row, row[::-1]):
            for size in range(len(line), 3, -1):
                for k in range(len(line) - size + 1):
                    chunk = line[k:k + size]
                    start = lower.find(chunk)
                    while start != -1:
                        found.append((start, start + size, 6 + math.log2(size), "keyboard", password[start:start + size]))
                        start = lower.find(chunk, start + 1)

    for i in range(n - 3):  # years 1900-2039
        chunk = lower[i:i + 4]
        if chunk.isdigit() and 1900 <= int(chunk) <= 2039:
            found.append((i, i + 4, math.log2(140), "year", password[i:i + 4]))
    return found


def _tokens(value):
    """'sneha.s@example.com' -> ['sneha', 's', 'example', 'com', 'sneha.s@example.com']."""
    text = str(value or "").lower()
    parts = "".join(c if c.isalnum() else " " for c in text).split()
    return parts + ([text] if text else [])


def estimate_entropy(password, user_inputs=()):
    """Return (bits, chosen_patterns)."""
    n = len(password)
    if n == 0:
        return 0.0, []
    char_bits = math.log2(pool_size(password))
    candidates = _patterns(password, user_inputs)
    # greedily take the patterns that save the most bits, without overlaps
    candidates.sort(key=lambda p: ((p[1] - p[0]) * char_bits - p[2]), reverse=True)
    covered = [False] * n
    chosen = []
    for start, end, bits, kind, text in candidates:
        if bits >= (end - start) * char_bits or any(covered[start:end]):
            continue
        chosen.append((start, end, bits, kind, text))
        for k in range(start, end):
            covered[k] = True
    # free characters cost log2(pool) each; a character that repeats among them
    # (e.g. the same separator between words) is a single choice, so later copies cost 1 bit
    seen, free_bits = set(), 0.0
    for k, ch in enumerate(password):
        if not covered[k]:
            free_bits += 1 if ch in seen else char_bits
            seen.add(ch)
    total = sum(p[2] for p in chosen) + free_bits
    # a password made of one repeated chunk ("abcabcabc") is barely stronger than the chunk
    for size in range(1, n // 2 + 1):
        if n % size == 0 and password[:size] * (n // size) == password and n // size > 1:
            chunk_bits, _ = estimate_entropy(password[:size], user_inputs)
            total = min(total, chunk_bits + math.log2(n // size))
            break
    return total, chosen


def analyse(password, user_inputs=()):
    password = password or ""
    lower = password.lower()
    if not password:
        return Strength(0, 0.0, "instantly", ["The password is empty."], ["Enter or generate a password."])
    if lower in COMMON_SET or lower.translate(LEET) in COMMON_SET:
        return Strength(0, round(math.log2(COMMON_PASSWORDS.index(lower) + 2), 1) if lower in COMMON_SET else 8.0,
                        "instantly", ["This is one of the most common passwords in the world."],
                        ["Use a generated password or a passphrase of 5+ random words."])

    bits, patterns = estimate_entropy(password, user_inputs)
    score = sum(bits >= t for t in SCORE_THRESHOLDS)
    if len(password) < 8:
        score = min(score, 1)
    seconds = 2 ** (bits - 1) / OFFLINE_GUESSES_PER_SECOND

    warnings, suggestions = [], []
    kinds = {p[3] for p in patterns}
    messages = {
        "personal": "Contains your name, username or the site name.",
        "common": "Contains a very common password ({}).",
        "name": "Contains a common first name ({}) — names are among the first things attackers try.",
        "word": "Contains dictionary words ({}) — fine in a long random passphrase, risky on their own.",
        "sequence": "Contains a sequence such as 'abc' or '123' ({}).",
        "repeat": "Contains repeated characters ({}).",
        "keyboard": "Contains a keyboard pattern ({}).",
        "year": "Contains a year ({}) — years and birthdays are guessed early.",
    }
    for kind in ("personal", "common", "name", "word", "keyboard", "sequence", "repeat", "year"):
        if kind in kinds and (kind != "word" or score < 3):
            examples = ", ".join(sorted({p[4] for p in patterns if p[3] == kind}))
            warnings.append(messages[kind].format(examples))
    if score < 3:
        if len(password) < 12:
            suggestions.append("Use at least 12 characters — length matters more than complexity.")
        classes = sum(bool(set(password) & set(s)) for s in
                      (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation))
        if classes < 3:
            suggestions.append("Mix upper and lower case, digits and symbols — or use a long passphrase.")
        if kinds & {"personal", "common", "name", "sequence", "keyboard", "repeat", "year"}:
            suggestions.append("Avoid predictable parts; let the generator create the password for you.")
        if not suggestions:
            suggestions.append("Make it longer: every extra random character multiplies the guessing work.")
    return Strength(score, round(bits, 1), format_duration(seconds), warnings, suggestions)
