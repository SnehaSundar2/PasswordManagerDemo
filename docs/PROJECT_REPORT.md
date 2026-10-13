# Project Report: Password Manager Demo

**Program:** Virtual Internship – Python Development, Skyrovix IT Solutions Pvt. Ltd.
**Project:** Password Manager Demo
**Developed and submitted by:** Sneha S (Intern ID: SKX-2026-6425)
**Due date:** 24 November 2026

---

## 1. Introduction

Most people reuse a few easy passwords across many websites, so one leaked password can unlock
email, banking and social media accounts. A password manager solves this. It stores a different
strong password for every site in an encrypted vault, protected by a single master password the
user remembers.

This project is an educational password manager in Python. It shows how a vault can be
encrypted and checked for tampering, and how input is validated. It also shows how passwords can
be analysed and generated so users choose better ones.

## 2. Objectives

1. Build a working password manager from clearly separated Python modules.
2. Validate every input, including a strong-master-password policy based on real strength analysis.
3. Process data: estimate password strength from patterns, find reused and old passwords, score the vault's health.
4. Handle errors safely: wrong password, tampered or damaged files, bad import rows, locked vault.
5. Document the workflow and verify the behaviour with automated tests.

## 3. Tools and technologies

| Item | Used |
|---|---|
| Language | Python 3 (tested on 3.13) |
| Libraries | Standard library only: `hashlib` (scrypt, SHA-256), `hmac`, `secrets`, `base64`, `json`, `csv`, `getpass`, `dataclasses`, `datetime`, `logging`, `argparse`, `unittest` |
| Storage | One encrypted JSON vault file, with a `.bak` copy of the previous version |

## 4. System design

### 4.1 Modules

| Module | Responsibility |
|---|---|
| `crypto.py` | Key derivation (scrypt), encryption (HMAC-SHA256 keystream), authentication tag |
| `vault.py` | Vault file format, create/unlock/lock, entries, password history, master change, safe saving |
| `models.py` | `Entry` dataclass |
| `validators.py` | Field validation and the master-password policy |
| `strength.py` | Pattern-aware entropy estimate, score, crack time, warnings, suggestions |
| `generator.py` | Random passwords and passphrases using `secrets` |
| `wordlist.py` | About 1,200 common words |
| `audit.py` | Vault health check |
| `csv_io.py` | Import from browser exports; plain-text export |
| `demo.py` | Demo vault with fictional accounts |
| `cli.py`, `main.py` | Menu (hidden input, masking, auto-lock, attempt limit) and command-line options |
| `exceptions.py` | Custom error types |

### 4.2 Security design

| Threat | Protection |
|---|---|
| Someone copies the vault file | All content is encrypted; only random-looking bytes and scrypt settings are visible |
| Guessing the master password offline | scrypt (N=32768, r=8, p=1, random 16-byte salt) makes every guess slow and memory-heavy; a strong master password is required |
| Modifying the file | HMAC-SHA256 tag over header, nonce and ciphertext, checked in constant time before decrypting |
| Identical saves revealing patterns | Fresh random 16-byte nonce on every save |
| Shoulder-surfing | Hidden password input, masked lists, reveal only after confirmation |
| Walking away from the computer | Auto-lock after 5 minutes; keys and entries wiped from memory |
| Leaked old master password | Master change uses a new salt and also replaces the backup file |
| Logs exposing secrets | Only events are logged (e.g. "Added entry #3"), never usernames or passwords |

## 5. Implementation highlights

**Strength analysis that thinks like an attacker.** `Sunshine2024!` has upper and lower case, a
digit and a symbol, so a simple checker calls it strong. This analyser recognises a common
password plus a year and rates it **Very weak** (about 22 bits, cracked instantly). A random
6-word passphrase such as `maple-river-cloud-tiger-lemon-jazz` is rated **Strong** (about 71 bits).
That's because the analyser counts each word as one choice from the word list, and the repeated
separator only once.

**Health check.** On the demo vault, the report finds 4 weak passwords, one password shared by
two sites, two passwords older than a year, and a password containing the site name. It gives a
health score of 50/100 ("Needs attention"). Passwords are grouped by their SHA-256 hash to detect
reuse.

**Password history.** Changing a password stores the old one, keeping the last 5. Choosing one of
those again is refused: "You have used this password for this account before."

**Safe import.** A Chrome-style CSV export is mapped automatically: name, url, username,
password, note. If the name is missing, the site is taken from the URL. Bad rows are reported:

```
Imported 3 entries.
  - skipped Line 5: Password cannot be empty.
  - skipped Line 6: There is already an entry for Example Forum for 'sneha.demo' (#1). Edit it instead.
  - skipped Line 7: Website address cannot contain spaces.
```

## 6. Testing

32 automated tests were written and **all pass**.

| # | Test case | Expected | Result |
|---|---|---|---|
| 1 | Encrypt then decrypt (with Unicode) | Original text back | Pass |
| 2 | Same message encrypted twice | Different ciphertext (fresh nonce) | Pass |
| 3 | Wrong key; one flipped bit in ciphertext, tag or header; short nonce | AuthenticationError | Pass |
| 4 | Vault file searched for the site, username, password and notes | Not found (encrypted) | Pass |
| 5 | scrypt setting changed in the file | AuthenticationError | Pass |
| 6 | Bad JSON, wrong format, missing tag, corrupted base64 | VaultFormatError with a clear message | Pass |
| 7 | Master `password1234` | Rejected as very weak | Pass |
| 8 | `P@ssw0rd`, `Rahul1998`, `Sunshine2024!` | Very weak, with the reason | Pass |
| 9 | Generated passwords (50 runs) | Right length, every type, no look-alikes, all unique | Pass |
| 10 | Edit with one invalid field | Nothing changed | Pass |
| 11 | Reusing one of the last 5 passwords | Refused | Pass |
| 12 | Master password changed | Old password opens neither the vault nor the backup | Pass |
| 13 | Demo vault health check | 4 weak, 1 reused pair, 2 old, score below 75 | Pass |
| 14 | Browser CSV with 3 bad rows | 3 imported, 3 reported by line number | Pass |
| 15 | 3 wrong master passwords | Program exits | Pass |
| 16 | 10 minutes idle | Vault auto-locks and asks for the master password | Pass |

## 7. Challenges and solutions

| Challenge | Solution |
|---|---|
| No AES in Python's standard library | Built encryption from standard primitives (scrypt, HMAC-SHA256 in counter mode, encrypt-then-MAC), and documented clearly that audited libraries should be used for real data |
| Detecting both a wrong password and tampering | One authentication tag covers everything; the tag is checked before decrypting |
| Simple strength rules give wrong answers | Pattern-based entropy estimate that recognises common passwords, names, words, sequences and years |
| Passphrases rated too strong because of separators | A repeated separator character is counted as a single choice |
| Testing hidden input and timeouts | Injectable `read_secret` and clock functions, so tests can "type" passwords and "wait" 10 minutes instantly |
| Slow key derivation in tests | Tests use a lighter scrypt setting; real vaults use the strong default |

## 8. Future enhancements

- Use audited AES-GCM or ChaCha20-Poly1305 encryption via the `cryptography` package
- Clipboard copy with automatic clearing after 30 seconds
- Breach check against "Have I Been Pwned" using k-anonymity (only a hash prefix leaves the computer)
- Two-factor (TOTP) code storage
- Graphical interface and browser auto-fill

## 9. Conclusion

The Password Manager Demo meets all the project objectives. It is organised into focused modules
and validates every field, with a master-password policy based on real strength analysis. It
processes password data into meaningful strength scores and a vault health report, and it
handles wrong passwords, tampering and damaged files safely. The workflow is documented and the
behaviour is verified by 32 passing automated tests.

## 10. How to run

```bash
cd PasswordManagerDemo
python main.py --demo
python main.py --generate 24
python -m unittest discover -s tests -t . -v
```
