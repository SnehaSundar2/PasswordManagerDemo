# Password Manager Demo

An educational command-line password manager. It keeps all your logins in **one encrypted vault
file** protected by a single **master password**, and helps you use better passwords: a secure
**generator**, a **strength checker** that spots the patterns attackers try first, and a **vault
health check** that finds weak, reused and old passwords.

Developed by **Sneha S** as a virtual internship project (Python Development, Skyrovix IT
Solutions) to demonstrate **Python modules, input validation, data processing and error
handling**. Only the Python standard library is used, so there is nothing to install.

> **Demo notice.** This project shows how a password manager works. Its encryption uses
> standard, well-understood building blocks, but the code has **not been independently audited**.
> For your real passwords, use an established, audited password manager.

---

## 1. Features

| Area | What it does |
|---|---|
| **Encrypted vault** | Everything (site names, usernames, passwords, notes) is encrypted in one file; tampering is detected |
| **Master password** | Must be 12+ characters and rated "Strong"; never stored; 3 wrong attempts end the program |
| **Auto-lock** | Locks itself after 5 minutes without activity; keys are wiped from memory |
| **Entries** | Add, list (passwords masked), search, view (reveal on request), edit, delete |
| **Password history** | Remembers the last 5 passwords per entry and refuses to reuse them |
| **Generator** | Random passwords (8–128 characters, chosen character types, no look-alike characters) and word passphrases |
| **Strength checker** | Score 0–4, estimated entropy and cracking time, plus specific warnings and tips |
| **Health check** | Weak, fair, reused, old (1+ year) and personal passwords; a 0–100 health score |
| **Import / export** | Import a browser's CSV export (bad rows reported by line number); export to CSV after a typed confirmation |
| **Safe storage** | Atomic saves, previous version kept as `.bak`, clear messages for damaged files |

---

## 2. How the vault is protected

```
 master password ──► scrypt (random salt, N=32768, r=8, p=1) ──► 64-byte key
                                                                  ├─ 32 bytes: encryption key
                                                                  └─ 32 bytes: authentication key

 save:   entries (JSON) ──XOR──► ciphertext        keystream = HMAC-SHA256(enc key, nonce ‖ counter)
         tag = HMAC-SHA256(auth key, header ‖ nonce ‖ ciphertext)       new random nonce on every save

 open:   recompute the tag ── matches? ──► decrypt
                         └── different ──► "Wrong master password, or the vault file has been modified."
```

- **scrypt** is deliberately slow and memory-hungry, so each master-password guess is expensive
  for an attacker. It takes about 0.25 s here.
- **Encrypt-then-MAC:** the file is checked *before* anything is decrypted. The header (format and
  scrypt settings) is covered by the tag too, so even changing a setting is detected.
- **Nothing readable on disk:** the vault file shows only the scrypt settings, salt, nonce,
  ciphertext and tag.
- **Changing the master password** generates a new salt, re-encrypts the vault and replaces the
  backup, so the old password no longer opens anything.
- **Never logged:** passwords and usernames never appear in the log file. Passwords are typed with
  `getpass`, so they don't show on screen.
- **Not recoverable:** there is no "forgot password". If you lose the master password, the vault
  cannot be opened, which is the point.

### Strength checker

Instead of only counting character types, the checker looks for what attackers try first and
gives each pattern only the few bits it is really worth:

| Pattern | Example | Treated as |
|---|---|---|
| Common password (also in l33t-speak) | `P@ssw0rd`, `qwerty123` | ~7 bits |
| Your name / username / site | `Gmail@sneha` | ~2 bits |
| Common first name | `Rahul`, `Priya` | ~8 bits |
| Dictionary word | `river` | ~10 bits |
| Sequence, keyboard run, repeat | `abcd`, `poiuy`, `aaaa` | 5–9 bits |
| Year | `1998` | ~7 bits |

Score: **0** Very weak (< 28 bits) · **1** Weak · **2** Fair (36+) · **3** Strong (60+) ·
**4** Very strong (80+). Passwords under 8 characters are capped at "Weak".

---

## 3. Project structure

```
PasswordManagerDemo/
├── main.py                       # Entry point: menu, demo vault, generate/check shortcuts
├── pwmanager/                    # The application package
│   ├── exceptions.py             # Custom exception hierarchy
│   ├── crypto.py                 # scrypt key derivation, HMAC-SHA256 stream cipher + tag
│   ├── vault.py                  # Encrypted vault: create, unlock, lock, entries, master change
│   ├── models.py                 # Entry dataclass (with password history)
│   ├── validators.py             # Site, username, password, URL, tags, master-password policy
│   ├── strength.py               # Pattern-aware strength estimation
│   ├── generator.py              # Passwords and passphrases (secrets module)
│   ├── wordlist.py               # ~1,200 common words for passphrases and the dictionary check
│   ├── audit.py                  # Vault health check
│   ├── csv_io.py                 # CSV import/export
│   ├── demo.py                   # Demo vault with fictional accounts
│   └── cli.py                    # Interactive menu (auto-lock, attempt limit, masking)
├── sample_data/
│   └── browser_export_sample.csv # Import example with 3 deliberately bad rows
├── tests/                        # 32 automated tests
└── docs/
    └── PROJECT_REPORT.md         # Internship submission report
```

---

## 4. How to run

Requires **Python 3.8 or newer**.

```bash
cd PasswordManagerDemo
python main.py --demo          # try the demo vault (its master password is printed)
python main.py                 # create or open your own vault at data/vault.pmv
python main.py --generate 24   # print a random 24-character password
python main.py --passphrase 6  # print a 6-word passphrase
python main.py --check         # check a password's strength (typed hidden, never saved)
```

The demo vault contains **fictional** accounts. Some have deliberately weak or reused passwords so
you can see the health check work.

### Typical session

1. Start the program and type the master password. On the first run it asks you to create one.
2. **4. Add an entry.** Leave the password empty to get a strong generated one, or type your own
   and see its strength straight away.
3. **1. List** shows everything with passwords masked. **3. View** shows one entry and reveals the
   password only if you confirm.
4. **10. Vault health check** lists weak, reused and old passwords. **5. Edit** changes them.
5. **0** locks the vault and exits. Walking away also locks it after 5 minutes.

### Input rules

| Input | Rule |
|---|---|
| Master password | 12+ characters, rated Strong (score 3+), typed twice when created |
| Site name | Required, up to 60 characters |
| Username | Optional, up to 100 characters; site + username must be unique |
| Password | Required, up to 256 characters, kept exactly as typed (inner spaces allowed; leading/trailing spaces rejected as likely copy-paste mistakes) |
| Website | Optional; `https://` added if missing; must be a real host name |
| Tags | Up to 5, comma-separated, letters/digits/hyphens |
| Generated password | 8–128 characters, at least one of each chosen type |
| Passphrase | 4–12 words; separator `-` `.` `_` space or none |

---

## 5. Key concepts demonstrated

**Python modules.** Cryptography (`crypto`), storage and rules (`vault`), analysis (`strength`,
`audit`), generation (`generator`), files (`csv_io`) and interface (`cli`) are separate. The vault
never prints anything and the CLI never touches keys, so each part is tested on its own.

**Input validation.** Every field is validated before it is stored, including duplicate
detection, URL host names and tag rules. The master password must pass a policy based on real
strength analysis, not just "one uppercase, one digit". An edit validates *all* new values
before changing any.

**Data processing.**
- Pattern matching for words, names, sequences, keyboard runs, repeats, years and l33t-speak.
- Entropy estimation that picks the best non-overlapping set of patterns.
- Grouping passwords by SHA-256 hash to find reuse.
- Age calculations and a weighted health score.

**Error handling**
- Custom exceptions: `PMError` → `ValidationError`, `AuthenticationError`, `VaultFormatError`,
  `VaultLockedError`, `NotFoundError`, `DuplicateError`, `StorageError`.
- A wrong password and a tampered file give the same safe message, without revealing which.
- A damaged file (bad JSON, missing fields, wrong format, corrupted base64) gives a clear
  explanation and points to the `.bak` copy.
- Existing vaults and exports are never overwritten.
- Import skips bad rows with line numbers, and the vault is saved once at the end.

---

## 6. Testing

```bash
cd PasswordManagerDemo
python -m unittest discover -s tests -t . -v
```

Result: **32 tests, all passing.** Tests use a lighter scrypt setting so they run in about a
second; the real vault uses N=32768.

| Test file | Tests | Covers |
|---|---|---|
| `test_crypto.py` | 5 | Round trip with Unicode, a fresh nonce every time, key derivation, wrong key and five kinds of tampering, unsafe scrypt settings rejected |
| `test_strength_generator.py` | 8 | Common passwords, each pattern type, random vs passphrase strength, short-password cap, repeated chunks, time formatting, generator rules, passphrase entropy |
| `test_vault.py` | 11 | Validators, master-password policy, nothing readable on disk, `.bak` copy, wrong password, tampered ciphertext and settings, damaged files, CRUD, duplicates, all-or-nothing edits, password history and reuse, lock, master change (old password opens neither vault nor backup) |
| `test_audit_csv_cli.py` | 8 | Health report on the demo vault, a perfect score, browser CSV import with bad rows, import/export errors, menu sessions: weak master rejected, 3 wrong attempts, auto-lock, refusing a weak password, friendly errors |
