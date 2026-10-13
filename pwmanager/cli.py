"""Interactive menu-driven command-line interface.

Security behaviour:
  * master and entry passwords are typed with getpass (not shown on screen)
  * passwords are masked in lists and only revealed on request
  * 3 wrong master passwords end the program
  * the vault locks itself after a period without activity
"""

import getpass
import logging
import time

from . import audit, csv_io, generator
from . import validators as v
from .exceptions import AuthenticationError, PMError, ValidationError
from .strength import analyse
from .vault import Vault

log = logging.getLogger("pwmanager")

MENU = """
================== PASSWORD MANAGER (DEMO) ==================
 ENTRIES                          TOOLS
  1. List all entries              7. Generate a password
  2. Search                        8. Generate a passphrase
  3. View an entry                 9. Check a password's strength
  4. Add an entry                 10. Vault health check
  5. Edit an entry                11. Import from CSV
  6. Delete an entry              12. Export to CSV (unencrypted!)
                                  13. Change master password
                                  14. Lock now
  0. Lock and exit
============================================================="""
MAX_ATTEMPTS = 3
AUTO_LOCK_SECONDS = 300


def ask(prompt):
    return input(f"  {prompt}: ").strip()


def confirm(prompt):
    return ask(f"{prompt} [y/N]").lower() in {"y", "yes"}


def strength_line(password, user_inputs=()):
    s = analyse(password, user_inputs)
    bar = "■" * (s.score + 1) + "□" * (4 - s.score)
    return s, f"{bar} {s.label} · ~{s.entropy:.0f} bits · offline cracking: {s.crack_time}"


class PasswordManagerCLI:
    def __init__(self, path, read_secret=getpass.getpass, clock=time.monotonic, auto_lock=AUTO_LOCK_SECONDS):
        self.path = path
        self.read_secret = read_secret   # injectable so tests can type "hidden" passwords
        self.clock = clock
        self.auto_lock = auto_lock
        self.vault = None
        self.last_activity = clock()
        self.actions = {
            "1": self.list_entries, "2": self.search, "3": self.view, "4": self.add, "5": self.edit,
            "6": self.delete, "7": self.gen_password, "8": self.gen_passphrase, "9": self.check_strength,
            "10": self.health, "11": self.import_csv, "12": self.export_csv, "13": self.change_master,
            "14": self.lock_now,
        }

    def secret(self, prompt):
        return self.read_secret(f"  {prompt}: ")

    # ---------------------------------------------------------- start-up
    def start(self):
        """Create a vault if none exists, otherwise unlock it. Returns False if access is refused."""
        if not self.path.exists():
            print(f"\n  No vault found at {self.path}. Let's create one.")
            print("  Choose a strong master password — it cannot be recovered if you forget it.")
            print("  Tip: a passphrase of 5-6 random words works well (option 8 can suggest one later).")
            for _ in range(MAX_ATTEMPTS):
                try:
                    self.vault = Vault.create(self.path, self.secret("New master password"),
                                              self.secret("Type it again"))
                    print("  Vault created and unlocked.")
                    return True
                except ValidationError as exc:
                    print(f"  ! {exc}")
            return False
        return self.unlock()

    def unlock(self):
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                if self.vault is None:
                    self.vault = Vault.open(self.path, self.secret("Master password"))
                else:
                    self.vault.unlock(self.secret("Master password"))
                self.last_activity = self.clock()
                print(f"  Unlocked. {len(self.vault.entries)} entr{'y' if len(self.vault.entries) == 1 else 'ies'}.")
                return True
            except AuthenticationError as exc:
                log.warning("Failed unlock attempt %d", attempt)
                left = MAX_ATTEMPTS - attempt
                print(f"  ! {exc}" + (f" {left} attempt(s) left." if left else ""))
        print("  Too many wrong attempts. Exiting.")
        return False

    def run(self):
        try:
            if not self.start():
                return
        except PMError as exc:
            print(f"  ! Error: {exc}")
            return
        while True:
            print(MENU)
            choice = ask("Choose an option")
            if self.clock() - self.last_activity > self.auto_lock and not self.vault.is_locked:
                self.vault.lock()
                print(f"  The vault was locked after {self.auto_lock // 60} minutes without activity.")
            if choice == "0":
                self.vault.lock()
                print("  Vault locked. Goodbye!")
                return
            action = self.actions.get(choice)
            if action is None:
                print("  ! Invalid option, please enter a number from the menu.")
                continue
            if self.vault.is_locked and not self.unlock():
                return
            try:
                action()
            except PMError as exc:
                log.warning("%s failed: %s", action.__name__, type(exc).__name__)  # message may contain data
                print(f"  ! Error: {exc}")
            except (KeyboardInterrupt, EOFError):
                print("\n  Cancelled.")
            except Exception:  # safety net; details go to the log file (never passwords)
                log.exception("Unexpected error in %s", action.__name__)
                print("  ! An unexpected error occurred. See pwmanager.log for details.")
            self.last_activity = self.clock()

    # ---------------------------------------------------------- entries
    def show_list(self, entries):
        if not entries:
            print("  No entries found.")
            return
        print(f"  {'#':>3}  {'SITE':<22} {'USERNAME':<28} {'PASSWORD':<13} TAGS")
        print(f"  {'-' * 3}  {'-' * 22} {'-' * 28} {'-' * 13} {'-' * 12}")
        for e in entries:
            print(f"  {e.entry_id:>3}  {e.site[:22]:<22} {e.username[:28]:<28} {e.masked():<13} {', '.join(e.tags)}")

    def list_entries(self):
        self.show_list(self.vault.list())

    def search(self):
        self.show_list(self.vault.search(ask("Search for (site, username, website, tag or note)")))

    def view(self):
        e = self.vault.get(ask("Entry number"))
        print(f"\n  #{e.entry_id} {e.site}")
        print(f"  Username : {e.username or '-'}")
        print(f"  Password : {e.masked()}")
        print(f"  Website  : {e.url or '-'}")
        print(f"  Tags     : {', '.join(e.tags) or '-'}")
        print(f"  Notes    : {e.notes or '-'}")
        print(f"  Created {e.created.replace('T', ' ')} · password changed {e.updated.replace('T', ' ')}"
              f" · {len(e.history)} older password(s) remembered")
        print(f"  Strength : {strength_line(e.password, (e.site, e.username))[1]}")
        if confirm("Show the password on screen?"):
            print(f"  Password : {e.password}")

    def ask_password(self, user_inputs=()):
        """Type a password (hidden) or press Enter to generate one."""
        typed = self.secret("Password (leave empty to generate a strong one)")
        if not typed:
            password, bits = generator.generate_password(20)
            print(f"  Generated a 20-character password (~{bits:.0f} bits).")
            return password
        strength, line = strength_line(typed, user_inputs)
        print(f"  {line}")
        for w in strength.warnings:
            print(f"    - {w}")
        if strength.score < 2 and not confirm("This password is weak. Save it anyway?"):
            raise ValidationError("Cancelled — choose a stronger password or let the generator create one.")
        return typed

    def add(self):
        site = v.validate_site(ask("Site or service name"))
        username = v.validate_username(ask("Username or email"))
        password = self.ask_password((site, username))
        entry = self.vault.add(site, username, password, ask("Website (optional)"), ask("Notes (optional)"),
                               ask("Tags, comma-separated (optional, e.g. work, email)"))
        print(f"  Saved as entry #{entry.entry_id}.")

    def edit(self):
        e = self.vault.get(ask("Entry number"))
        print("  Press Enter to keep the current value.")
        site = ask(f"Site [{e.site}]") or None
        username = ask(f"Username [{e.username or '-'}]") or None
        url = ask(f"Website [{e.url or '-'}]") or None
        notes = ask(f"Notes [{e.notes or '-'}]") or None
        tags = ask(f"Tags [{', '.join(e.tags) or '-'}]") or None
        password = self.ask_password((site or e.site, username or e.username)) \
            if confirm("Change the password?") else None
        self.vault.update(e.entry_id, site, username, password, url, notes, tags)
        print(f"  Entry #{e.entry_id} updated.")

    def delete(self):
        e = self.vault.get(ask("Entry number"))
        if not confirm(f"Delete '{e.site}' ({e.username or 'no username'}) permanently?"):
            print("  Cancelled. Nothing was deleted.")
            return
        self.vault.delete(e.entry_id)
        print(f"  Deleted entry #{e.entry_id}.")

    # ---------------------------------------------------------- tools
    def gen_password(self):
        length = v.validate_int(ask("Length [20]") or 20, "Length", 8, 128)
        symbols = not ask("Include symbols? [Y/n]").lower().startswith("n")
        password, bits = generator.generate_password(length, symbols=symbols)
        print(f"\n  {password}\n  ~{bits:.0f} bits · {strength_line(password)[1]}")

    def gen_passphrase(self):
        words = v.validate_int(ask("Number of words [6]") or 6, "Number of words", 4, 12)
        phrase, bits = generator.generate_passphrase(words, "-", capitalize=confirm("Capitalise words?"),
                                                     add_number=confirm("Add a number?"))
        print(f"\n  {phrase}\n  ~{bits:.0f} bits of randomness · easy to type and remember")

    def check_strength(self):
        password = self.secret("Password to check (not saved)")
        strength, line = strength_line(password)
        print(f"  {line}")
        for w in strength.warnings:
            print(f"    ! {w}")
        for tip in strength.suggestions:
            print(f"    → {tip}")

    def health(self):
        r = audit.health_report(self.vault)
        print(f"\n  Vault health: {r['score']}/100 — {r['grade']}  ({r['healthy']} of {r['total']} entries have no issues)")
        sections = [("Weak passwords", r["weak"]), ("Fair passwords (could be stronger)", r["fair"]),
                    (f"Not changed for over {audit.OLD_AFTER_DAYS} days", r["old"]),
                    ("Contain the site name or username", r["personal"])]
        for title, entries in sections:
            if entries:
                print(f"  {title}: " + ", ".join(f"#{e.entry_id} {e.site}" for e in entries))
        for group in r["reused"]:
            print("  Same password used for: " + ", ".join(f"#{e.entry_id} {e.site}" for e in group))
        if r["weak"] or r["reused"]:
            print("  → Use option 5 to change these passwords (leave the password empty to generate one).")
        counts = audit.category_counts(self.vault)
        if counts:
            print("  By tag: " + ", ".join(f"{t} {n}" for t, n in counts.items()))

    def import_csv(self):
        added, problems = csv_io.import_csv(self.vault, ask("CSV file to import"))
        print(f"  Imported {added} entr{'y' if added == 1 else 'ies'}.")
        for p in problems:
            print(f"    - skipped {p}")
        if added:
            print("  Tip: delete the CSV file now — it contains your passwords in plain text.")

    def export_csv(self):
        print("  WARNING: the exported file is NOT encrypted. Anyone who opens it can read every password.")
        if ask("Type EXPORT to continue") != "EXPORT":
            print("  Cancelled.")
            return
        self.vault.verify_master(self.secret("Confirm your master password"))
        path = ask("File name [passwords_export.csv]") or "passwords_export.csv"
        count = csv_io.export_csv(self.vault, path)
        print(f"  Exported {count} entries to {path}. Delete it as soon as you no longer need it.")

    def change_master(self):
        current = self.secret("Current master password")
        self.vault.change_master(current, self.secret("New master password"), self.secret("Type it again"))
        print("  Master password changed. The vault and its backup were re-encrypted with new keys.")

    def lock_now(self):
        self.vault.lock()
        print("  Vault locked.")
