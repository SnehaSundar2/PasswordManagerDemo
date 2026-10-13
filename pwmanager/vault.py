"""The encrypted vault: create, unlock, lock, and manage entries.

On disk the vault is a small JSON file. Only the KDF settings, salt, nonce,
ciphertext and tag are visible; site names, usernames and passwords are all
inside the encrypted part:

    {"format": "pmdemo-vault-1",
     "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": "<base64>"},
     "nonce": "<base64>", "ciphertext": "<base64>", "tag": "<base64>"}

The format and KDF settings are authenticated too, so changing any byte of
the file (even the settings) is detected when the vault is opened.
"""

import base64
import binascii
import hmac
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

from . import crypto
from . import validators as v
from .exceptions import (
    AuthenticationError, DuplicateError, NotFoundError, StorageError, ValidationError, VaultFormatError,
    VaultLockedError,
)
from .models import HISTORY_SIZE, Entry

log = logging.getLogger("pwmanager")

FORMAT = "pmdemo-vault-1"
MAX_ENTRIES = 1000


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(text, field):
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise VaultFormatError(f"The vault file is damaged (invalid {field}).") from None


class Vault:
    def __init__(self, path, now=datetime.now):
        self.path = Path(path)
        self._now = now  # injectable clock for tests
        self._keys = None
        self._kdf = None
        self.entries = {}
        self.next_id = 1
        self.created = ""

    # ------------------------------------------------------------ create / open / lock
    @classmethod
    def create(cls, path, master_password, confirm=None, kdf=None, now=datetime.now):
        vault = cls(path, now)
        if vault.path.exists():
            raise StorageError(f"A vault already exists at {vault.path}. Open it, or choose another file.")
        v.validate_master_password(master_password, confirm)
        vault._kdf = {**(kdf or crypto.DEFAULT_KDF), "salt": _b64(crypto.new_salt())}
        vault._keys = vault._derive(master_password)
        vault.created = vault._timestamp()
        vault.save()
        log.info("Created a new vault at %s", vault.path)
        return vault

    @classmethod
    def open(cls, path, master_password, now=datetime.now):
        vault = cls(path, now)
        vault.unlock(master_password)
        return vault

    def _read_file(self):
        if not self.path.exists():
            raise StorageError(f"No vault found at {self.path}. Create one first.")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            raise StorageError(f"Could not read the vault file: {exc}") from exc
        except json.JSONDecodeError:
            raise VaultFormatError("The vault file is damaged (not valid JSON). "
                                   f"If you have {self.path.name}.bak, it holds the previous version.") from None
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise VaultFormatError("This file is not a vault created by this program.")
        for key in ("kdf", "nonce", "ciphertext", "tag"):
            if key not in data:
                raise VaultFormatError(f"The vault file is damaged (missing '{key}').")
        if not isinstance(data["kdf"], dict) or "salt" not in data["kdf"]:
            raise VaultFormatError("The vault file is damaged (bad key-derivation settings).")
        return data

    def _header(self):
        """Authenticated-but-unencrypted part of the file: format + KDF settings + salt."""
        return json.dumps({"format": FORMAT, "kdf": self._kdf}, sort_keys=True).encode("utf-8")

    def _derive(self, master_password):
        salt = _unb64(self._kdf["salt"], "salt")
        try:
            return crypto.derive_keys(master_password, salt, self._kdf)
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultFormatError(f"The vault's key-derivation settings are invalid: {exc}") from None

    def unlock(self, master_password):
        data = self._read_file()
        self._kdf = data["kdf"]
        keys = self._derive(master_password or "")
        plaintext = crypto.decrypt(keys, _unb64(data["nonce"], "nonce"), _unb64(data["ciphertext"], "ciphertext"),
                                   _unb64(data["tag"], "tag"), self._header())
        try:
            payload = json.loads(plaintext.decode("utf-8"))
            self.entries = {e.entry_id: e for e in map(Entry.from_dict, payload["entries"])}
            self.next_id = int(payload["next_id"])
            self.created = payload.get("created", "")
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultFormatError(f"The vault contents are damaged: {exc}") from None
        self._keys = keys
        log.info("Vault unlocked (%d entries)", len(self.entries))

    def lock(self):
        """Forget the keys and decrypted entries; the master password is needed again."""
        self._keys = None
        self.entries = {}
        log.info("Vault locked")

    @property
    def is_locked(self):
        return self._keys is None

    def _require_unlocked(self):
        if self.is_locked:
            raise VaultLockedError("The vault is locked. Enter the master password to unlock it.")

    # ------------------------------------------------------------ saving
    def now(self):
        return self._now()

    def _timestamp(self):
        return self._now().isoformat(timespec="seconds")

    def save(self):
        """Encrypt and write atomically, keeping the previous version as <name>.bak."""
        self._require_unlocked()
        payload = json.dumps({"created": self.created, "next_id": self.next_id,
                              "entries": [e.to_dict() for e in sorted(self.entries.values(),
                                                                      key=lambda e: e.entry_id)]})
        nonce, ciphertext, tag = crypto.encrypt(self._keys, payload.encode("utf-8"), self._header())
        document = {"format": FORMAT, "kdf": self._kdf, "nonce": _b64(nonce),
                    "ciphertext": _b64(ciphertext), "tag": _b64(tag)}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                shutil.copy2(self.path, self.path.with_name(self.path.name + ".bak"))
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(document, fh, indent=1)
            os.replace(tmp, self.path)
        except OSError as exc:
            raise StorageError(f"Could not save the vault: {exc.strerror or exc}") from exc

    # ------------------------------------------------------------ entries
    def _check_duplicate(self, site, username, ignore_id=None):
        key = (site.lower(), username.lower())
        for e in self.entries.values():
            if e.key == key and e.entry_id != ignore_id:
                who = f" for '{username}'" if username else ""
                raise DuplicateError(f"There is already an entry for {site}{who} (#{e.entry_id}). Edit it instead.")

    def add(self, site, username, password, url="", notes="", tags="", save=True):
        self._require_unlocked()
        if len(self.entries) >= MAX_ENTRIES:
            raise ValidationError(f"This demo vault holds at most {MAX_ENTRIES} entries.")
        site, username = v.validate_site(site), v.validate_username(username)
        entry = Entry(entry_id=self.next_id, site=site, username=username, password=v.validate_password(password),
                      url=v.validate_url(url), notes=v.validate_notes(notes), tags=v.validate_tags(tags),
                      created=self._timestamp(), updated=self._timestamp())
        self._check_duplicate(site, username)
        self.entries[entry.entry_id] = entry
        self.next_id += 1
        if save:
            self.save()
        log.info("Added entry #%d (%s)", entry.entry_id, entry.site)  # never log usernames or passwords
        return entry

    def get(self, entry_id):
        self._require_unlocked()
        entry_id = v.validate_entry_id(entry_id)
        try:
            return self.entries[entry_id]
        except KeyError:
            raise NotFoundError(f"There is no entry #{entry_id}.") from None

    def list(self):
        self._require_unlocked()
        return sorted(self.entries.values(), key=lambda e: (e.site.lower(), e.username.lower()))

    def search(self, text):
        """Match site, username, website, tags or notes (never the password)."""
        self._require_unlocked()
        q = (text or "").strip().lower()
        if not q:
            raise ValidationError("Type something to search for.")
        return [e for e in self.list()
                if q in e.site.lower() or q in e.username.lower() or q in e.url.lower()
                or q in e.notes.lower() or any(q in t for t in e.tags)]

    def update(self, entry_id, site=None, username=None, password=None, url=None, notes=None, tags=None):
        """Change fields (None = keep). All values are validated before anything changes."""
        entry = self.get(entry_id)
        changes = {}
        if site is not None:
            changes["site"] = v.validate_site(site)
        if username is not None:
            changes["username"] = v.validate_username(username)
        if url is not None:
            changes["url"] = v.validate_url(url)
        if notes is not None:
            changes["notes"] = v.validate_notes(notes)
        if tags is not None:
            changes["tags"] = v.validate_tags(tags)
        if password is not None:
            password = v.validate_password(password)
            previous = [entry.password] + [h["password"] for h in entry.history]
            if any(hmac.compare_digest(password.encode(), p.encode()) for p in previous):
                raise ValidationError("You have used this password for this account before. Choose a new one.")
            changes["password"] = password
        if not changes:
            raise ValidationError("Nothing to change.")
        if "site" in changes or "username" in changes:
            self._check_duplicate(changes.get("site", entry.site), changes.get("username", entry.username),
                                  ignore_id=entry.entry_id)
        if "password" in changes:
            entry.history.insert(0, {"password": entry.password, "changed": self._timestamp()})
            del entry.history[HISTORY_SIZE:]
            entry.updated = self._timestamp()
        for name, value in changes.items():
            setattr(entry, name, value)
        self.save()
        log.info("Updated entry #%d (%s)", entry.entry_id, ", ".join(sorted(changes)))
        return entry

    def delete(self, entry_id):
        entry = self.get(entry_id)
        del self.entries[entry.entry_id]
        self.save()
        log.info("Deleted entry #%d", entry.entry_id)
        return entry

    # ------------------------------------------------------------ master password
    def verify_master(self, master_password):
        self._require_unlocked()
        keys = self._derive(master_password or "")
        if not (hmac.compare_digest(keys[0], self._keys[0]) and hmac.compare_digest(keys[1], self._keys[1])):
            raise AuthenticationError("The current master password is not correct.")

    def change_master(self, current, new, confirm=None):
        self.verify_master(current)
        v.validate_master_password(new, confirm)
        if hmac.compare_digest(current.encode(), new.encode()):
            raise ValidationError("The new master password must be different from the current one.")
        self._kdf = {**{k: val for k, val in self._kdf.items() if k != "salt"}, "salt": _b64(crypto.new_salt())}
        self._keys = self._derive(new)  # new salt -> completely new keys
        self.save()
        # the .bak copy still opens with the OLD password; replace it so a leaked old password is useless
        try:
            shutil.copy2(self.path, self.path.with_name(self.path.name + ".bak"))
        except OSError as exc:
            raise StorageError(f"Master password changed, but the backup file could not be updated: {exc}") from exc
        log.info("Master password changed")
