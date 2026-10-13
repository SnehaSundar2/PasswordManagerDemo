import base64
import json

from pwmanager import validators as v
from pwmanager.exceptions import (
    AuthenticationError, DuplicateError, NotFoundError, StorageError, ValidationError, VaultFormatError,
    VaultLockedError,
)
from pwmanager.models import HISTORY_SIZE
from pwmanager.vault import Vault
from tests.helpers import FAST_KDF, MASTER, NEW_MASTER, TempDirTest


class TestValidators(TempDirTest):
    def test_text_fields(self):
        self.assertEqual(v.validate_site("  My   Bank "), "My Bank")
        self.assertEqual(v.validate_url("accounts.example.com"), "https://accounts.example.com")
        self.assertEqual(v.validate_tags("Work, email ,work"), ["email", "work"])
        for call, bad in [(v.validate_site, ""), (v.validate_site, "x" * 61), (v.validate_url, "not a site"),
                          (v.validate_url, "ftp://x.example.com"), (v.validate_tags, "a,b,c,d,e,f"),
                          (v.validate_tags, "bad tag!"), (v.validate_entry_id, "abc"), (v.validate_entry_id, "0")]:
            with self.assertRaises(ValidationError, msg=bad):
                call(bad)

    def test_passwords_are_kept_exactly(self):
        self.assertEqual(v.validate_password("my pass phrase"), "my pass phrase")
        for bad in ["", " leading", "trailing ", "tab\there", "x" * 257]:
            with self.assertRaises(ValidationError, msg=bad):
                v.validate_password(bad)

    def test_master_password_policy(self):
        self.assertEqual(v.validate_master_password(MASTER, MASTER), MASTER)
        for pw, confirm in [("Short1!", None), ("password1234", None), ("aaaaaaaaaaaaaaa", None),
                            (MASTER, MASTER + "x")]:
            with self.assertRaises(ValidationError, msg=pw):
                v.validate_master_password(pw, confirm)


class TestVaultFile(TempDirTest):
    def test_create_reopen_and_nothing_readable_on_disk(self):
        vault = self.new_vault()
        vault.add("Example Bank", "sneha", "Xq7!mZ2@pL9#vR4$", "bank.example.com", "PIN in safe", "finance")
        raw = self.path.read_text(encoding="utf-8")
        for secret in ("Example Bank", "sneha", "Xq7!mZ2@pL9#vR4$", "PIN in safe"):
            self.assertNotIn(secret, raw)
        again = self.reopen()
        self.assertEqual(again.get(1).password, "Xq7!mZ2@pL9#vR4$")
        self.assertTrue(self.path.with_name("vault.pmv.bak").exists())  # previous version kept
        with self.assertRaises(StorageError):
            self.new_vault()  # never overwrite an existing vault

    def test_wrong_password_and_tampering(self):
        self.new_vault().add("Mail", "s", "Xq7!mZ2@pL9#vR4$")
        with self.assertRaises(AuthenticationError):
            self.reopen("Wrong-Master-Password-123")
        original = json.loads(self.path.read_text(encoding="utf-8"))
        ct = bytearray(base64.b64decode(original["ciphertext"]))
        ct[5] ^= 0x01
        for change in ({"ciphertext": base64.b64encode(bytes(ct)).decode()},
                       {"kdf": {**original["kdf"], "n": 2 ** 11}}):
            self.path.write_text(json.dumps({**original, **change}), encoding="utf-8")
            with self.assertRaises(AuthenticationError):
                self.reopen()

    def test_damaged_files_give_clear_errors(self):
        self.new_vault()
        original = json.loads(self.path.read_text(encoding="utf-8"))
        cases = ["{not json", json.dumps({**original, "format": "something-else"}),
                 json.dumps({k: val for k, val in original.items() if k != "tag"}),
                 json.dumps({**original, "nonce": "%%%"})]
        for text in cases:
            self.path.write_text(text, encoding="utf-8")
            with self.assertRaises(VaultFormatError):
                self.reopen()
        with self.assertRaises(StorageError):
            Vault.open(self.dir / "missing.pmv", MASTER)


class TestEntries(TempDirTest):
    def setUp(self):
        super().setUp()
        self.vault = self.new_vault()
        self.vault.add("Example Mail", "sneha@example.com", "Xq7!mZ2@pL9#vR4$", tags="email")
        self.vault.add("Code Hosting", "snehadev", "Kp2@vL9!mX4#qR7z", notes="work laptop", tags="work")

    def test_add_get_list_search_delete(self):
        self.assertEqual([e.site for e in self.vault.list()], ["Code Hosting", "Example Mail"])
        self.assertEqual([e.entry_id for e in self.vault.search("laptop")], [2])
        self.assertEqual(self.vault.search("Xq7!"), [])           # passwords are never searched
        with self.assertRaises(DuplicateError):
            self.vault.add("example mail", "SNEHA@example.com", "Other!Pass99x")
        self.vault.delete(1)
        with self.assertRaises(NotFoundError):
            self.vault.get(1)
        self.assertEqual(len(self.reopen().entries), 1)

    def test_update_is_all_or_nothing(self):
        with self.assertRaises(ValidationError):
            self.vault.update(1, site="New Name", url="not a site")
        self.assertEqual(self.vault.get(1).site, "Example Mail")
        with self.assertRaises(DuplicateError):
            self.vault.update(2, site="Example Mail", username="sneha@example.com")
        self.vault.update(1, site="Mail (personal)", tags="email,personal")
        self.assertEqual(self.reopen().get(1).tags, ["email", "personal"])

    def test_password_history_and_reuse(self):
        self.now.advance(days=30)
        for i in range(HISTORY_SIZE + 2):
            self.vault.update(1, password=f"New!Password#{i}x")
        entry = self.vault.get(1)
        self.assertEqual(len(entry.history), HISTORY_SIZE)
        self.assertEqual(entry.history[0]["password"], f"New!Password#{HISTORY_SIZE}x")
        self.assertEqual(entry.updated, "2026-11-12T09:00:00")
        with self.assertRaises(ValidationError):
            self.vault.update(1, password=f"New!Password#{HISTORY_SIZE + 1}x")  # current password
        with self.assertRaises(ValidationError):
            self.vault.update(1, password="New!Password#4x")                      # in history

    def test_lock_and_change_master(self):
        self.vault.lock()
        with self.assertRaises(VaultLockedError):
            self.vault.list()
        self.vault.unlock(MASTER)
        with self.assertRaises(AuthenticationError):
            self.vault.change_master("not-the-master", NEW_MASTER, NEW_MASTER)
        with self.assertRaises(ValidationError):
            self.vault.change_master(MASTER, "weakpassword", "weakpassword")
        self.vault.change_master(MASTER, NEW_MASTER, NEW_MASTER)
        for path in (self.path, self.path.with_name("vault.pmv.bak")):
            with self.assertRaises(AuthenticationError):
                Vault.open(path, MASTER)                # old password opens neither the vault nor its backup
            self.assertEqual(len(Vault.open(path, NEW_MASTER).entries), 2)

    def test_fast_kdf_is_recorded_in_file(self):
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["kdf"]["n"], FAST_KDF["n"])
