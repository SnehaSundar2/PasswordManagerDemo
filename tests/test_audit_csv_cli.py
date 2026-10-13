"""Health check, CSV import/export and end-to-end menu sessions."""

import csv
import io
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from pwmanager import audit, csv_io
from pwmanager.cli import PasswordManagerCLI
from pwmanager.demo import DEMO_MASTER, create_demo_vault
from pwmanager.exceptions import StorageError
from tests.helpers import FAST_KDF, MASTER, TempDirTest

SAMPLE_CSV = Path(__file__).parent.parent / "sample_data" / "browser_export_sample.csv"


class TestAuditAndCSV(TempDirTest):
    def test_health_report_on_demo_vault(self):
        vault = create_demo_vault(self.path, kdf=FAST_KDF)
        r = audit.health_report(vault)
        sites = lambda entries: sorted(e.site for e in entries)
        self.assertEqual(sites(r["weak"]), ["College Portal", "Music App", "Shopping Site", "Wi-Fi Router"])
        self.assertEqual([sites(g) for g in r["reused"]], [["Music App", "Shopping Site"]])
        self.assertEqual(sites(r["old"]), ["Example Bank", "Wi-Fi Router"])
        self.assertIn("College Portal", sites(r["personal"]))
        self.assertEqual((r["total"], r["healthy"]), (7, 2))
        self.assertLess(r["score"], 75)
        self.assertEqual(audit.category_counts(vault)["email"], 1)

    def test_healthy_vault_scores_100(self):
        vault = self.new_vault()
        vault.add("A", "a", "Xq7!mZ2@pL9#vR4$")
        vault.add("B", "b", "Kp2@vL9!mX4#qR7z")
        self.assertEqual(audit.health_report(vault)["score"], 100)

    def test_import_sample_browser_export(self):
        vault = self.new_vault()
        added, problems = csv_io.import_csv(vault, SAMPLE_CSV)
        self.assertEqual(added, 3)
        self.assertEqual([p.split(":")[0] for p in problems], ["Line 5", "Line 6", "Line 7"])
        self.assertIn("Password cannot be empty", problems[0])
        self.assertIn("already an entry", problems[1])
        self.assertIn("photos.example.net", [e.site for e in vault.list()])  # site taken from the URL
        self.assertEqual(len(self.reopen().entries), 3)                       # saved once at the end

    def test_import_and_export_errors(self):
        vault = self.new_vault()
        bad = self.dir / "bad.csv"
        bad.write_text("title,secret\nx,y\n", encoding="utf-8")
        with self.assertRaises(StorageError):
            csv_io.import_csv(vault, bad)
        with self.assertRaises(StorageError):
            csv_io.import_csv(vault, self.dir / "missing.csv")
        vault.add("Mail", "s", "Xq7!mZ2@pL9#vR4$", tags="email")
        out = self.dir / "export.csv"
        self.assertEqual(csv_io.export_csv(vault, out), 1)
        with out.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows[0]["password"], "Xq7!mZ2@pL9#vR4$")
        with self.assertRaises(StorageError):
            csv_io.export_csv(vault, out)  # never overwrite


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def run_cli(path, inputs, secrets, clock=None, auto_lock=300):
    out = io.StringIO()
    secret_iter, input_iter = iter(secrets), iter(inputs)
    clock = clock or FakeClock()

    def fake_input(prompt=""):
        value = next(input_iter)
        if value == "<wait 10 minutes>":
            clock.t += 600
            value = next(input_iter)
        return value

    cli = PasswordManagerCLI(path, read_secret=lambda prompt: next(secret_iter), clock=clock, auto_lock=auto_lock)
    with patch("builtins.input", fake_input), redirect_stdout(out):
        cli.run()
    return out.getvalue(), cli


class TestCLI(TempDirTest):
    def test_create_vault_rejects_weak_master_first(self):
        out, cli = run_cli(self.path, ["0"], ["password1234", "password1234", MASTER, MASTER])
        self.assertIn("The master password is very weak", out)
        self.assertIn("Vault created and unlocked.", out)
        self.assertTrue(self.path.exists())

    def test_three_wrong_passwords_exit(self):
        create_demo_vault(self.path, kdf=FAST_KDF)
        out, cli = run_cli(self.path, [], ["guess-one", "guess-two", "guess-three"])
        self.assertIn("1 attempt(s) left", out)
        self.assertIn("Too many wrong attempts", out)

    def test_add_view_and_auto_lock(self):
        create_demo_vault(self.path, kdf=FAST_KDF)
        out, cli = run_cli(self.path, [
            "4", "Library", "sneha", "", "", "books",          # add; empty password -> generated
            "3", "8", "n",                                       # view, don't reveal
            "<wait 10 minutes>", "1",                            # idle -> auto-lock -> asks master again
            "0"], [DEMO_MASTER, "", DEMO_MASTER])
        self.assertIn("Generated a 20-character password", out)
        self.assertIn("Saved as entry #8.", out)
        self.assertIn("#8 Library", out)
        self.assertIn("locked after 5 minutes without activity", out)
        self.assertIn("Vault locked. Goodbye!", out)
        self.assertTrue(cli.vault.is_locked)

    def test_weak_password_can_be_refused_and_errors_are_friendly(self):
        create_demo_vault(self.path, kdf=FAST_KDF)
        out, _ = run_cli(self.path, [
            "4", "Forum", "sneha", "n",                          # weak typed password, refuse to save
            "42",                                                # invalid option
            "3", "99",                                           # unknown entry
            "12", "nope",                                        # export not confirmed
            "0"], [DEMO_MASTER, "football"])
        self.assertIn("Very weak", out)
        self.assertIn("Cancelled — choose a stronger password", out)
        self.assertIn("Invalid option", out)
        self.assertIn("There is no entry #99", out)
        self.assertIn("NOT encrypted", out)
        self.assertNotIn("Exported", out)
