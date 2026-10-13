import math
import string
import unittest

from pwmanager import generator
from pwmanager.exceptions import ValidationError
from pwmanager.strength import analyse, format_duration
from pwmanager.wordlist import WORDS


class TestStrength(unittest.TestCase):
    def test_common_passwords_are_very_weak(self):
        for pw in ["password", "P@ssw0rd", "123456", "qwerty", "iloveyou", "Admin"]:
            s = analyse(pw)
            self.assertEqual((s.score, s.crack_time), (0, "instantly"), pw)
            self.assertIn("most common", s.warnings[0])

    def test_patterns_are_recognised(self):
        cases = {"abcdefgh12": "sequence", "Poiuytre#55": "keyboard", "Rahul1998": "first name", "Priya@2005": "year",
                 "xxxxxxxx77": "repeated", "Sunshine2024!": "common password"}
        for pw, word in cases.items():
            s = analyse(pw)
            self.assertLessEqual(s.score, 1, pw)
            self.assertTrue(any(word in w for w in s.warnings), (pw, s.warnings))
        personal = analyse("Sneha@Gmail99", user_inputs=("Gmail", "sneha.s@example.com"))
        self.assertTrue(any("your name" in w for w in personal.warnings))
        self.assertLess(personal.score, 2)

    def test_random_and_passphrase_strength(self):
        self.assertEqual(analyse("kX9#mQ2$vL7@pR4!").score, 4)
        self.assertEqual(analyse("correct horse battery staple").score, 2)  # 4 common words: only "fair"
        self.assertGreaterEqual(analyse("maple-river-cloud-tiger-lemon-jazz").score, 3)
        self.assertLessEqual(analyse("kX9#m!").score, 1)                      # too short whatever the mix
        self.assertEqual(analyse("").score, 0)

    def test_repeated_chunk_is_not_stronger(self):
        self.assertLess(analyse("Xq7!Xq7!Xq7!Xq7!").entropy, analyse("Xq7!mZ2@pL9#vR4$").entropy / 2)

    def test_format_duration(self):
        self.assertEqual(format_duration(0.5), "instantly")
        self.assertEqual(format_duration(1), "1 second")
        self.assertEqual(format_duration(7200), "2 hours")
        self.assertEqual(format_duration(86400 * 45), "1 month")
        self.assertEqual(format_duration(1e12), "centuries")


class TestGenerator(unittest.TestCase):
    def test_password_rules(self):
        for _ in range(50):
            pw, bits = generator.generate_password(16)
            self.assertEqual(len(pw), 16)
            for chars in (string.ascii_lowercase, string.ascii_uppercase, string.digits, generator.SYMBOLS):
                self.assertTrue(set(pw) & set(chars), pw)       # every type present
            self.assertFalse(set(pw) & generator.AMBIGUOUS)    # no I l 1 O 0 o
        digits_only, bits = generator.generate_password(12, lower=False, upper=False, symbols=False)
        self.assertTrue(digits_only.isdigit())
        self.assertEqual(bits, round(12 * math.log2(8), 1))   # 8 digits left after removing 0 and 1
        self.assertEqual(len({generator.generate_password(20)[0] for _ in range(100)}), 100)

    def test_password_validation(self):
        for kwargs in ({"length": 7}, {"length": 129}, {"length": "ten"},
                       {"lower": False, "upper": False, "digits": False, "symbols": False}):
            with self.assertRaises(ValidationError, msg=kwargs):
                generator.generate_password(**kwargs)

    def test_passphrase(self):
        phrase, bits = generator.generate_passphrase(5, ".", capitalize=True, add_number=True)
        parts = phrase.split(".")
        self.assertEqual(len(parts), 6)
        self.assertTrue(all(p.lower() in WORDS for p in parts[:5]) and parts[5].isdigit())
        self.assertTrue(all(p[0].isupper() for p in parts[:5]))
        self.assertAlmostEqual(bits, 5 * math.log2(len(WORDS)) + math.log2(100), places=0)
        for args in ((3,), (13,), (6, "/")):
            with self.assertRaises(ValidationError):
                generator.generate_passphrase(*args)


if __name__ == "__main__":
    unittest.main()
