"""Entry point for the Password Manager Demo.

Usage:
    python main.py                        # open (or create) data/vault.pmv
    python main.py --demo                 # try a ready-made demo vault (password is printed)
    python main.py --generate 24          # print a random 24-character password and exit
    python main.py --passphrase 6         # print a 6-word passphrase and exit
    python main.py --check                # check a password's strength (typed hidden) and exit
"""

import argparse
import getpass
import logging
import sys
from pathlib import Path

from pwmanager import generator
from pwmanager.cli import PasswordManagerCLI, strength_line
from pwmanager.demo import DEMO_MASTER, create_demo_vault
from pwmanager.exceptions import PMError

DEMO_PATH = Path("data/demo_vault.pmv")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):  # show •, ■ and ₹ correctly on Windows consoles
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Password Manager Demo (educational)")
    parser.add_argument("--vault", default="data/vault.pmv", help="vault file (default data/vault.pmv)")
    parser.add_argument("--demo", action="store_true", help="open a demo vault with sample entries")
    parser.add_argument("--generate", nargs="?", const=20, metavar="LENGTH", help="print a random password")
    parser.add_argument("--passphrase", nargs="?", const=6, metavar="WORDS", help="print a random passphrase")
    parser.add_argument("--check", action="store_true", help="check the strength of a password (typed hidden)")
    args = parser.parse_args(argv)

    logging.basicConfig(filename="pwmanager.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        if args.generate is not None:
            password, bits = generator.generate_password(args.generate)
            print(f"{password}\n~{bits:.0f} bits")
            return 0
        if args.passphrase is not None:
            phrase, bits = generator.generate_passphrase(args.passphrase)
            print(f"{phrase}\n~{bits:.0f} bits")
            return 0
        if args.check:
            strength, line = strength_line(getpass.getpass("Password to check (hidden): "))
            print(line)
            for item in strength.warnings + strength.suggestions:
                print(f"  - {item}")
            return 0

        path = Path(args.vault)
        if args.demo:
            path = DEMO_PATH
            if not path.exists():
                create_demo_vault(path)
            print(f"Demo vault: {path}\nDemo master password: {DEMO_MASTER}\n"
                  "(The demo contains fictional accounts, some with deliberately weak passwords.)")
        PasswordManagerCLI(path).run()
        return 0
    except PMError as exc:
        print(f"Error: {exc}")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nExiting. The vault is locked.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
