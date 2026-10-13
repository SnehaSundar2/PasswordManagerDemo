"""Shared fixtures: temporary folders, a fast KDF and a controllable clock."""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from pwmanager.vault import Vault

FAST_KDF = {"name": "scrypt", "n": 2 ** 10, "r": 8, "p": 1}  # tests only; real vaults use 2**15
MASTER = "Velvet-Harbor-Quiz-Tango-Lemon-42"
NEW_MASTER = "Orbit-Cactus-Meadow-Violin-Jazz-77"


class FakeNow:
    def __init__(self, start=datetime(2026, 10, 13, 9, 0, 0)):
        self.current = start

    def __call__(self):
        return self.current

    def advance(self, **kwargs):
        self.current += timedelta(**kwargs)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "vault.pmv"
        self.now = FakeNow()

    def new_vault(self):
        return Vault.create(self.path, MASTER, kdf=FAST_KDF, now=self.now)

    def reopen(self, password=MASTER):
        return Vault.open(self.path, password, now=self.now)
