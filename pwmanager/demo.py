"""A demo vault with fictional accounts, including some deliberately bad passwords
so the health check has something to find."""

from datetime import timedelta

from .vault import Vault

DEMO_MASTER = "Velvet-Harbor-Quiz-Tango-Lemon-42"
DEMO_ENTRIES = [
    # site, username, password, url, notes, tags, age_days
    ("Example Mail", "sneha.demo@example.com", "m7#Rq2!vXp9$Lt4w", "mail.example.com", "", "email,personal", 40),
    ("Example Bank", "sneha_demo", "Velvet!Oak9Trail#2", "netbanking.example.com", "Demo only", "finance", 500),
    ("College Portal", "ENGDEMO001", "college123", "portal.example.edu", "", "education", 200),
    ("Shopping Site", "sneha.demo@example.com", "Sunshine2024!", "shop.example.com", "", "shopping", 30),
    ("Music App", "sneha.demo", "Sunshine2024!", "music.example.com", "Same as shopping (bad!)", "fun", 30),
    ("Code Hosting", "snehademo", "pR4!kX9#mQ2$vL7@zT", "code.example.com", "", "work", 10),
    ("Wi-Fi Router", "admin", "admin", "router.example.net", "Default password - change it!", "home", 700),
]


def create_demo_vault(path, kdf=None):
    vault = Vault.create(path, DEMO_MASTER, kdf=kdf)
    now = vault.now()
    for site, user, password, url, notes, tags, age in DEMO_ENTRIES:
        entry = vault.add(site, user, password, url, notes, tags, save=False)
        entry.created = entry.updated = (now - timedelta(days=age)).isoformat(timespec="seconds")
    vault.save()
    return vault
