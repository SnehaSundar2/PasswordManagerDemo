"""Data model for one saved login."""

from dataclasses import asdict, dataclass, field

HISTORY_SIZE = 5  # previous passwords remembered per entry


@dataclass
class Entry:
    entry_id: int
    site: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    tags: list = field(default_factory=list)
    created: str = ""
    updated: str = ""                          # when the password was last changed
    history: list = field(default_factory=list)  # [{"password": ..., "changed": iso}] newest first

    @property
    def key(self):
        """Identity used to stop duplicates: same site + username."""
        return (self.site.lower(), self.username.lower())

    def masked(self):
        return "•" * min(len(self.password), 12)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)
