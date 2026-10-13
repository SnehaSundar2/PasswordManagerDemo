"""Custom exception hierarchy.

Every deliberate error derives from PMError so the CLI can catch a single
base class and show a friendly message instead of a traceback.
"""


class PMError(Exception):
    """Base class for all password manager errors."""


class ValidationError(PMError):
    """Raised when user input fails validation."""


class AuthenticationError(PMError):
    """Wrong master password, or the vault file was modified by someone else."""


class VaultFormatError(PMError):
    """The vault file is not a valid vault (wrong format, missing fields)."""


class VaultLockedError(PMError):
    """An action needs the vault to be unlocked first."""


class NotFoundError(PMError):
    """An entry does not exist."""


class DuplicateError(PMError):
    """An entry for the same site and username already exists."""


class StorageError(PMError):
    """The vault or an export file cannot be read or written."""
