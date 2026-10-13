"""Password Manager Demo.

An educational, command-line password manager: an encrypted vault protected
by one master password, a password and passphrase generator, a strength
checker, a vault health audit and CSV import/export.

This is a learning project. For real passwords use an established, audited
password manager.
"""

import logging

__version__ = "1.0.0"

# Stay silent unless the application (main.py) configures logging. Passwords are never logged.
logging.getLogger("pwmanager").addHandler(logging.NullHandler())
