"""passgen - a dependency-free password, passphrase and PIN generator.

Example:
    >>> from passgen import generate_password, PasswordOptions
    >>> options = PasswordOptions(length=12)
    >>> len(generate_password(options))
    12
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Goutam Singh"
__email__ = "25mcaa22@kristujayanti.com"
__license__ = "MIT"

from .generator import (
    CONFUSABLE_CHARS,
    DIGITS,
    LOWERCASE,
    RECOVERY_ALPHABET,
    SYMBOLS,
    UPPERCASE,
    PasswordError,
    PasswordOptions,
    char_pool,
    generate_batch,
    generate_passphrase,
    generate_pin,
    generate_recovery_codes,
    generate_token,
)
from .strength import StrengthReport, analyze, estimate_crack_time, strength_label
from .wordlist import default_wordlist, load_wordlist, wordlist_entropy

__all__ = [
    "__version__",
    "PasswordError",
    "PasswordOptions",
    "StrengthReport",
    "CONFUSABLE_CHARS",
    "DIGITS",
    "LOWERCASE",
    "RECOVERY_ALPHABET",
    "SYMBOLS",
    "UPPERCASE",
    "analyze",
    "char_pool",
    "default_wordlist",
    "estimate_crack_time",
    "generate_batch",
    "generate_passphrase",
    "generate_pin",
    "generate_recovery_codes",
    "generate_token",
    "load_wordlist",
    "strength_label",
    "wordlist_entropy",
]
