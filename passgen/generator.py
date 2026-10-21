"""Core password generation primitives.

Every random choice in this module uses :mod:`secrets` (or a
:class:`random.SystemRandom` instance) so the output is suitable for
producing real credentials.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import Iterable, Sequence

__all__ = [
    "LOWERCASE",
    "UPPERCASE",
    "DIGITS",
    "SYMBOLS",
    "CONFUSABLE_CHARS",
    "RECOVERY_ALPHABET",
    "PasswordOptions",
    "PasswordError",
    "char_pool",
    "generate_password",
    "generate_batch",
    "generate_passphrase",
    "generate_pin",
    "generate_recovery_codes",
    "generate_token",
]

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}<>?,.;:~"

#: Characters that are easily confused with one another when a password has
#: to be read out loud or typed from a printed sheet.
CONFUSABLE_CHARS = set("Il1O0oB8S5Z2|`'\".,:;()[]{}")

#: Crockford-ish alphabet used for recovery codes (no ambiguous glyphs).
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class PasswordError(ValueError):
    """Raised when the requested options cannot produce a valid password."""


@dataclass(frozen=True)
class PasswordOptions:
    """Configuration for :func:`generate_password`.

    Attributes:
        length: Number of characters in the generated password.
        use_lowercase: Allow ``a-z``.
        use_uppercase: Allow ``A-Z``.
        use_digits: Allow ``0-9``.
        use_symbols: Allow punctuation characters.
        exclude_confusables: Drop characters that look like one another.
        exclude_chars: Extra characters to remove from the pool.
        require_all_classes: Guarantee at least one character from every
            enabled class.
        allow_repeats: Allow the same character to appear more than once.
        symbols: Custom symbol set used when ``use_symbols`` is enabled.
    """

    length: int = 20
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_confusables: bool = False
    exclude_chars: str = ""
    require_all_classes: bool = True
    allow_repeats: bool = True
    symbols: str = SYMBOLS

    def enabled_classes(self) -> list[str]:
        """Return the names of the character classes that are switched on."""
        names = []
        if self.use_lowercase:
            names.append("lowercase")
        if self.use_uppercase:
            names.append("uppercase")
        if self.use_digits:
            names.append("digits")
        if self.use_symbols:
            names.append("symbols")
        return names

    def pool(self) -> str:
        """Return the de-duplicated character pool implied by the options."""
        return char_pool(self)


def _unique(chars: Iterable[str]) -> str:
    """De-duplicate ``chars`` while preserving their original order."""
    seen: set[str] = set()
    out: list[str] = []
    for char in chars:
        if char not in seen:
            seen.add(char)
            out.append(char)
    return "".join(out)


def char_pool(options: PasswordOptions) -> str:
    """Build the character pool for ``options``.

    Raises:
        PasswordError: If no character class is enabled or the pool ends up
            empty after applying the exclusions.
    """
    parts: list[str] = []
    if options.use_lowercase:
        parts.append(LOWERCASE)
    if options.use_uppercase:
        parts.append(UPPERCASE)
    if options.use_digits:
        parts.append(DIGITS)
    if options.use_symbols:
        parts.append(options.symbols)

    if not parts:
        raise PasswordError("At least one character class must be enabled.")

    pool = _unique("".join(parts))

    if options.exclude_confusables:
        pool = "".join(c for c in pool if c not in CONFUSABLE_CHARS)

    excluded = set(options.exclude_chars)
    if excluded:
        pool = "".join(c for c in pool if c not in excluded)

    if not pool:
        raise PasswordError("The character pool is empty after applying exclusions.")

    return pool


def _class_members(pool: str, options: PasswordOptions) -> dict[str, str]:
    """Return the characters of ``pool`` that belong to each enabled class."""
    members: dict[str, str] = {}
    if options.use_lowercase:
        members["lowercase"] = "".join(c for c in pool if c in LOWERCASE)
    if options.use_uppercase:
        members["uppercase"] = "".join(c for c in pool if c in UPPERCASE)
    if options.use_digits:
        members["digits"] = "".join(c for c in pool if c in DIGITS)
    if options.use_symbols:
        members["symbols"] = "".join(c for c in pool if c in options.symbols)
    return members


def generate_password(options: PasswordOptions | None = None) -> str:
    """Generate a single cryptographically secure password.

    Args:
        options: Generation options. Defaults to :class:`PasswordOptions`.

    Returns:
        The generated password.

    Raises:
        PasswordError: If the options are inconsistent, e.g. a length that is
            shorter than the number of enabled character classes.
    """
    options = options or PasswordOptions()
    if options.length < 1:
        raise PasswordError("Password length must be at least 1.")

    pool = options.pool()
    members = _class_members(pool, options)
    active = {name: chars for name, chars in members.items() if chars}

    if options.require_all_classes and options.length < len(active):
        raise PasswordError(
            f"Length {options.length} is too short to include one character "
            f"from each of the {len(active)} enabled classes."
        )

    if not options.allow_repeats and options.length > len(pool):
        raise PasswordError(
            f"Length {options.length} exceeds the pool size ({len(pool)}) "
            "and repeats are disabled."
        )

    chosen: list[str] = []
    remaining_pool = pool

    if options.require_all_classes:
        for chars in active.values():
            pick = secrets.choice(chars)
            chosen.append(pick)
            if not options.allow_repeats:
                remaining_pool = remaining_pool.replace(pick, "", 1)

    missing = options.length - len(chosen)
    if missing < 0:
        missing = 0

    if options.allow_repeats:
        chosen.extend(secrets.choice(pool) for _ in range(missing))
    else:
        if missing > len(remaining_pool):
            raise PasswordError(
                f"Length {options.length} exceeds the pool size ({len(pool)}) "
                "and repeats are disabled."
            )
        chosen.extend(secrets.SystemRandom().sample(remaining_pool, missing))

    secrets.SystemRandom().shuffle(chosen)
    return "".join(chosen)


def generate_batch(
    count: int, options: PasswordOptions | None = None, *, unique: bool = True
) -> list[str]:
    """Generate ``count`` passwords.

    Args:
        count: How many passwords to generate.
        options: Generation options.
        unique: Ensure the returned passwords are all different.

    Returns:
        A list of generated passwords.

    Raises:
        PasswordError: If ``count`` is not positive.
    """
    if count < 1:
        raise PasswordError("count must be at least 1.")

    options = options or PasswordOptions()
    results: list[str] = []
    seen: set[str] = set()

    while len(results) < count:
        candidate = generate_password(options)
        if not unique or candidate not in seen:
            results.append(candidate)
            seen.add(candidate)

    return results


def generate_passphrase(
    words: int = 6,
    *,
    separator: str = "-",
    capitalize: bool = False,
    include_number: bool = False,
    wordlist: Sequence[str] | None = None,
) -> str:
    """Generate a diceware-style passphrase.

    Args:
        words: Number of words to use.
        separator: String placed between the words.
        capitalize: Capitalize the first letter of every word.
        include_number: Append a random two digit number to the passphrase.
        wordlist: Words to pick from. Defaults to the bundled EFF list.

    Returns:
        The generated passphrase.
    """
    if words < 1:
        raise PasswordError("A passphrase needs at least one word.")

    if wordlist is None:
        from .wordlist import default_wordlist

        wordlist = default_wordlist()

    usable = [w for w in wordlist if w]
    if not usable:
        raise PasswordError("The wordlist is empty.")

    parts = [secrets.choice(usable) for _ in range(words)]
    if capitalize:
        parts = [w.capitalize() for w in parts]
    if include_number:
        parts.append(f"{secrets.randbelow(90) + 10:02d}")

    return separator.join(parts)


def generate_pin(length: int = 6, *, digits_only: bool = True, allow_repeats: bool = True) -> str:
    """Generate a numeric PIN.

    Args:
        length: Number of characters.
        digits_only: Restrict the output to ``0-9``.
        allow_repeats: Allow repeated digits.

    Returns:
        The generated PIN.
    """
    if length < 1:
        raise PasswordError("PIN length must be at least 1.")

    alphabet = DIGITS if digits_only else RECOVERY_ALPHABET
    if not allow_repeats:
        if length > len(alphabet):
            raise PasswordError(
                f"Length {length} exceeds the pool size ({len(alphabet)}) "
                "and repeats are disabled."
            )
        picks = secrets.SystemRandom().sample(alphabet, length)
        return "".join(picks)

    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_recovery_codes(
    count: int = 8, *, groups: int = 2, group_length: int = 4, separator: str = "-"
) -> list[str]:
    """Generate one-time recovery codes (for example for a 2FA reset flow).

    Args:
        count: How many codes to generate.
        groups: Number of groups per code.
        group_length: Characters per group.
        separator: String placed between the groups.

    Returns:
        A list of recovery codes.
    """
    if count < 1:
        raise PasswordError("count must be at least 1.")
    if groups < 1 or group_length < 1:
        raise PasswordError("groups and group_length must be at least 1.")

    codes: list[str] = []
    for _ in range(count):
        parts = [
            "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(group_length))
            for _ in range(groups)
        ]
        codes.append(separator.join(parts))
    return codes


def generate_token(n_bytes: int = 32) -> str:
    """Generate a URL-safe random token.

    Args:
        n_bytes: Number of random bytes. 32 bytes gives 256 bits of entropy.

    Returns:
        A URL-safe token.
    """
    if n_bytes < 8:
        raise PasswordError("Use at least 8 bytes for a token.")
    return secrets.token_urlsafe(n_bytes)
