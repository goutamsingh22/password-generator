"""Password strength analysis.

The module estimates how much entropy a password carries and turns that
number into a rating, a set of concrete weaknesses and crack-time estimates
for a few attack scenarios.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterable

from .generator import DIGITS, LOWERCASE, SYMBOLS, UPPERCASE

__all__ = [
    "COMMON_PASSWORDS",
    "StrengthReport",
    "analyze",
    "charset_size",
    "estimate_crack_time",
    "format_duration",
    "strength_label",
]

#: A small slice of the most frequently used passwords. Any password that
#: appears here is essentially worthless, no matter how long it is.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456",
        "password",
        "12345678",
        "qwerty",
        "123456789",
        "12345",
        "1234",
        "111111",
        "1234567",
        "dragon",
        "123123",
        "baseball",
        "abc123",
        "football",
        "monkey",
        "shadow",
        "master",
        "666666",
        "qwertyuiop",
        "123321",
        "mustang",
        "1234567890",
        "michael",
        "654321",
        "superman",
        "1qaz2wsx",
        "7777777",
        "121212",
        "000000",
        "qazwsx",
        "123qwe",
        "killer",
        "trustno1",
        "jordan",
        "jennifer",
        "zxcvbnm",
        "asdfgh",
        "hunter",
        "buster",
        "soccer",
        "harley",
        "batman",
        "andrew",
        "tigger",
        "sunshine",
        "iloveyou",
        "fuckyou",
        "2000",
        "charlie",
        "robert",
        "thomas",
        "hockey",
        "ranger",
        "daniel",
        "starwars",
        "klaster",
        "112233",
        "george",
        "asshole",
        "computer",
        "michelle",
        "jessica",
        "pepper",
        "1111",
        "zxcvbn",
        "555555",
        "11111111",
        "131313",
        "freedom",
        "777777",
        "pass",
        "fuck",
        "maggie",
        "159753",
        "aaaaaa",
        "ginger",
        "princess",
        "joshua",
        "cheese",
        "amanda",
        "summer",
        "love",
        "ashley",
        "6969",
        "nicole",
        "chelsea",
        "biteme",
        "matthew",
        "access",
        "yankees",
        "987654321",
        "dallas",
        "austin",
        "thunder",
        "taylor",
        "matrix",
        "minemine",
        "william",
        "corvette",
        "hello",
        "martin",
        "heather",
        "secret",
        "fucker",
        "merlin",
        "diamond",
        "1234qwer",
        "gfhjkm",
        "hammer",
        "silver",
        "222222",
        "88888888",
        "anthony",
        "justin",
        "test",
        "bailey",
        "q1w2e3r4t5",
        "patrick",
        "internet",
        "scooter",
        "orange",
        "11111",
        "golfer",
        "cookie",
        "richard",
        "samantha",
        "bigdog",
        "guitar",
        "jackson",
        "whatever",
        "mickey",
        "chicken",
        "sparky",
        "snoopy",
        "maverick",
        "phoenix",
        "camaro",
        "peanut",
        "morgan",
        "welcome",
        "falcon",
        "andrea",
        "mercedes",
        "spider",
        "diablo",
        "lovers",
        "alpha",
        "brandon",
        "makers",
        "tucker",
        "elizabeth",
        "willie",
        "houston",
        "miller",
        "parker",
        "sandra",
        "admin",
        "administrator",
        "root",
        "user",
        "guest",
        "login",
        "letmein",
        "welcome1",
        "qwerty123",
        "password1",
        "passw0rd",
        "p@ssw0rd",
        "iloveyou1",
        "abc123456",
        "abcd1234",
        "1q2w3e4r",
        "zaq1@WSX",
    }
)

_KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "1qaz2wsx3edc",
    "qazwsxedc",
)

_LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
        "+": "t",
    }
)

_DICTIONARY_WORDS = (
    "password",
    "admin",
    "welcome",
    "iloveyou",
    "letmein",
    "login",
    "master",
    "dragon",
    "monkey",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "trustno1",
    "superman",
    "batman",
    "starwars",
    "whatever",
    "freedom",
    "secret",
    "computer",
    "america",
    "jesus",
    "money",
    "lovely",
    "orange",
    "banana",
    "google",
    "facebook",
    "instagram",
    "twitter",
    "github",
    "troubador",
    "trouble",
    "soccer",
    "hockey",
    "killer",
    "ranger",
    "harley",
    "daniel",
    "thomas",
    "tigger",
    "charlie",
    "ashley",
    "amanda",
    "nicole",
    "jessica",
    "michelle",
    "pepper",
    "ginger",
    "maggie",
    "cookie",
    "chicken",
    "sparky",
    "snoopy",
    "maverick",
    "phoenix",
    "peanut",
    "morgan",
    "corvette",
    "mustang",
    "diamond",
    "silver",
    "hammer",
    "summer",
    "winter",
    "spring",
    "autumn",
    "qwerty",
    "azerty",
    "keyboard",
    "london",
    "paris",
    "tokyo",
)

_SEQUENCES = "abcdefghijklmnopqrstuvwxyz0123456789"

_SCENARIOS: dict[str, float] = {
    "offline_fast_hash": 1e10,
    "offline_slow_hash": 1e4,
    "online_unthrottled": 1e3,
    "online_throttled": 1e2,
}

_SCENARIO_LABELS = {
    "offline_fast_hash": "offline, fast hash (10^10 guesses/s)",
    "offline_slow_hash": "offline, slow hash (10^4 guesses/s)",
    "online_unthrottled": "online, unthrottled (10^3 guesses/s)",
    "online_throttled": "online, throttled (10^2 guesses/s)",
}


@dataclass
class StrengthReport:
    """The result of analysing a password."""

    length: int
    charset_size: int
    entropy_bits: float
    score: int
    label: str
    weaknesses: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    crack_times: dict[str, str] = field(default_factory=dict)

    @property
    def is_strong(self) -> bool:
        """``True`` when the rating is "Strong" or better."""
        return self.score >= 3

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation of the report."""
        return {
            "length": self.length,
            "charset_size": self.charset_size,
            "entropy_bits": round(self.entropy_bits, 2),
            "score": self.score,
            "label": self.label,
            "weaknesses": list(self.weaknesses),
            "suggestions": list(self.suggestions),
            "crack_times": dict(self.crack_times),
        }


def charset_size(password: str) -> int:
    """Return the size of the character set the password could be drawn from.

    Args:
        password: The password to inspect.

    Returns:
        The number of distinct characters available in the given classes.
    """
    size = 0
    if any(c in LOWERCASE for c in password):
        size += 26
    if any(c in UPPERCASE for c in password):
        size += 26
    if any(c in DIGITS for c in password):
        size += 10
    if any(c in SYMBOLS for c in password):
        size += len(SYMBOLS)
    if not size:
        size = len(set(password))
    return size


def _has_repeated_char(password: str) -> str | None:
    for match in re.finditer(r"(.)\1{2,}", password):
        return match.group(0)
    return None


def _has_repeated_sequence(password: str) -> str | None:
    for size in (2, 3):
        for start in range(len(password) - size * 2 + 1):
            block = password[start : start + size]
            if password[start + size : start + size * 2] == block:
                return block
    return None


def _has_sequence(password: str) -> str | None:
    lowered = password.lower()
    for size in range(5, 2, -1):
        for start in range(len(lowered) - size + 1):
            chunk = lowered[start : start + size]
            for alphabet in (_SEQUENCES, _SEQUENCES[::-1]):
                index = alphabet.find(chunk)
                if index != -1:
                    return chunk
    return None


def _has_keyboard_pattern(password: str) -> str | None:
    lowered = password.lower()
    for row in _KEYBOARD_ROWS:
        for candidate in (row, row[::-1]):
            if candidate in lowered:
                return candidate
    return None


def _has_year(password: str) -> str | None:
    match = re.search(r"(19|20)\d{2}", password)
    return match.group(0) if match else None


def _has_dictionary_word(password: str) -> str | None:
    """Find a dictionary word, ignoring simple letter substitutions."""
    lowered = password.lower()
    candidates = {lowered, lowered.translate(_LEET_MAP)}
    for word in _DICTIONARY_WORDS:
        if len(word) < 5:
            continue
        for candidate in candidates:
            if word in candidate:
                return word
    return None


def _detect_weaknesses(password: str) -> list[tuple[str, str]]:
    """Return ``(code, description)`` pairs for every weakness found."""
    found: list[tuple[str, str]] = []

    if not password:
        return [("empty", "The password is empty.")]

    if password.lower() in COMMON_PASSWORDS:
        found.append(("common", "The password is one of the most commonly used ones."))

    dictionary = _has_dictionary_word(password)
    if dictionary:
        found.append(("dictionary", f"It contains the common word '{dictionary}'."))

    repeated_char = _has_repeated_char(password)
    if repeated_char:
        found.append(("repeated_char", f"It repeats the character '{repeated_char[0]}'."))

    repeated_seq = _has_repeated_sequence(password)
    if repeated_seq:
        found.append(("repeated_sequence", f"It repeats the sequence '{repeated_seq}'."))

    sequence = _has_sequence(password)
    if sequence:
        found.append(("sequence", f"It contains the run '{sequence}'."))

    keyboard = _has_keyboard_pattern(password)
    if keyboard:
        found.append(("keyboard", f"It follows the keyboard pattern '{keyboard}'."))

    year = _has_year(password)
    if year:
        found.append(("year", f"It contains the year '{year}'."))

    classes = 0
    if any(c in LOWERCASE for c in password):
        classes += 1
    if any(c in UPPERCASE for c in password):
        classes += 1
    if any(c in DIGITS for c in password):
        classes += 1
    if any(c in SYMBOLS for c in password):
        classes += 1
    if classes <= 1:
        found.append(
            ("single_class", "It uses only one character type (add upper case, digits or symbols).")
        )

    return found


def format_duration(seconds: float) -> str:
    """Render a number of seconds as a human readable duration.

    Args:
        seconds: The duration in seconds.

    Returns:
        A short human readable string such as ``"3 hours"`` or ``"instantly"``.
    """
    if seconds < 1:
        return "instantly"

    units = (
        (1, "second"),
        (60, "minute"),
        (3600, "hour"),
        (86400, "day"),
        (2592000, "month"),
        (31536000, "year"),
    )
    for limit, unit in units:
        if seconds < limit * 60:
            value = seconds / limit
            if value < 2:
                return f"1 {unit}"
            return f"{int(value)} {unit}s"

    years = seconds / 31536000
    exponent = math.floor(math.log10(years))
    mantissa = years / 10**exponent
    return f"{mantissa:.0f}e{exponent:+03d} years"


def estimate_crack_time(entropy_bits: float, guesses_per_second: float) -> float:
    """Estimate how long an attack takes to guess a password.

    Args:
        entropy_bits: Entropy of the password in bits.
        guesses_per_second: Speed of the attacker.

    Returns:
        The number of seconds needed.
    """
    if entropy_bits <= 0:
        return 0.0
    guesses = 2 ** max(entropy_bits - 1, 0)
    return guesses / guesses_per_second


def strength_label(score: int) -> str:
    """Return the human readable label for a numeric score."""
    return {
        0: "Very weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very strong",
    }.get(score, "Unknown")


def _score_for(entropy: float) -> int:
    if entropy < 28:
        return 0
    if entropy < 36:
        return 1
    if entropy < 60:
        return 2
    if entropy < 128:
        return 3
    return 4


def analyze(password: str) -> StrengthReport:
    """Analyse a password and return a :class:`StrengthReport`.

    Args:
        password: The password to analyse.

    Returns:
        A report describing the entropy, rating, weaknesses and suggestions.
    """
    if not password:
        return StrengthReport(
            length=0,
            charset_size=0,
            entropy_bits=0.0,
            score=0,
            label=strength_label(0),
            weaknesses=["The password is empty."],
            suggestions=["Use a generated password of at least 16 characters."],
            crack_times={name: "instantly" for name in _SCENARIOS},
        )

    size = charset_size(password)
    entropy = len(password) * math.log2(size) if size > 1 else 0.0

    weaknesses = _detect_weaknesses(password)

    for code, _ in weaknesses:
        if code == "common":
            entropy = min(entropy, 8.0)
        elif code == "dictionary":
            entropy *= 0.35
        elif code in {"repeated_char", "repeated_sequence", "sequence", "keyboard", "year"}:
            entropy *= 0.6
        elif code == "single_class":
            entropy *= 0.8

    entropy = max(0.0, min(entropy, len(password) * math.log2(size) if size > 1 else 0.0))
    score = _score_for(entropy)

    suggestions: list[str] = []
    if score < 3:
        suggestions.append("Use at least 16 characters.")
    if any(c in LOWERCASE for c in password) and not any(c in UPPERCASE for c in password):
        suggestions.append("Mix in upper case letters.")
    if not any(c in DIGITS for c in password):
        suggestions.append("Mix in digits.")
    if not any(c in SYMBOLS for c in password):
        suggestions.append("Mix in symbols.")
    if weaknesses:
        suggestions.append("Avoid words, keyboard runs and repeated characters.")
    if not suggestions:
        suggestions.append("Nothing obvious to fix - keep using a manager.")

    crack_times = {
        name: format_duration(estimate_crack_time(entropy, rate))
        for name, rate in _SCENARIOS.items()
    }

    return StrengthReport(
        length=len(password),
        charset_size=size,
        entropy_bits=entropy,
        score=score,
        label=strength_label(score),
        weaknesses=[description for _, description in weaknesses],
        suggestions=suggestions,
        crack_times=crack_times,
    )


def describe_scenarios() -> Iterable[tuple[str, str]]:
    """Yield the ``(key, label)`` pairs of the crack-time scenarios."""
    yield from _SCENARIO_LABELS.items()
