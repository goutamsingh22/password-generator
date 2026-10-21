"""Wordlist helpers for passphrase generation.

The bundled wordlist is the EFF "large" list (7,776 words, ~12.9 bits of
entropy per word) published at https://www.eff.org/dice
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Sequence

__all__ = [
    "DATA_DIR",
    "wordlist_path",
    "load_wordlist",
    "default_wordlist",
    "filter_words",
    "wordlist_entropy",
]

DATA_DIR = Path(__file__).resolve().parent / "data"
EFF_LARGE_WORDFILENAME = "eff_large_wordlist.txt"


def wordlist_path(name: str = EFF_LARGE_WORDFILENAME) -> Path:
    """Return the path of a bundled wordlist.

    Args:
        name: File name inside the package ``data`` directory.

    Returns:
        The absolute path of the wordlist.
    """
    return DATA_DIR / name


def _parse(text: str) -> list[str]:
    """Parse a Diceware style wordlist file into a list of words."""
    words: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # EFF files use "<dice>\t<word>"; plain lists use one word per line.
        if "\t" in line:
            line = line.split("\t", 1)[1]
        elif " " in line and line.split(" ", 1)[0].isdigit():
            line = line.split(" ", 1)[1]
        word = line.strip().lower()
        if word:
            words.append(word)
    return words


def load_wordlist(path: str | os.PathLike[str]) -> list[str]:
    """Load a wordlist from an arbitrary file.

    Args:
        path: Path of the wordlist file.

    Returns:
        The list of words, lower-cased and de-duplicated in file order.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    text = Path(path).read_text(encoding="utf-8")
    return list(dict.fromkeys(_parse(text)))


@lru_cache(maxsize=1)
def default_wordlist() -> tuple[str, ...]:
    """Return the bundled EFF large wordlist.

    Returns:
        A tuple of 7,776 words.
    """
    return tuple(load_wordlist(wordlist_path()))


def filter_words(
    words: Sequence[str], min_length: int = 0, max_length: int | None = None
) -> list[str]:
    """Filter a wordlist by word length.

    Args:
        words: The words to filter.
        min_length: Minimum number of characters.
        max_length: Maximum number of characters (``None`` means no limit).

    Returns:
        The filtered words.
    """
    result = []
    for word in words:
        if len(word) < min_length:
            continue
        if max_length is not None and len(word) > max_length:
            continue
        result.append(word)
    return result


def wordlist_entropy(word_count: int, list_size: int | None = None) -> float:
    """Return the entropy of a passphrase drawn from a wordlist.

    Args:
        word_count: Number of words in the passphrase.
        list_size: Size of the wordlist. Defaults to the bundled list.

    Returns:
        The entropy in bits.
    """
    import math

    size = list_size if list_size is not None else len(default_wordlist())
    if size < 2 or word_count < 1:
        return 0.0
    return word_count * math.log2(size)
