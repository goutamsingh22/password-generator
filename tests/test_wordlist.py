"""Tests for the wordlist helpers."""

from __future__ import annotations

import math
import tempfile
import unittest
from pathlib import Path

from passgen.wordlist import (
    default_wordlist,
    filter_words,
    load_wordlist,
    wordlist_entropy,
    wordlist_path,
)


class TestDefaultWordlist(unittest.TestCase):
    def test_wordlist_exists(self) -> None:
        self.assertTrue(wordlist_path().exists())

    def test_wordlist_size(self) -> None:
        self.assertEqual(len(default_wordlist()), 7776)

    def test_words_are_unique_and_lowercase(self) -> None:
        words = default_wordlist()
        self.assertEqual(len(set(words)), len(words))
        for word in words:
            self.assertEqual(word, word.lower())

    def test_words_are_short_enough_to_type(self) -> None:
        for word in default_wordlist():
            self.assertLessEqual(len(word), 9)
            self.assertGreaterEqual(len(word), 3)


class TestLoadWordlist(unittest.TestCase):
    def test_plain_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "words.txt"
            path.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
            self.assertEqual(load_wordlist(path), ["alpha", "beta", "gamma"])

    def test_diceware_wordlist(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "words.txt"
            path.write_text("11111\tabacus\n22222\tbobcat\n", encoding="utf-8")
            self.assertEqual(load_wordlist(path), ["abacus", "bobcat"])

    def test_comments_and_blank_lines_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "words.txt"
            path.write_text("# a comment\n\nalpha\n", encoding="utf-8")
            self.assertEqual(load_wordlist(path), ["alpha"])


class TestFilterAndEntropy(unittest.TestCase):
    def test_filter_by_length(self) -> None:
        words = ["a", "abc", "abcdef"]
        self.assertEqual(filter_words(words, min_length=3), ["abc", "abcdef"])
        self.assertEqual(filter_words(words, min_length=3, max_length=3), ["abc"])

    def test_entropy(self) -> None:
        self.assertAlmostEqual(wordlist_entropy(6, 7776), 6 * math.log2(7776), places=6)

    def test_entropy_of_empty_wordlist(self) -> None:
        self.assertEqual(wordlist_entropy(6, 1), 0.0)


if __name__ == "__main__":
    unittest.main()
