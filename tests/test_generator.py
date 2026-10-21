"""Tests for the core generation functions."""

from __future__ import annotations

import math
import unittest

from passgen.generator import (
    CONFUSABLE_CHARS,
    PasswordError,
    PasswordOptions,
    char_pool,
    generate_batch,
    generate_passphrase,
    generate_password,
    generate_pin,
    generate_recovery_codes,
    generate_token,
)
from passgen.strength import analyze


class TestCharPool(unittest.TestCase):
    def test_default_pool_contains_every_class(self) -> None:
        pool = char_pool(PasswordOptions())
        self.assertTrue(any(c.islower() for c in pool))
        self.assertTrue(any(c.isupper() for c in pool))
        self.assertTrue(any(c.isdigit() for c in pool))
        self.assertTrue(any(not c.isalnum() for c in pool))

    def test_pool_has_no_duplicates(self) -> None:
        pool = char_pool(PasswordOptions())
        self.assertEqual(len(pool), len(set(pool)))

    def test_confusables_can_be_removed(self) -> None:
        pool = char_pool(PasswordOptions(exclude_confusables=True))
        for char in CONFUSABLE_CHARS:
            self.assertNotIn(char, pool)

    def test_custom_exclusions(self) -> None:
        pool = char_pool(PasswordOptions(exclude_chars="abc"))
        for char in "abc":
            self.assertNotIn(char, pool)

    def test_no_class_enabled_raises(self) -> None:
        options = PasswordOptions(
            use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False
        )
        with self.assertRaises(PasswordError):
            char_pool(options)

    def test_excluding_everything_raises(self) -> None:
        options = PasswordOptions(
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            symbols="!",
            exclude_chars="!",
        )
        with self.assertRaises(PasswordError):
            char_pool(options)


class TestGeneratePassword(unittest.TestCase):
    def test_default_length(self) -> None:
        self.assertEqual(len(generate_password()), 20)

    def test_custom_length(self) -> None:
        self.assertEqual(len(generate_password(PasswordOptions(length=37))), 37)

    def test_invalid_length_raises(self) -> None:
        with self.assertRaises(PasswordError):
            generate_password(PasswordOptions(length=0))

    def test_every_enabled_class_is_present(self) -> None:
        for _ in range(50):
            password = generate_password(PasswordOptions(length=12))
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(not c.isalnum() for c in password))

    def test_require_all_classes_too_short_raises(self) -> None:
        with self.assertRaises(PasswordError):
            generate_password(PasswordOptions(length=3))

    def test_no_require_all_allows_short_password(self) -> None:
        password = generate_password(PasswordOptions(length=2, require_all_classes=False))
        self.assertEqual(len(password), 2)

    def test_disabled_classes_are_absent(self) -> None:
        password = generate_password(
            PasswordOptions(length=30, use_symbols=False, use_digits=False)
        )
        self.assertTrue(password.isalpha())

    def test_no_repeat(self) -> None:
        password = generate_password(
            PasswordOptions(length=20, allow_repeats=False, require_all_classes=False)
        )
        self.assertEqual(len(password), len(set(password)))

    def test_no_repeat_beyond_pool_raises(self) -> None:
        with self.assertRaises(PasswordError):
            generate_password(
                PasswordOptions(
                    length=200,
                    allow_repeats=False,
                    use_symbols=False,
                    use_digits=False,
                )
            )

    def test_passwords_differ(self) -> None:
        passwords = {generate_password() for _ in range(100)}
        self.assertGreater(len(passwords), 95)

    def test_entropy_of_default_password(self) -> None:
        options = PasswordOptions(length=20)
        password = generate_password(options)
        pool_size = len(char_pool(options))
        theoretical = len(password) * math.log2(pool_size)
        report = analyze(password)
        self.assertLessEqual(report.entropy_bits, theoretical + 0.01)
        self.assertGreater(report.entropy_bits, theoretical * 0.7)


class TestGenerateBatch(unittest.TestCase):
    def test_batch_size(self) -> None:
        self.assertEqual(len(generate_batch(5)), 5)

    def test_batch_is_unique(self) -> None:
        batch = generate_batch(25, PasswordOptions(length=16))
        self.assertEqual(len(batch), len(set(batch)))

    def test_invalid_count_raises(self) -> None:
        with self.assertRaises(PasswordError):
            generate_batch(0)


class TestPassphrase(unittest.TestCase):
    def test_word_count(self) -> None:
        phrase = generate_passphrase(5, separator="-")
        self.assertEqual(len(phrase.split("-")), 5)

    def test_separator(self) -> None:
        phrase = generate_passphrase(3, separator=".")
        self.assertEqual(len(phrase.split(".")), 3)

    def test_capitalize(self) -> None:
        phrase = generate_passphrase(4, capitalize=True)
        for word in phrase.split("-"):
            self.assertTrue(word[0].isupper())

    def test_include_number(self) -> None:
        phrase = generate_passphrase(3, include_number=True)
        self.assertTrue(phrase.split("-")[-1].isdigit())

    def test_custom_wordlist(self) -> None:
        phrase = generate_passphrase(2, wordlist=["alpha", "beta"])
        parts = phrase.split("-")
        self.assertEqual(len(parts), 2)
        for part in parts:
            self.assertIn(part, ("alpha", "beta"))

    def test_zero_words_raises(self) -> None:
        with self.assertRaises(PasswordError):
            generate_passphrase(0)


class TestPin(unittest.TestCase):
    def test_default_pin(self) -> None:
        pin = generate_pin()
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isdigit())

    def test_custom_length(self) -> None:
        self.assertEqual(len(generate_pin(9)), 9)

    def test_no_repeats(self) -> None:
        pin = generate_pin(10, allow_repeats=False)
        self.assertEqual(len(set(pin)), 10)

    def test_alnum_pin(self) -> None:
        pin = generate_pin(20, digits_only=False)
        self.assertTrue(pin.isalnum())


class TestRecoveryCodes(unittest.TestCase):
    def test_count_and_shape(self) -> None:
        codes = generate_recovery_codes(5, groups=2, group_length=4)
        self.assertEqual(len(codes), 5)
        for code in codes:
            parts = code.split("-")
            self.assertEqual(len(parts), 2)
            self.assertEqual(len(parts[0]), 4)

    def test_codes_are_unique(self) -> None:
        codes = generate_recovery_codes(20)
        self.assertEqual(len(codes), len(set(codes)))

    def test_ambiguous_characters_are_not_used(self) -> None:
        for code in generate_recovery_codes(50):
            for char in code:
                self.assertNotIn(char, "O0I1")


class TestToken(unittest.TestCase):
    def test_token_length_is_sufficient(self) -> None:
        token = generate_token(32)
        self.assertGreaterEqual(len(token), 40)

    def test_tokens_differ(self) -> None:
        tokens = {generate_token() for _ in range(50)}
        self.assertEqual(len(tokens), 50)

    def test_short_token_raises(self) -> None:
        with self.assertRaises(PasswordError):
            generate_token(4)


if __name__ == "__main__":
    unittest.main()
