"""Tests for the strength analysis module."""

from __future__ import annotations

import unittest

from passgen.strength import (
    analyze,
    charset_size,
    estimate_crack_time,
    format_duration,
    strength_label,
)


class TestCharsetSize(unittest.TestCase):
    def test_lowercase_only(self) -> None:
        self.assertEqual(charset_size("abc"), 26)

    def test_mixed(self) -> None:
        self.assertEqual(charset_size("aA1!"), 26 + 26 + 10 + 26)

    def test_empty(self) -> None:
        self.assertEqual(charset_size(""), 0)


class TestAnalyze(unittest.TestCase):
    def test_empty_password(self) -> None:
        report = analyze("")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.entropy_bits, 0.0)
        self.assertFalse(report.is_strong)

    def test_very_weak(self) -> None:
        report = analyze("123456")
        self.assertEqual(report.score, 0)
        self.assertTrue(any("commonly used" in w for w in report.weaknesses))

    def test_common_password_gets_low_entropy(self) -> None:
        report = analyze("password")
        self.assertLess(report.entropy_bits, 20)

    def test_strong_password(self) -> None:
        report = analyze("Kq7#vR2$xLp9!zWc4&")
        self.assertGreaterEqual(report.score, 3)
        self.assertTrue(report.is_strong)

    def test_long_random_password_is_very_strong(self) -> None:
        report = analyze("Xk3!pQ7@vB9#mZ2&hR5*yT8%sW")
        self.assertEqual(report.score, 4)

    def test_repeated_characters_are_detected(self) -> None:
        report = analyze("aaaa")
        self.assertTrue(any("repeats" in w for w in report.weaknesses))

    def test_sequence_is_detected(self) -> None:
        report = analyze("abcdefgh")
        self.assertTrue(any("run" in w for w in report.weaknesses))

    def test_keyboard_pattern_is_detected(self) -> None:
        report = analyze("qwertyuiop")
        self.assertTrue(any("keyboard" in w for w in report.weaknesses))

    def test_year_is_detected(self) -> None:
        report = analyze("Summer2024!")
        self.assertTrue(any("year" in w for w in report.weaknesses))

    def test_single_class_is_detected(self) -> None:
        report = analyze("alllowercaseletters")
        self.assertTrue(any("one character type" in w for w in report.weaknesses))

    def test_entropy_never_exceeds_maximum(self) -> None:
        report = analyze("abcdefghijklmnop")
        self.assertLessEqual(report.entropy_bits, 16 * 4)

    def test_report_is_serialisable(self) -> None:
        data = analyze("Tr0ub4dor&3").to_dict()
        self.assertIn("entropy_bits", data)
        self.assertIn("label", data)
        self.assertIsInstance(data["weaknesses"], list)

    def test_crack_times_present(self) -> None:
        report = analyze("Kq7#vR2$xLp9!zWc4&")
        self.assertIn("offline_fast_hash", report.crack_times)
        self.assertIn("online_throttled", report.crack_times)


class TestHelpers(unittest.TestCase):
    def test_labels(self) -> None:
        self.assertEqual(strength_label(0), "Very weak")
        self.assertEqual(strength_label(4), "Very strong")

    def test_crack_time_scales(self) -> None:
        fast = estimate_crack_time(60, 1e10)
        slow = estimate_crack_time(60, 1e2)
        self.assertLess(fast, slow)

    def test_format_duration(self) -> None:
        self.assertEqual(format_duration(0.1), "instantly")
        self.assertEqual(format_duration(30), "30 seconds")
        self.assertEqual(format_duration(3600), "1 hour")
        self.assertIn("years", format_duration(1e12))

    def test_leetspeak_dictionary_word_is_detected(self) -> None:
        report = analyze("Tr0ub4dor&3")
        self.assertTrue(any("common word" in w for w in report.weaknesses))
        self.assertLess(report.score, 3)


if __name__ == "__main__":
    unittest.main()
