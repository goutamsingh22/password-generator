"""Tests for the command line interface."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from passgen.cli import main


def run(*argv: str) -> tuple[int, str, str]:
    """Run the CLI and capture stdout, stderr and the exit code."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestGenerateCommand(unittest.TestCase):
    def test_default_output_is_a_single_password(self) -> None:
        code, out, _ = run("generate")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip()), 20)

    def test_length_option(self) -> None:
        code, out, _ = run("generate", "-l", "32")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip()), 32)

    def test_count_option(self) -> None:
        code, out, _ = run("generate", "-n", "4", "-l", "10")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 4)

    def test_bare_options_default_to_generate(self) -> None:
        code, out, _ = run("-l", "16")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip()), 16)

    def test_json_output(self) -> None:
        code, out, _ = run("generate", "-n", "2", "-f", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 2)
        self.assertIn("password", data[0])
        self.assertIn("entropy_bits", data[0])

    def test_csv_output(self) -> None:
        code, out, _ = run("generate", "-n", "2", "-f", "csv")
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], "index,password,entropy_bits,strength")
        self.assertEqual(len(lines), 3)

    def test_table_output(self) -> None:
        code, out, _ = run("generate", "-n", "1", "-f", "table")
        self.assertEqual(code, 0)
        self.assertIn("password", out)
        self.assertIn("strength", out)

    def test_confusable_exclusion(self) -> None:
        code, out, _ = run("generate", "-n", "20", "-l", "30", "--exclude-confusables")
        self.assertEqual(code, 0)
        for password in out.strip().splitlines():
            for char in "Il1O0o":
                self.assertNotIn(char, password)

    def test_invalid_length_is_reported(self) -> None:
        code, _, err = run("generate", "-l", "0")
        self.assertEqual(code, 2)
        self.assertIn("error:", err)


class TestPassphraseCommand(unittest.TestCase):
    def test_default_passphrase(self) -> None:
        code, out, _ = run("passphrase")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().split("-")), 6)

    def test_word_count(self) -> None:
        code, out, _ = run("passphrase", "-w", "3")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().split("-")), 3)

    def test_json_output(self) -> None:
        code, out, _ = run("passphrase", "-n", "2", "-f", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 2)
        self.assertIn("passphrase", data[0])


class TestOtherCommands(unittest.TestCase):
    def test_pin(self) -> None:
        code, out, _ = run("pin", "-l", "4")
        self.assertEqual(code, 0)
        self.assertTrue(out.strip().isdigit())
        self.assertEqual(len(out.strip()), 4)

    def test_codes(self) -> None:
        code, out, _ = run("codes", "-n", "3")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 3)

    def test_token(self) -> None:
        code, out, _ = run("token")
        self.assertEqual(code, 0)
        self.assertGreater(len(out.strip()), 20)

    def test_check(self) -> None:
        code, out, _ = run("check", "password")
        self.assertEqual(code, 0)
        self.assertIn("Entropy", out)
        self.assertIn("Very weak", out)

    def test_check_json(self) -> None:
        code, out, _ = run("check", "Kq7#vR2$xLp9!zWc4&", "-f", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["length"], 18)
        self.assertGreaterEqual(data["score"], 3)

    def test_check_empty_password(self) -> None:
        code, out, _ = run("check", "")
        self.assertEqual(code, 0)
        self.assertIn("empty", out.lower())


class TestHelp(unittest.TestCase):
    def test_help_lists_commands(self) -> None:
        with self.assertRaises(SystemExit):
            run("--help")

    def test_version(self) -> None:
        with self.assertRaises(SystemExit):
            run("--version")


if __name__ == "__main__":
    unittest.main()
