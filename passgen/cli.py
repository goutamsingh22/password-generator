"""Command line interface for the password generator."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from typing import Any, Sequence

from . import __version__
from .generator import (
    PasswordError,
    PasswordOptions,
    generate_batch,
    generate_passphrase,
    generate_pin,
    generate_recovery_codes,
    generate_token,
)
from .strength import analyze
from .wordlist import default_wordlist, load_wordlist, wordlist_entropy

__all__ = ["main", "build_parser"]

FORMATS = ("plain", "json", "csv", "table")

BANNER = r"""
  ___                     ____              _        _
 / _ \___ ____  ___ ___  / ___| __ ___  ___| |_ _ __| |_ ___ ___  _ __
| |_| / _` \/ -_) __/ _| \___ \/ _` \(_-<  _|  _/ _` |  _/ -_) ' \|  _/
|  _  \ (_| \___ \__\___ |___/\__,_/__/__/\__|\__\__,_|\__\___|_||_|\__|
 \_/ \_/\___/|___/___/
"""


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _entropy_for_password(password: str) -> float:
    return analyze(password).entropy_bits


def _copy_to_clipboard(text: str) -> bool:
    """Try to put ``text`` on the system clipboard.

    Returns:
        ``True`` when the text was copied.
    """
    if shutil.which("powershell"):
        try:
            subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Set-Clipboard -Value $args[0]",
                    text,
                ],
                check=True,
                capture_output=True,
            )
            return True
        except (subprocess.CalledProcessError, OSError):
            pass

    try:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
        return True
    except Exception:  # pragma: no cover - depends on the desktop environment
        return False


def _print_rows(rows: list[dict[str, Any]], fmt: str, headers: Sequence[str]) -> None:
    """Render ``rows`` in the requested output format."""
    if fmt == "json":
        print(json.dumps(rows, indent=2))
        return

    if fmt == "csv":
        print(",".join(headers))
        for row in rows:
            values = [str(row.get(header, "")).replace(",", " ") for header in headers]
            print(",".join(values))
        return

    if fmt == "table":
        widths = {
            header: max(
                len(header),
                max((len(str(row.get(header, ""))) for row in rows), default=0),
            )
            for header in headers
        }
        separator = "+" + "+".join("-" * (width + 2) for width in widths.values()) + "+"
        print(separator)
        print("| " + " | ".join(header.ljust(widths[header]) for header in headers) + " |")
        print(separator)
        for row in rows:
            print(
                "| "
                + " | ".join(str(row.get(header, "")).ljust(widths[header]) for header in headers)
                + " |"
            )
        print(separator)
        return

    for row in rows:
        print(row.get(headers[0], ""))


def _print_text(text: str) -> None:
    print(text)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def _options_from_args(args: argparse.Namespace) -> PasswordOptions:
    return PasswordOptions(
        length=args.length,
        use_lowercase=not args.no_lower,
        use_uppercase=not args.no_upper,
        use_digits=not args.no_digits,
        use_symbols=not args.no_symbols,
        exclude_confusables=args.exclude_confusables,
        exclude_chars=args.exclude,
        require_all_classes=not args.no_require_all,
        allow_repeats=not args.no_repeat,
    )


def cmd_generate(args: argparse.Namespace) -> int:
    options = _options_from_args(args)
    passwords = generate_batch(args.count, options)

    rows = [
        {
            "index": i + 1,
            "password": password,
            "entropy_bits": round(_entropy_for_password(password), 1),
            "strength": analyze(password).label,
        }
        for i, password in enumerate(passwords)
    ]

    if args.format == "plain":
        for password in passwords:
            print(password)
    else:
        _print_rows(rows, args.format, ("index", "password", "entropy_bits", "strength"))

    if args.copy and passwords:
        if _copy_to_clipboard(passwords[0]):
            print("Copied the first password to the clipboard.", file=sys.stderr)
    return 0


def cmd_passphrase(args: argparse.Namespace) -> int:
    words = load_wordlist(args.wordlist) if args.wordlist else list(default_wordlist())

    passphrases = [
        generate_passphrase(
            args.words,
            separator=args.separator,
            capitalize=args.capitalize,
            include_number=args.include_number,
            wordlist=words,
        )
        for _ in range(args.count)
    ]

    bits = wordlist_entropy(args.words, len(words))
    rows = [
        {
            "index": i + 1,
            "passphrase": phrase,
            "entropy_bits": round(bits, 1),
            "strength": analyze(phrase).label,
        }
        for i, phrase in enumerate(passphrases)
    ]

    if args.format == "plain":
        for phrase in passphrases:
            print(phrase)
    else:
        _print_rows(rows, args.format, ("index", "passphrase", "entropy_bits", "strength"))

    if args.copy and passphrases:
        if _copy_to_clipboard(passphrases[0]):
            print("Copied the first passphrase to the clipboard.", file=sys.stderr)
    return 0


def cmd_pin(args: argparse.Namespace) -> int:
    pins = [
        generate_pin(args.length, digits_only=not args.alnum, allow_repeats=not args.no_repeat)
        for _ in range(args.count)
    ]

    rows = [
        {
            "index": i + 1,
            "pin": pin,
            "entropy_bits": round(args.length * math.log2(10 if not args.alnum else 32), 1),
            "strength": analyze(pin).label,
        }
        for i, pin in enumerate(pins)
    ]

    if args.format == "plain":
        for pin in pins:
            print(pin)
    else:
        _print_rows(rows, args.format, ("index", "pin", "entropy_bits", "strength"))
    return 0


def cmd_codes(args: argparse.Namespace) -> int:
    codes = generate_recovery_codes(
        args.count,
        groups=args.groups,
        group_length=args.group_length,
        separator=args.separator,
    )

    rows = [
        {
            "index": i + 1,
            "code": code,
            "entropy_bits": round(args.groups * args.group_length * math.log2(32), 1),
            "strength": "Strong",
        }
        for i, code in enumerate(codes)
    ]

    if args.format == "plain":
        for code in codes:
            print(code)
    else:
        _print_rows(rows, args.format, ("index", "code", "entropy_bits", "strength"))
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    tokens = [generate_token(args.bytes) for _ in range(args.count)]

    rows = [
        {
            "index": i + 1,
            "token": token,
            "entropy_bits": round(args.bytes * 8, 1),
            "strength": "Very strong",
        }
        for i, token in enumerate(tokens)
    ]

    if args.format == "plain":
        for token in tokens:
            print(token)
    else:
        _print_rows(rows, args.format, ("index", "token", "entropy_bits", "strength"))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    password = args.password
    if password is None:
        password = sys.stdin.readline().rstrip("\n")

    report = analyze(password)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    if args.format == "csv":
        print("length,entropy_bits,score,label")
        print(f"{report.length},{report.entropy_bits:.2f},{report.score},{report.label}")
        return 0

    print(f"Length      : {report.length}")
    print(f"Entropy     : {report.entropy_bits:.1f} bits")
    print(f"Strength    : {report.label} ({report.score}/4)")
    if report.weaknesses:
        print("Weaknesses  :")
        for weakness in report.weaknesses:
            print(f"  - {weakness}")
    print("Suggestions :")
    for suggestion in report.suggestions:
        print(f"  - {suggestion}")
    print("Crack time  :")
    for scenario, duration in report.crack_times.items():
        print(f"  - {scenario:<22}: {duration}")
    return 0


def cmd_interactive(args: argparse.Namespace) -> int:
    """Ask the user a few questions and print a password."""
    if not args.quiet:
        _print_text(BANNER)

    def ask(prompt: str, default: str) -> str:
        answer = input(f"{prompt} [{default}]: ").strip()
        return answer or default

    length = ask("Length", "20")
    try:
        length_value = int(length)
    except ValueError:
        print("Invalid length, falling back to 20.", file=sys.stderr)
        length_value = 20

    symbols = ask("Include symbols? (y/n)", "y").lower().startswith("y")
    digits = ask("Include digits? (y/n)", "y").lower().startswith("y")
    uppercase = ask("Include upper case? (y/n)", "y").lower().startswith("y")
    exclude_confusables = ask("Exclude confusable characters? (y/n)", "n").lower().startswith("y")

    options = PasswordOptions(
        length=length_value,
        use_lowercase=True,
        use_uppercase=uppercase,
        use_digits=digits,
        use_symbols=symbols,
        exclude_confusables=exclude_confusables,
    )
    password = generate_batch(1, options)[0]
    report = analyze(password)

    print()
    print(f"Password : {password}")
    print(f"Entropy  : {report.entropy_bits:.1f} bits ({report.label})")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``passgen`` command."""
    parser = argparse.ArgumentParser(
        prog="passgen",
        description="Generate secure passwords, passphrases and PINs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  passgen generate -l 24\n"
            "  passgen generate -n 5 --exclude-confusables -f table\n"
            "  passgen passphrase -w 5 --capitalize\n"
            "  passgen check 'MyPassword123!'\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", metavar="command")

    def add_format(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "-f",
            "--format",
            choices=FORMATS,
            default="plain",
            help="output format (default: plain)",
        )

    generate = subparsers.add_parser("generate", help="generate a random password")
    generate.add_argument(
        "-l", "--length", type=int, default=20, help="password length (default: 20)"
    )
    generate.add_argument("-n", "--count", type=int, default=1, help="how many to generate")
    generate.add_argument("--no-lower", action="store_true", help="drop lower case letters")
    generate.add_argument("--no-upper", action="store_true", help="drop upper case letters")
    generate.add_argument("--no-digits", action="store_true", help="drop digits")
    generate.add_argument("--no-symbols", action="store_true", help="drop symbols")
    generate.add_argument(
        "--exclude-confusables",
        action="store_true",
        help="remove characters that look alike (l/1, O/0, ...)",
    )
    generate.add_argument(
        "--exclude", default="", metavar="CHARS", help="extra characters to remove"
    )
    generate.add_argument(
        "--no-require-all",
        action="store_true",
        help="do not force one character from every enabled class",
    )
    generate.add_argument("--no-repeat", action="store_true", help="never repeat a character")
    generate.add_argument(
        "--copy", action="store_true", help="copy the first result to the clipboard"
    )
    add_format(generate)
    generate.set_defaults(func=cmd_generate)

    passphrase = subparsers.add_parser("passphrase", help="generate a word based passphrase")
    passphrase.add_argument(
        "-w", "--words", type=int, default=6, help="number of words (default: 6)"
    )
    passphrase.add_argument("-n", "--count", type=int, default=1, help="how many to generate")
    passphrase.add_argument(
        "-s", "--separator", default="-", help="separator between words (default: -)"
    )
    passphrase.add_argument("--capitalize", action="store_true", help="capitalize every word")
    passphrase.add_argument(
        "--include-number", action="store_true", help="append a random two digit number"
    )
    passphrase.add_argument("--wordlist", help="path to a custom wordlist (one word per line)")
    passphrase.add_argument(
        "--copy", action="store_true", help="copy the first result to the clipboard"
    )
    add_format(passphrase)
    passphrase.set_defaults(func=cmd_passphrase)

    pin = subparsers.add_parser("pin", help="generate a numeric PIN")
    pin.add_argument("-l", "--length", type=int, default=6, help="PIN length (default: 6)")
    pin.add_argument("-n", "--count", type=int, default=1, help="how many to generate")
    pin.add_argument(
        "--alnum", action="store_true", help="use letters and digits instead of digits only"
    )
    pin.add_argument("--no-repeat", action="store_true", help="never repeat a character")
    add_format(pin)
    pin.set_defaults(func=cmd_pin)

    codes = subparsers.add_parser("codes", help="generate one-time recovery codes")
    codes.add_argument("-n", "--count", type=int, default=8, help="how many codes (default: 8)")
    codes.add_argument("--groups", type=int, default=2, help="groups per code (default: 2)")
    codes.add_argument(
        "--group-length", type=int, default=4, help="characters per group (default: 4)"
    )
    codes.add_argument("--separator", default="-", help="separator between groups (default: -)")
    add_format(codes)
    codes.set_defaults(func=cmd_codes)

    token = subparsers.add_parser("token", help="generate a URL-safe random token")
    token.add_argument("--bytes", type=int, default=32, help="number of random bytes (default: 32)")
    token.add_argument("-n", "--count", type=int, default=1, help="how many to generate")
    add_format(token)
    token.set_defaults(func=cmd_token)

    check = subparsers.add_parser("check", help="check the strength of a password")
    check.add_argument("password", nargs="?", help="the password (read from stdin if omitted)")
    add_format(check)
    check.set_defaults(func=cmd_check)

    interactive = subparsers.add_parser(
        "interactive", help="answer a few questions and get a password"
    )
    interactive.add_argument("-q", "--quiet", action="store_true", help="do not print the banner")
    interactive.set_defaults(func=cmd_interactive, quiet=False)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``passgen`` command.

    Args:
        argv: Command line arguments. Defaults to ``sys.argv[1:]``.

    Returns:
        The process exit code.
    """
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "generate")

    if not argv:
        argv = ["interactive"]

    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return int(args.func(args) or 0)
    except PasswordError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("\nAborted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
