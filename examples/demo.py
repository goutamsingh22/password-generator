"""A small tour of the passgen library.

Run it with::

    python examples/demo.py
"""

from __future__ import annotations

from passgen import (
    PasswordOptions,
    analyze,
    generate_batch,
    generate_passphrase,
    generate_pin,
    generate_recovery_codes,
    generate_token,
)


def main() -> None:
    print("=" * 60)
    print("1. Random passwords")
    print("=" * 60)
    for password in generate_batch(3, PasswordOptions(length=24)):
        print(f"   {password}")

    print()
    print("=" * 60)
    print("2. Without confusable characters")
    print("=" * 60)
    options = PasswordOptions(length=24, exclude_confusables=True)
    print(f"   {generate_batch(1, options)[0]}")

    print()
    print("=" * 60)
    print("3. Diceware passphrase")
    print("=" * 60)
    print(f"   {generate_passphrase(6)}")

    print()
    print("=" * 60)
    print("4. PIN and recovery codes")
    print("=" * 60)
    print(f"   PIN:    {generate_pin(6)}")
    for code in generate_recovery_codes(3):
        print(f"   Code:   {code}")

    print()
    print("=" * 60)
    print("5. URL-safe token")
    print("=" * 60)
    print(f"   {generate_token(32)}")

    print()
    print("=" * 60)
    print("6. Strength report")
    print("=" * 60)
    for candidate in ("password", "Tr0ub4dor&3", "Kq7#vR2$xLp9!zWc4&"):
        report = analyze(candidate)
        print(f"   {candidate:<20} {report.entropy_bits:>7.1f} bits  {report.label}")


if __name__ == "__main__":
    main()
