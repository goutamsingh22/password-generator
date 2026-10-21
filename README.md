
# 🔐 passgen - Python Password Generator

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-85%20passing-brightgreen.svg)](tests)
[![No dependencies](https://img.shields.io/badge/dependencies-0-informational.svg)](pyproject.toml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A fast, **dependency-free** password generator with a strength analyser, diceware
passphrases, PINs, recovery codes and URL-safe tokens - usable as a CLI or as a
Python library.

> Every random choice is made with Python's [`secrets`](https://docs.python.org/3/library/secrets.html)
> module, which draws from the operating system's cryptographically secure random
> source. `random` is never used for credentials.

---

## ✨ Features

| Feature | Description |
| --- | --- |
| 🔡 Random passwords | 1-256 characters, custom character classes, guaranteed one from each class |
| 🗣 Diceware passphrases | Uses the official **EFF large wordlist** (7,776 words, 12.9 bits per word) |
| 🔢 PINs | Numeric or alphanumeric, optional no-repeat |
| 🛟 Recovery codes | Ambiguity-free groups such as `H4KM-7PQR` for 2FA resets |
| 🔑 URL-safe tokens | `secrets.token_urlsafe` for API keys, session ids and CSRF tokens |
| 📊 Strength analyser | Entropy in bits, 0-4 rating, weakness detection and crack-time estimates |
| 🚫 Confusable filter | Removes characters that look alike (`l`/`1`, `O`/`0`, ...) |
| 🖥️ Four output formats | `plain`, `json`, `csv` and `table` for scripting and piping |
| 🤖 Interactive mode | Answer a few questions, get a password |
| 📋 Clipboard support | `--copy` puts the first result on your clipboard |
| 🧪 85 unit tests | Cross-platform CI on Linux, macOS and Windows |

---

## 📦 Installation

```bash
# from a clone
git clone https://github.com/goutamsingh22/password-generator.git
cd password-generator
pip install .

# development install with the test tools
pip install -e ".[dev]"
```

The package has **no runtime dependencies** and works on Python 3.8+.
You can also run it straight from the source tree without installing:

```bash
python -m passgen generate -l 24
```

---

## 🚀 Quick start

```bash
# a 20 character password (the default)
passgen generate

# longer, and without characters that look alike
passgen generate -l 32 --exclude-confusables

# five passwords as a table, with entropy for each
passgen generate -n 5 -f table
```

```text
+------+---------------------------+--------------+---------------+
| index | password                  | entropy_bits | strength      |
+------+---------------------------+--------------+---------------+
| 1    | 8sQ!vGz2#Kd7Lmpw          | 129.2        | Very strong   |
| 2    | Zr4$wHn9@Ty3QbXe          | 129.2        | Very strong   |
| 3    | fJ7&aCv2*Uo6#Ns           | 129.2        | Very strong   |
+------+---------------------------+--------------+---------------+
```

---

## 🛠️ Commands

### `generate` - random password

```bash
passgen generate [options]
```

| Option | Description | Default |
| --- | --- | --- |
| `-l, --length` | Password length | `20` |
| `-n, --count` | How many to generate | `1` |
| `--no-lower` | Drop lower case letters | off |
| `--no-upper` | Drop upper case letters | off |
| `--no-digits` | Drop digits | off |
| `--no-symbols` | Drop symbols | off |
| `--exclude-confusables` | Remove look-alike characters | off |
| `--exclude CHARS` | Remove specific characters | - |
| `--no-require-all` | Do not force one char per class | off |
| `--no-repeat` | Never repeat a character | off |
| `--copy` | Copy the first result to the clipboard | off |
| `-f, --format` | `plain`, `json`, `csv`, `table` | `plain` |

```bash
$ passgen generate -n 3 --no-symbols -f csv
index,password,entropy_bits,strength
1,Pz3mKq7Lw9,71.4,Strong
2,Tr8yBcx4Hd,71.4,Strong
3,Nv6jRg2Wq5,71.4,Strong
```

### `passphrase` - word based passphrase

```bash
passgen passphrase -w 6 --capitalize --include-number
# correct-horse-battery-staple-42
```

| Option | Description | Default |
| --- | --- | --- |
| `-w, --words` | Number of words | `6` |
| `-s, --separator` | Separator between words | `-` |
| `--capitalize` | Capitalize every word | off |
| `--include-number` | Append a random two digit number | off |
| `--wordlist` | Path to a custom wordlist | EFF list |

A six word passphrase carries about **77.5 bits** of entropy - far stronger than
a typical 12 character password with mixed characters.

### `pin` - numeric PIN

```bash
passgen pin -l 4 --no-repeat
# 7391
```

### `codes` - one-time recovery codes

```bash
passgen codes -n 8 --groups 2 --group-length 4
# H4KM-7PQR
```

### `token` - URL-safe token

```bash
passgen token --bytes 32
# 0Yl3nG8sVq1Xz0Kf5mT7pR2wYb9CdEjH4uA6oIs8
```

### `check` - analyse an existing password

```bash
passgen check "Tr0ub4dor&3"
```

```text
Length      : 11
Entropy     : 24.9 bits
Strength    : Very weak (0/4)
Weaknesses  :
  - It contains the common word 'troubador'.
Suggestions :
  - Use at least 16 characters.
  - Avoid words, keyboard runs and repeated characters.
Crack time  :
  - offline_fast_hash     : instantly
  - offline_slow_hash     : 25 minutes
  - online_unthrottled    : 4 hours
  - online_throttled      : 42 hours
```

Add `-f json` to get the same report as JSON, for example for a sign-up form
that checks a password in the browser or in a service.

### `interactive` - guided mode

```bash
passgen interactive
```

---

## 🐍 Python API

```python
from passgen import (
    PasswordOptions,
    analyze,
    generate_batch,
    generate_passphrase,
    generate_pin,
    generate_recovery_codes,
    generate_token,
)

# a single password
options = PasswordOptions(length=24, exclude_confusables=True)
password = generate_batch(1, options)[0]

# a passphrase
phrase = generate_passphrase(words=5, separator=".", capitalize=True)

# a PIN and recovery codes
pin = generate_pin(6)
codes = generate_recovery_codes(count=8)

# a token for a session cookie
token = generate_token(32)

# analyse something the user typed
report = analyze("Tr0ub4dor&3")
print(report.entropy_bits, report.label, report.weaknesses)
```

`PasswordOptions` fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `length` | `20` | Number of characters |
| `use_lowercase` | `True` | Allow `a-z` |
| `use_uppercase` | `True` | Allow `A-Z` |
| `use_digits` | `True` | Allow `0-9` |
| `use_symbols` | `True` | Allow punctuation |
| `exclude_confusables` | `False` | Drop look-alike characters |
| `exclude_chars` | `""` | Extra characters to remove |
| `require_all_classes` | `True` | One character from every enabled class |
| `allow_repeats` | `False` | Allow repeated characters |

---

## 📐 How the entropy is calculated

For a password drawn uniformly from a pool of `N` distinct characters:

```text
entropy = length × log2(N)
```

The default pool has 88 characters (26 + 26 + 10 + 26 symbols), so a 20
character password carries about **129 bits** of entropy.

The analyser additionally looks for patterns that make a password easier to
guess and reduces the estimate accordingly:

- common passwords (`password`, `123456`, ...)
- dictionary words embedded in the password
- repeated characters (`aaaa`) and repeated blocks (`abcabc`)
- sequential runs (`abcd`, `9876`)
- keyboard walks (`qwerty`, `asdfgh`)
- years (`2024`) and single character-type passwords

Crack times are reported for four scenarios, from a fast offline attack
(10^10 guesses/second, a GPU rig against a fast hash) to a throttled online
attack (10^2 guesses/second).

---

## 🗂️ Project structure

```text
password-generator/
├── passgen/
│   ├── __init__.py       # public API
│   ├── __main__.py       # python -m passgen
│   ├── cli.py            # argparse based command line interface
│   ├── generator.py      # password, passphrase, PIN and token generation
│   ├── strength.py       # entropy, rating, weaknesses, crack times
│   ├── wordlist.py       # wordlist loading and filtering
│   └── data/
│       └── eff_large_wordlist.txt   # 7,776 words (public domain, EFF)
├── tests/
│   ├── test_generator.py
│   ├── test_strength.py
│   ├── test_wordlist.py
│   └── test_cli.py
├── examples/
│   └── demo.py
├── .github/workflows/ci.yml
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## 🧪 Testing

```bash
python -m unittest discover -s tests -v
# or
pytest -q
```

---

## 🔒 Security notes

- Randomness comes from `secrets` / `os.urandom`, never from `random`.
- Passwords are **not** logged, cached or written to disk by this tool.
- The `--copy` option uses the system clipboard; be aware that clipboard
  managers may keep a history.
- Prefer a password manager with a generated password over reusing a phrase.
- A passphrase is only as strong as the wordlist behind it - 7,776 words give
  12.9 bits per word, so six words are strong but four words (51.7 bits) are
  not enough for high value accounts.

---

## 🛠️ Contributing

Contributions are welcome.

1. Fork the repository and create a branch.
2. Add tests for any behaviour you change.
3. Make sure `python -m pytest -q` and `ruff check .` pass.
4. Open a pull request describing what you changed and why.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the details.

---

## 📜 License

Released under the [MIT License](LICENSE).

The EFF large wordlist in `passgen/data/` is in the public domain, published by
the Electronic Frontier Foundation.
=======
# password-generator
>>>>>>> 1b85d669c47ae42ce8cd3da9767947b6c7f97fea
