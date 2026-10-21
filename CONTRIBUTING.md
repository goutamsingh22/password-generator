# Contributing to passgen

Thanks for taking the time to contribute.

## Getting set up

```bash
git clone https://github.com/goutamsingh22/password-generator.git
cd password-generator
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # macOS / Linux
pip install -e ".[dev]"
```

## Running the checks

```bash
python -m pytest -q        # tests
ruff check .               # lint
black --check .            # formatting
```

All three must pass before you open a pull request. The same commands run in
GitHub Actions on Linux, macOS and Windows.

## Guidelines

- **Keep it dependency free.** The library must stay importable with nothing
  but the standard library. Optional integrations belong behind extras.
- **Never use `random` for credentials.** Use `secrets` or
  `random.SystemRandom`.
- **Add a test with every change.** A new option needs at least one test for
  its default behaviour and one for its edge case.
- **Keep the CLI output stable.** Scripts may depend on it; prefer adding a
  new flag over changing existing output.
- **Document user facing changes** in the README and the help text.

## Reporting bugs

Open an issue with the command you ran, the output you got, the output you
expected and your Python version.

## Adding a wordlist

Wordlists live in `passgen/data/`. A custom list can also be passed at
runtime with `--wordlist path/to/words.txt`; one word per line, or the EFF
Diceware `number<TAB>word` format.
