# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |

## Reporting a vulnerability

If you find a security issue in this project, please **do not open a public
issue**. Email the maintainer or use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
and you will get a response within a week.

Please include:

- a description of the problem and its impact
- the steps needed to reproduce it
- the version, operating system and Python version you used

## Scope

This project generates and analyses passwords. Reports that are in scope:

- the generator producing **predictable** output (a biased or non-random
  character selection, a seeded PRNG, a hard-coded fallback)
- the CLI writing credentials to disk or to logs without being asked to
- the strength analyser reporting a misleading rating (for example reporting a
  known common password as "Strong")

Out of scope:

- weak password policies in other products
- attacks on the operating system or on the Python runtime
- the strength estimator being an approximation rather than a proof

## Design commitments

- All randomness comes from `secrets` / `os.urandom`. Pull requests that
  introduce `random` for credential generation will not be merged.
- Generated secrets are never written to disk by the library.
- The `check` command does not send the password anywhere; all analysis
  happens locally in the process.
