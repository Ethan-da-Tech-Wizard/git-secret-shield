# Git Secret Shield

Git Secret Shield is a Python project for exploring secret detection in files and Git changes. It combines pattern matching with entropy-based checks and includes commands for reports, hook management, and redaction.

**Status:** Experimental security tooling. Detection can miss secrets or flag harmless data. A clean result is not proof that a repository contains no credentials, and the tool has not been independently security audited in this review.

## Getting started

The project declares Python 3.8 or newer in [pyproject.toml](pyproject.toml). From the repository root:

```sh
python3 -m secretshield --help
python3 -m secretshield scan .
python3 -m secretshield scan --staged --fail-on-findings
python3 -m secretshield patterns
```

To save an example report, the CLI supports `python3 -m secretshield scan . --json -o audit-receipt.json`. Treat findings and reports as sensitive: review their contents before sharing.

The CLI also offers `install-hook`, `uninstall-hook`, and `redact` commands. Read each command's `--help` and inspect your existing hook before installation; `install-hook --force` can overwrite it. Redaction can modify files, especially with `--in-place`; use a disposable copy first and keep an appropriate backup. If a real credential is exposed, revoke or rotate it using the issuing service's process.

The commands above are based on the CLI source and previous documentation; they were not run as part of this review. See the tests for examples and check your own environment before relying on a hook.

## Project layout

[CLI source](secretshield/cli.py) · [Package metadata](pyproject.toml) · [Tests](tests/) · [Issues](https://github.com/Ethan-da-Tech-Wizard/git-secret-shield/issues)

## License

Project code is distributed under the [MIT License](LICENSE). Dependencies and tools retain their own terms.
