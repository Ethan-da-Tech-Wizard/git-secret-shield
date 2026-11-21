# Contributing

Thanks for looking. This is a small, one-maintainer project, so the process is light.

## Useful contributions

1. **Corrections:** a claim in the README or docs that the code or tests do not support.
2. **Bug reports** with a reproduction (exact command, version, OS, raw output).
3. **Small pull requests** that fix one thing and add or change a test.

Vulnerabilities do not go in public issues; see [SECURITY.md](SECURITY.md). Questions and bugs: GitHub Issues on this repository.

## Run the tests

```sh
python3 -m unittest discover -s tests
```

No install step and no network are needed. CI runs the same command on Ubuntu and macOS.

## Style

Python 3.9 or newer, standard library only (no third-party dependencies). Keep changes small, add a test for every behavior change, and write comments that say why, not what.

## Ground rules

- No private data in code, tests or docs: no real keys, tokens, hostnames, MAC addresses, e-mail addresses or personal paths. Build credential-shaped test strings from pieces at run time so the source holds no scannable literal.
- Claims need evidence: numbers in the docs come from a real run you can repeat.
- AI-assisted contributions are welcome; say so in the pull request and read the code yourself first.

By contributing you agree your contribution is licensed under the repository's license (MIT). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
