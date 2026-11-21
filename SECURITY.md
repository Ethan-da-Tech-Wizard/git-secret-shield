# Security policy

## What git-secret-shield is, and is not

git-secret-shield is a small, standard-library Python tool that looks for credential-shaped strings in files and staged git changes. It uses patterns plus a Shannon-entropy heuristic and can miss real secrets (encoded, split or unusual formats) and flag harmless data. A clean scan is not proof that no credentials exist, and the pre-commit hook can be skipped with git commit --no-verify.

It is not audited by any third party. The tests are the author's own, written with AI coding agents. Do not treat it as a security boundary or rely on it as your only control.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**: open this repository's **Security** tab and choose **Report a vulnerability**. That creates a private advisory visible only to the maintainer and to you. Do not open a public issue for a vulnerability, and do not paste real secrets or personal data into any report.

Useful in a report: what you did, what you expected, what happened, and your Python version and OS.

This is a one-person project with no service-level promise; reports are answered as time allows.

Wrong or overstated claims in the README count too. Open a normal issue for those.

## Supported versions

Only the latest commit on the default branch. There are no releases.
