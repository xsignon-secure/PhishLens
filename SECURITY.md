# Security policy

PhishLens is a security tool, so we take reports seriously.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub:
[Report a vulnerability](https://github.com/xsignon-secure/PhishLens/security/advisories/new).
Don't open a public issue for security problems.

Include what you found, how to reproduce it, and the impact you expect. We aim
to acknowledge reports within 3 working days and to ship a fix, with credit if
you want it, as soon as we can.

## Scope

In scope: this repository's code (the web app, scanner, API and scripts), for
example authentication or tenant-isolation bypasses, SSRF past the scanner's
guard, XSS, CSRF, or secrets exposure.

Out of scope: findings that need a compromised server or admin access,
rate-limit tuning on a particular public instance, and reports from automated
scanners without a working proof of concept.

## Supported versions

Fixes land on `main`. Self-hosters should update to the latest `main` or
release.
