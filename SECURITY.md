# Security Policy

## Authorized use

VulnScan is a security assessment tool intended **only** for systems you own or have
explicit written permission to test. Using it against third-party systems without
authorization may be illegal. You are solely responsible for your use of this tool.

The scanner performs **passive and light-active** checks only (GET / OPTIONS / GraphQL
introspection). It deliberately contains no exploitation, denial-of-service, brute-force,
or detection-evasion capabilities.

## Reporting a vulnerability

If you discover a security vulnerability **in VulnScan itself**, please report it privately:

- Open a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories) on the repository, **or**
- Email the maintainer, **Ahmed AL Abri**:
  - **a.ghost.om@gmail.com**
  - **79033079a@gmail.com**

Please include steps to reproduce and the affected version. We aim to acknowledge reports
within 72 hours. Do not open a public issue for security problems.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
