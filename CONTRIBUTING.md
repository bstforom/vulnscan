# Contributing to VulnScan

Thanks for your interest! VulnScan is open source (MIT) — everyone is welcome to use, modify,
and improve it.

## Ground rules

- **Authorized, defensive use only.** VulnScan performs passive/light-active checks. Please do
  not add exploitation, denial-of-service, brute-force, or detection-evasion features — those are
  out of scope and PRs adding them will be declined.
- Be respectful and constructive in issues and reviews.

## Getting started

```bash
git clone <your-fork-url>
cd vulnscan
npm install
npm test        # run the test suite
npm start       # http://localhost:3000
```

Requires Node.js 22+ (uses the built-in `node:sqlite`).

## Making a change

1. Fork the repo and create a branch: `git checkout -b my-change`.
2. Make your change. Keep the style of the surrounding code.
3. **Add or update tests** in `test/` and make sure `npm test` passes.
4. Update `README.md` / `CHANGELOG.md` if behavior changes.
5. Open a pull request describing what and why.

## Adding a new check or detection

- **Web checks** live in `src/checks.js`; sensitive paths in `src/wordlists.js`.
- **Secret patterns** live in `src/secrets.js`; **SAST rules** in `src/sast.js`.
- Every finding should include a `severity`, a clear `title`, a `detail` (remediation),
  an `evidence` string, and ideally a `cwe` and `owasp` tag.
- Prefer **high precision** — add a content signature or version check to avoid false positives.

## Reporting a security issue

See [SECURITY.md](SECURITY.md) — please report privately, not via a public issue.
