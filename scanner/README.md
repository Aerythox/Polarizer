# Polarizer scanner

A small Python CLI that replays API requests across several user identities to
find broken authorization. Give it an OpenAPI spec and tokens for two or three
test users, and it checks whether one user can act as another.

**Only scan systems you own or are authorized to test.**

## What it checks

| Check | OWASP API Top 10 (2023) | How it decides |
| --- | --- | --- |
| BOLA | API1 Broken Object Level Authorization | One user requests another user's object by ID. Flagged if the response is 2xx and matches what the owner sees. |
| BFLA | API5 Broken Function Level Authorization | A non-admin calls a route you marked admin-only. Flagged if the response is 2xx. |
| Mass assignment | API3 Broken Object Property Level Authorization | A user sends a field such as `role` on an update, then reads it back. Flagged if it changed. Needs `--allow-writes`. |
| Missing authentication | API2 Broken Authentication | A route the spec marks as protected is called with no token. Flagged if the response is 2xx. Safe methods only. |
| Weak JWT secret | API2 Broken Authentication | Each supplied token's signature is recomputed against a short list of common secrets. Offline, sends no requests. |

## Install

```
cd scanner
python -m venv .venv
.venv/Scripts/activate        # Windows; use source .venv/bin/activate on macOS/Linux
pip install -e ".[dev]"
```

## Run against the lab in this repo

Start the lab (see the top-level README), then:

```
# Log in the test users and set their tokens as environment variables
eval "$(python examples/get_tokens.py)"            # bash
python examples/get_tokens.py --powershell          # PowerShell: run the printed lines

polarizer scan --config examples/lab.yaml --allow-writes --format both --out-dir reports
```

The scan prints a Markdown report and writes `reports/polarizer-report.md` and
`.json`. Exit codes:

- `0` no findings
- `1` findings
- `2` the scan could not run properly (bad config, unreachable host, or a user
  could not read their own object)

The non-zero code on findings is what lets it fail a CI job.

## Configuration

Tokens are read from environment variables named in the config, never stored in
the file. The config also supplies the knowledge an OpenAPI spec does not carry:
which object each user owns, and which routes are meant to be admin-only. See
[`examples/lab.yaml`](examples/lab.yaml).

## Safety

- Only `localhost` is allowed by default. Any other host needs `--allow-host HOST`,
  which is you asserting you may test it. The host is checked on every request,
  including after redirects, which are never followed.
- Requests are rate limited (default 5 per second, `--rate` to change).
- Writes happen only with `--allow-writes`, are limited to the mass-assignment
  check, run against the test user, and are restored afterward.
- Tokens are never written to reports. Evidence records show only the identity
  label, method, path, and status.

## Honest limits and false positives

- **You describe the target.** The scanner only knows an object's owner and which
  routes are admin-only because you told it. Wrong entries cause wrong results.
- **BOLA uses response similarity.** If two users genuinely share identical data,
  or an endpoint returns the same empty envelope to everyone, the comparison can
  misjudge. It reports both directions it finds, which you should confirm by hand.
- **It reasons about status codes and bodies, not intent.** A route that returns
  200 with an empty list is treated as success. Read the evidence before acting.
- **It is not a fuzzer.** It does not discover endpoints, object IDs, or
  injection flaws. It tests the authorization of the operations you give it.
- **The JWT check is a short wordlist,** meant to catch obvious default secrets.
  A strong secret will correctly show nothing.

## How it relates to existing tools

The idea is the same as the [Autorize](https://github.com/PortSwigger/autorize)
extension for Burp Suite: take a request made as one user, replay it as another,
and compare. Autorize works inside Burp as an interception proxy, driven by your
browsing. Polarizer is a standalone CLI driven by an OpenAPI spec, so it fits in
CI and produces a diffable report. It is narrower than Autorize and is not a
replacement for a proxy-driven review or a manual test. It is a focused,
repeatable check for the most common authorization mistakes.

## Tests

```
pytest -q
```

The tests run the full scanner against an in-memory fake of the lab, so they need
no server or database.
