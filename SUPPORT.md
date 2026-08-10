# Support

WPShield is an early research preview maintained by volunteers. There is no commercial support
contract and no response-time guarantee.

## Before you ask

Read the [README](README.md) for current capability status, and the [roadmap](ROADMAP.md) for what
is planned but not yet built. The README status table is kept honest: if something says `Planned`, it
does not work yet, and an issue reporting that it does not work will be closed as expected behavior.

## Where to go

| I want to… | Go here |
| --- | --- |
| Report an exploitable vulnerability | [Private vulnerability reporting](https://github.com/peopleworks/WPShield/security/advisories/new) — **never** a public issue |
| Report that a rule flagged legitimate traffic | [False positive report](https://github.com/peopleworks/WPShield/issues/new?template=false_positive.yml) |
| Report a defect | [Bug report](https://github.com/peopleworks/WPShield/issues/new?template=bug_report.yml) |
| Propose a rule or capability | [Feature proposal](https://github.com/peopleworks/WPShield/issues/new?template=feature_request.yml) |
| Ask a configuration or deployment question | [Discussions](https://github.com/peopleworks/WPShield/discussions) |
| Contribute code | [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) |

## What we will not help with

- Placing WPShield in front of production traffic before the milestones in
  [ROADMAP.md](ROADMAP.md) are complete. The README warning is not a formality.
- Configuring WPShield as a public-facing listener during M1 and M2. Startup validation rejects it
  deliberately.
- Recovering a site that was already compromised. WPShield is a request-inspection gateway, not an
  incident response tool or a malware scanner. Restore from a verified backup and patch the entry
  point first.
- Using any part of this project offensively.

## Privacy when asking for help

Never paste credentials, session cookies, authorization headers, WordPress nonces, OAuth values,
complete query strings or request bodies into an issue or discussion. Redact real hostnames; use
`wordpress-one.example`. If a maintainer needs more detail than is safe to post publicly, they will
say so and move the conversation to private reporting.

## Languages

Issues, discussions and pull requests are welcome in **English or Spanish**. Documentation changes
that affect user-visible behavior are expected in both.
