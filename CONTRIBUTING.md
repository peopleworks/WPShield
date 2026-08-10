# Contributing

Thank you for helping build WPShield.

You do not need to write C# to contribute meaningfully. A [false positive
report](https://github.com/peopleworks/WPShield/issues/new?template=false_positive.yml) from someone
running WordPress on IIS is worth more to this project than most code changes, because a rule that
blocks legitimate traffic takes a working site offline.

## Principles

- Defensive use only.
- Explainable rules with tests.
- No real credentials, private logs, real hostnames, or weaponized examples.
- English is the canonical code language; user-facing content should be localizable.
- New behavior must default to Monitor mode unless explicitly justified.

## Before you start

Read [AGENTS.md](AGENTS.md). It holds the project invariants, and they are not negotiable style
preferences: several exist because a specific evasion or disclosure was found and fixed. Reverting one
reopens a real hole. The same file is what keeps AI coding assistants consistent with the project, so
if you establish a new invariant, record it there.

## Validation

Every change must pass locally before it is pushed:

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
dotnet format WPShield.slnx --verify-no-changes
git diff --check
```

CI additionally builds and tests `WPShield.Abstractions`, `WPShield.Core` and
`WPShield.Rules.WordPress` on Linux, so do not introduce a Windows-only dependency into those three.

## Pull requests

1. Create a focused branch.
2. Add or update tests.
3. Update English and Spanish documentation when user-facing behavior changes.
4. Explain false-positive risks and operational impact.
5. Do not combine unrelated changes.
6. Add an entry to [CHANGELOG.md](CHANGELOG.md) under `Unreleased`.

## Contributing a rule

A rule is not ready to merge until it arrives with all of the following:

- A stable, untranslated rule ID following the existing families (`WP-`, `IIS-`, `PHP-`, `FILE-`).
- The signals it combines, and why that combination rather than a single indicator.
- Its score, and the reasoning for that number against the default thresholds of 30 to observe and
  80 to block. A rule that blocks alone needs to justify why it can never be wrong.
- An explicit false-positive analysis. "None expected" is acceptable only when you can say why.
- Benign test fixtures that must stay silent, including realistic WordPress, Elementor and Google
  Site Kit traffic.
- Evasion tests. Assume an attacker knows the rule exists. If the rule reads a file name, it must
  match on the normalized form; see [upload rules](docs/en/m2-upload-rules.md).
- English and Spanish documentation.

Use harmless synthetic markers in tests. Never commit a working webshell.

## Security issues

Do not open a public issue for an exploitable vulnerability. Follow [SECURITY.md](SECURITY.md).

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
