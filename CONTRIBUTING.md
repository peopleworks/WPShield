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

## Where things live

| Path | What it is, and what belongs there |
| --- | --- |
| `src/WPShield.Abstractions/` | Inspection contracts. Changing one is a breaking change for every rule. |
| `src/WPShield.Core/` | Site resolution, scoring, Monitor/Block policy. Most engine fixes belong here. |
| `src/WPShield.Rules.WordPress/` | The rules themselves. A new detection normally starts and ends here. |
| `src/WPShield.Gateway/` | Kestrel and YARP, startup validation, forwarding. The only project allowed HTTP concerns. |
| `src/WPShield.Service/` | The engine demonstration. It is what the worked example in the README runs. |
| `tests/` | xUnit. 215 tests today, all of which run in about a second. |
| `docs/en/`, `docs/es/` | Paired operator and architecture documentation. Neither language is the translation of the other; both are maintained. `docs/README.md` indexes them. |
| `docs/assets/` | Figures used inside the documentation, as light/dark SVG pairs. |
| `assets/` | The project mark, the hero figure and the social preview. |
| `site/` | The GitHub Pages landing page. |
| `scripts/` | Read-only operator scripts: triage and IIS validation. They must never change a machine. |

## Validation

Every change must pass locally before it is pushed:

```powershell
dotnet restore WPShield.slnx
dotnet build WPShield.slnx --configuration Release --no-restore
dotnet test WPShield.slnx --configuration Release --no-build
dotnet format WPShield.slnx --verify-no-changes
git diff --check
```

If you touched anything under `scripts/`, also run:

```powershell
pwsh -File scripts/Test-WPShieldScripts.ps1
```

`dotnet build` never looks at a `.ps1`, so nothing above would notice a syntax error, a non-ASCII
byte that Windows PowerShell 5.1 cannot read, a new write path in a tool documented as read-only, or
a copy of the gateway's rule vocabulary that has drifted away from the gateway. That last one is the
quiet failure: a drifted copy does not break, it reports coverage WPShield does not have.

`dotnet format --verify-no-changes` is a CI job, not a suggestion — a pull request that fails it is
red before anyone reads the diff.

CI additionally builds and tests `WPShield.Abstractions`, `WPShield.Core` and
`WPShield.Rules.WordPress` on Linux. That leg is not there for portability as a goal in itself: the
README claims those three projects are platform-independent, and the Linux job is what makes the
claim falsifiable. Adding an ASP.NET Core, YARP, IIS or Windows-only dependency to any of them turns
that job red, which is the intended outcome. HTTP and Windows concerns belong in
`WPShield.Gateway`.

## Commit convention

```text
feat(scope): description
fix(scope): description
test(scope): description
docs(language): description
security(scope): description
refactor(scope): description
```

Use `security(scope)` when the change closes an evasion or a disclosure, even if the diff is one
line. The changelog is read by operators deciding whether they need to update, and that prefix is
how they find those entries.

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

## Contributing documentation

Operator-visible and architectural documentation lives in `docs/en` and `docs/es` as matching pairs.
Write each language rather than translating word for word, but keep the structure aligned: the two
files should have the same headings, and every number in one — score, threshold, port, byte limit —
must be the same number in the other. A Spanish reader following a different limit from an English
reader is a defect, not a translation nuance.

Configuration examples in documentation use RFC 2606 placeholders (`wordpress-one.example`,
`wordpress-two.example`) and loopback destinations. Never a real hostname, a real internal port, or
anything that describes a deployment that exists.

## Contributing a figure

Figures are hand-authored SVG and ship as **light/dark pairs**:

```text
docs/assets/<name>-light.svg
docs/assets/<name>-dark.svg
```

They are referenced through `<picture>` so the reader's theme picks the variant:

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/<name>-dark.svg">
  <img alt="A full sentence stating what this figure argues." src="docs/assets/<name>-light.svg">
</picture>
```

Three rules, each of which exists because the failure is silent:

- **Update both variants in the same commit.** Editing one leaves half of your readers with a figure
  that contradicts the text, and a reviewer looking at the rendered pull request sees only their own
  theme's variant, so nothing catches it.
- **The `alt` text carries the figure's argument**, in a full sentence — not a label. A figure whose
  point lives only in the pixels is unavailable to a screen reader and to every renderer that is not
  GitHub.
- **A figure must not depict real topology.** The same placeholder rule as configuration examples.

Mermaid stays the right tool for diagrams that change with the code — architecture and flow diagrams
inside `docs/en` and `docs/es`. Author a figure as an SVG pair when it needs to survive off GitHub:
the README's load-bearing figures and anything used on the landing page.

If you change `site/index.html`, the research-preview warning must remain above the fold. That page
is read by people evaluating WPShield who will never open the README, so it is the one place the
warning cannot be a callout further down.

## Security issues

Do not open a public issue for an exploitable vulnerability. Follow [SECURITY.md](SECURITY.md).

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
