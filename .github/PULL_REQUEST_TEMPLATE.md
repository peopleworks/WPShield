<!--
  Small and focused merges faster than large and comprehensive. One concern per pull request.
  Nothing in this template — not the description, not the tests, not the commit message — may
  contain a real hostname, an internal port, a credential, or a captured production request.
-->

## What this changes

<!-- One paragraph. What was wrong or missing, and what this does about it. -->

Closes #

## Why

<!--
  The reasoning that is not visible in the diff: the evasion it closes, the false positive it
  prevents, the operator mistake it makes impossible, the alternative you rejected and why.
  If an invariant in AGENTS.md motivated the shape of the change, name it.
-->

## Security and operational impact

<!--
  What changes for someone already running this on loopback? New response codes, new startup
  refusals, a different default, more work per request. "None" is a valid answer — say it rather
  than leaving this empty.
-->

## False-positive considerations

<!--
  What legitimate WordPress, Elementor, Google Site Kit or plugin traffic could this newly flag?
  For a non-rule change, what could it newly break. "None expected" is acceptable only with the
  reason attached.
-->

## Checklist

- [ ] **`dotnet test WPShield.slnx --configuration Release` passes**, and new behavior arrived with
      tests. A behavior with no test is a behavior that regresses quietly.
- [ ] **`dotnet format WPShield.slnx --verify-no-changes` passes.** CI runs this as its own job, so a
      formatting miss turns the pull request red before anyone reads the diff.
- [ ] **The build is clean.** `TreatWarningsAsErrors` is on.
- [ ] **English and Spanish documentation updated** for user-visible behavior, with the same numbers
      in both. A Spanish reader following a different limit from an English reader is a defect.
- [ ] **Monitor is still the default protection mode.** Blocking stays per-site and explicit.
- [ ] **No working webshell or weaponized payload** in fixtures, tests or documentation. Harmless
      synthetic markers demonstrate a detection just as well.
- [ ] **No real hostnames, internal ports or deployment topology** anywhere in the diff, including
      test data and the commit message. Use `wordpress-one.example` and loopback destinations.
- [ ] **`WPShield.Abstractions`, `WPShield.Core` and `WPShield.Rules.WordPress` gained no ASP.NET
      Core, YARP, IIS or Windows-only dependency.** The Linux CI leg exists to catch exactly this.
- [ ] **`CHANGELOG.md` updated under `Unreleased`**, so an operator can tell whether they need this.

## If this adds or changes a rule

<!--
  Assume the attacker knows the rule exists. On Windows, `shell.php.`, `shell.php ` (trailing space),
  `shell.php::$DATA` and `..\..\shell.php` all reach disk as `shell.php` — which is why a rule reads
  InspectionContext.NormalizedFile and never the raw client value, and why it checks every extension
  segment rather than only the last one.
-->

- [ ] Stable, untranslated rule ID in an existing family (`WP-`, `IIS-`, `PHP-`, `FILE-`).
- [ ] The score is justified against the default thresholds — 30 to observe, 80 to block. A rule that
      blocks on its own has said why it can never be wrong.
- [ ] An explicit false-positive analysis, with benign fixtures that stay silent, including realistic
      WordPress, Elementor and Google Site Kit traffic.
- [ ] Evasion tests against the normalized file name, covering every extension segment.
- [ ] Evidence is the normalized name, and carries nothing that must not be logged.
- [ ] The rule is documented in `docs/en` and `docs/es`.

## If this touches a figure or the landing page

- [ ] Both `docs/assets/<name>-light.svg` and `docs/assets/<name>-dark.svg` were updated together.
      A reviewer only ever sees their own theme's variant, so a one-sided edit passes review unnoticed.
- [ ] The `alt` text states the figure's argument in a full sentence, not a label.
- [ ] The figure shows placeholder hostnames and loopback ports, never real topology.
- [ ] `site/index.html` still carries the research-preview warning above the fold.
