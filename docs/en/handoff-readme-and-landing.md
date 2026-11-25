# Handoff for Codex: the README and the landing page (2026-11-25)

Working note, not a published document. Pedro asked for the README and `site/index.html` to be put
in order: both have grown by accretion and no longer say what WPShield is for. Delete this note when
the work it describes has merged.

## What is wrong today

- **The first screen describes a past product.** The README opens with "a security gateway", a
  subtitle about how many upload rules exist and what they do not read, and a hero figure about two
  file uploads. The landing page opens on "What reached your Windows server?" and then spends most of
  its length on upload and file-name edge cases. Since November WPShield also watches the host:
  failed Windows logons live and over 30 days, an evidence store, listener and traffic views, and an
  MCP server an assistant can ask. A reader of either page would not learn that.
- **The README is a manual.** 795 lines: architecture, request inspection internals, the rule list,
  configuration, response meanings, troubleshooting, traceability, comparisons, recent security work.
  Each is useful; none belongs before the reader knows what the tool is.
- **Numbers that age.** Rule counts in the subtitle and test counts in three places drift with every
  pull request; each rebase this week had to fix them by hand.

## What each page is for

**README:** the front door on GitHub. In order:

1. **Identity in one sentence**, then the research-preview warning immediately below it. Suggested:
   "WPShield (Windows Power Shield) watches a Windows Server that hosts IIS and WordPress sites: the
   requests that reach the sites, the logons that try the host, and the evidence of both - so you can
   see what is happening and ask about it."
2. **Three capabilities, one short paragraph and one image each**, in this order:
   - *Attacks on the host* - the desktop's Attacks view (failed RDP, SMB and network logons, 24 hours
     live, 7 and 30 days from the evidence store, labels), `wpshield attacks`.
   - *Requests to the sites* - the gateway in front of IIS, in Monitor by default, with the rules that
     matter on IIS (executable uploads, `web.config`, path rules).
   - *Ask about it* - `wpshield mcp`, read-only, for Claude Desktop or Claude Code.
3. **Quick start**: download the release, verify the SHA-256, `wpshield preflight`, then either the
   desktop (Attacks) or `wpshield evidence collect` + `wpshield attacks`. Five commands, no more.
4. **What it does not do yet**, plainly: it does not block at the host level on `main` (ADR 0006 is
   accepted; the enforcer is in PR #86), it is not approved for production traffic, and the gateway
   stays on loopback during M1/M2.
5. **Status**: a short table that links to `ROADMAP.md` for detail.
6. **Documentation, contributing, security, licence, credits**: links.

Everything else moves out of the README into `docs/en/` with a Spanish counterpart in `docs/es/`
(AGENTS.md requires both), linked from `docs/README.md`: architecture and request inspection, the
rule catalogue, configuration, response meanings, troubleshooting, traceability and policy preview,
comparisons, recent security work. Move the text; do not rewrite it in the same change, so the move is
reviewable.

**Landing page (`site/index.html`):** the page an evaluator reads instead of the README.

- Keep the research-preview warning **above the fold, before any capability**, in both languages, as
  `AGENTS.md` requires. It already is; keep it there.
- Lead with the same three capabilities as the README, with the same words.
- Keep the upload and file-name sections, but after the three capabilities, under a heading such as
  "Why IIS needs its own rules". They are the project's best technical writing; they are not its
  introduction.
- One "Start with a question" block that maps a question to a command, as today, updated with
  `wpshield attacks`, the desktop's Attacks view and `wpshield mcp`.

## Rules that apply (all from AGENTS.md or this week's decisions)

- **Never claim what `main` does not do.** No "blocks attacks", "protects your server" or "stops brute
  force" until the enforcer merges and is validated. "Watches", "records", "shows", "explains" are
  true today. Monitor is the default mode.
- **Images use synthetic data only**: RFC 5737 / RFC 3849 addresses, `.example` hostnames, no
  screenshot of the production host (its RDP port and public address appear in Pedro's own
  captures - never use those). Claude rendered the Attacks view from synthetic data for review; ask
  Pedro for that capture or render your own the same way from a test.
- **Figures ship as light and dark pairs** with `<picture>`, and alt text states the figure's argument
  in a sentence. Desktop screenshots have no dark theme: either render both variants, or record in
  `AGENTS.md` why a screenshot is exempt, in the same change.
- **Third-party names identify software only**; affiliation statements stay in `NOTICE.md`.
- **Test counts appear once.** Keep the per-project sentence in one place (or generate it in CI) and
  have the status table say "tested in CI" without a number, so a rebase stops touching three lines.
- **Bilingual.** The README links to `docs/es/`; the landing page keeps its `lang="en"` / `lang="es"`
  pairs.

## Acceptance

- A reader who stops after the first screen of the README knows the three capabilities and that it
  is a research preview.
- The README is under 250 lines; every moved section is reachable from `docs/README.md` in English and
  Spanish.
- No sentence on either page claims host-level blocking.
- Every image has a light and dark variant (or a recorded exemption) and a sentence of alt text.
- `git grep -n` finds no test count outside the one sentence you keep.
