# ADR 0012 — WPShield Packs: data, never code

- **Status:** Proposed
- **Deciders:** Pedro Hernández (maintainer)
- **Affects:** the evidence collector, `WPShield.Evidence`, the MCP server and the analyst, `wpshield`,
  the desktop, the repository's `packs/` directory

## Context

The maintainer wants others to extend WPShield: new detections, new questions an assistant can ask,
new web rules. The obvious shape is a plugin, a library someone writes and WPShield loads. That
shape is wrong here, for one reason. **WPShield runs elevated.** The service, the elevated CLI and the
MCP server can all read the Security log, the evidence store and the IIS configuration of every
site. A plugin loaded into any of them runs with the same rights. One malicious or compromised plugin
would be a backdoor that the security tool installed itself. That is a supply-chain attack, and it
is exactly the kind of compromise this project exists to see.

The security community already extends tools without shipping code:

- **osquery** packs are queries over read-only tables.
- **Sigma** rules describe event-log detections in YAML, and thousands of them are public.
- **Nuclei** templates describe the paths a scanner asks for.

What they share is that the tool executes them with its own engine. A rule can only ask for what the
engine knows how to do.

MCP is already extensible in the other direction too. A client such as Claude Desktop connects to
several servers at once, so anyone can run their own MCP server beside WPShield's without WPShield
loading anything.

## Decision

**A WPShield Pack is a declarative file. WPShield's own engine executes it, within a closed set of
capabilities. A pack never contains, names or causes code to run.** Third-party code never enters a
WPShield process.

### 1. What a pack is

One JSON file of at most 256 KB, with:

- `id` (lowercase, at most 24 characters), `version`, `title`, `author`, `license` (an SPDX
  identifier), `description` and `sources` (where its knowledge comes from);
- a list of **capabilities**, each of one of the kinds below.

Unknown fields and unknown kinds are refused, never ignored. A pack WPShield cannot fully
understand does not half-run.

### 2. Capabilities, a closed list

| Kind | What it may do | What WPShield does with it |
| --- | --- | --- |
| `event-detection` | Name one event-log channel, a set of event IDs, conditions on named fields (equals, starts with, ends with, contains, one of, a bounded regular expression), and the fields to keep | The collector evaluates it on live events and records a match in `events` as kind `pack.<id>`, with only the declared fields, each cleaned and bounded |
| `http-path-rule` | Describe path shapes over the normalized request path: exact segments, extensions, suffixes and prefixes, the shape of the exposure family | Evaluated on the IIS log evidence of ADR 0011. Its score is capped at the observe threshold: a pack rule reports and never blocks alone |
| `mcp-query` | Name one aggregated question over the pack's own events: counts by a declared field, over a closed set of ranges | Exposed as a read-only MCP tool `pack_<id>_<name>`, aggregated, with attacker-influenced values under `untrusted` (ADR 0008) |

**Regular expressions** compile with `RegexOptions.NonBacktracking` and a match timeout, so a pack
cannot spend the collector's time on a pathological pattern.

**What no capability can do:**

- run a program, a script, PowerShell or a query language;
- load an assembly;
- open a network connection;
- write a file;
- change a setting;
- add a decision or a block;
- read anything outside its declared channel, fields or paths.

Reading WMI classes and registry values is a capability for later. When it comes, it will cover an
allow-list of classes, properties and keys, in an amendment that names them.

### 3. Trust: what the operator approves is exactly what runs

- Packs live in `%ProgramData%\WPShield\packs\`, a directory that install creates with the same
  restricted permissions as the evidence directory.
- `wpshield packs validate <file>` checks a pack without installing it.
  `wpshield packs add <file>` validates the pack and copies it there. WPShield never downloads a pack;
  the operator brings the file.
- **Enabling a pack records its SHA-256.** The audited setting `packs.enabled` maps each pack ID to the
  hash the operator approved, with who and why, like every setting. A file whose hash no longer
  matches is not loaded, and the mismatch is reported. Changing a pack means approving it again.
- Before a pack is enabled, `wpshield packs show <id>` and the desktop list exactly what it reads:
  - its channels and event IDs, and the fields it keeps;
  - the path shapes it matches;
  - the MCP tools it adds.

  Enabling it accepts that list, nothing more.

### 4. Bounded

Per pack:

- at most 100 capabilities;
- at most 32 fields kept per detection, each at most 256 characters;
- at most 10,000 `events` rows a day, after which further matches are counted and not stored, and the
  overflow is recorded;
- an evaluation budget per tick.

A pack that exceeds its budget is suspended until the next start, and the suspension is reported.
It does not slow the collector down.

### 5. Where packs come from

- **Built-in packs** ship in the repository under `packs/`. They are reviewed like code, carry tests
  with synthetic events, and are signed off by the maintainer. The first one is
  `wpshield.persistence`, which looks for the shapes the 2026 incident left:
  - a service installed (System 7045);
  - a scheduled task created or changed (Security 4698 and 4702);
  - an account created or added to Administrators (4720, 4732);
  - the Security log cleared (1102).
- **Community packs** arrive as pull requests to `packs/community/`, reviewed like built-in ones,
  with the same tests.
- **The operator's own packs**, anywhere they like, enabled by hash.

### 6. Sigma, by conversion

`wpshield packs import-sigma <rule.yml>` converts a Sigma rule into an `event-detection` pack. The
output is a file to review, not something that runs. The converter supports a documented subset:
Windows event-log sources, field modifiers that map to the operators in section 2, and `and`, `or`
and `not` over named selections. A rule outside the subset is refused, with the construct named; it
is never partly converted. The pack keeps the rule's ID, author, references and licence; SigmaHQ's
rules are under the Detection Rule License, which requires attribution. Evaluating Sigma natively is
not planned. One engine, fed by conversion, is easier to bound and to test.

### 7. What leaves the host

Pack events are evidence like any other. The MCP tools a pack adds follow ADR 0008, section 7:
aggregated by default, with single records only under `mcp.detailed_records`. The analyst (ADR
0010) sees them through the same tools. Showing a pack's fields before it is enabled is what lets the
operator decide whether those fields may leave the host.

## Consequences

- **The community can extend detections, web rules and questions without being able to run anything
  on the operator's server.** The cost is expressiveness: what the engine cannot express, a pack
  cannot do, and extending the engine goes through review.
- **A malicious pack can still read what it declares.** A pack that keeps every field of the Security
  log would collect sensitive data into the store, and from there into an assistant's answers. The
  declared-fields display, the hash approval and the field bounds are the answer. The operator still
  has to read what they approve.
- **The incident's persistence shapes become visible** as soon as the first built-in pack is
  enabled: the scheduled tasks, services and accounts searched for by hand on 2026-11-01.
- **No pack decides or blocks.** If a pack's findings should feed a decision, a built-in engine rule
  is written for it under ADR 0009. A pack does not gain that power by being popular.

## Alternatives considered

- **.NET plugins loaded into WPShield.** They are the most expressive option, and they are a
  supply-chain backdoor in an elevated process. Rejected for the reason in the context.
- **Plugins in a separate, unprivileged process.** Without privileges a plugin cannot read the
  Security log or the store, and with them it is the same problem again. Anyone who wants code beside
  WPShield can already run their own MCP server; the assistant then combines both.
- **PowerShell snippets as packs.** They are code by another name, and the repository's own operator
  scripts already need an inventory guard just to stay read-only.
- **Native Sigma evaluation.** It would mean two engines, two sets of bounds and two sets of tests.
  Conversion keeps one of each.

## Revisiting this decision

- When the first community pack is proposed: check the format against a real contribution.
- When a capability is requested that the list lacks, WMI and registry first: add it here by name,
  with its allow-list, never as a general "read anything" kind.
