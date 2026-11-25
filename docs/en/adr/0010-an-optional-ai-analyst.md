# ADR 0010 — An optional AI analyst

- **Status:** Proposed
- **Deciders:** Pedro Hernández (maintainer)
- **Affects:** a new `WPShield.Analyst` assembly, `wpshield`, the desktop, the settings catalog,
  `NOTICE.md`, the operator documentation

## Context

WPShield now records what attacks the host (ADR 0007), answers questions about it over MCP
(ADR 0008), and will decide what deserves a block (ADR 0009). What it cannot do is read a week of
that evidence and tell the operator, in their language, what changed, which source matters, what the
thresholds missed and what to fix by hand. The MCP server lets an assistant do that, but only when a
person opens Claude Desktop on the server and asks.

The maintainer wants WPShield itself to carry an analyst: a model the operator can enable with their
own key for Anthropic, OpenAI or PeopleWorks Relay, which studies the attacks, explains them and
recommends. The same three providers already run in another PeopleWorks product, and what was learnt
there applies here: the Relay's OpenAI-style lane silently drops tools, a Relay token issued for
another project still answers `200`, and a provider's own tools can make an answer look researched
when it was not.

Three facts shape every choice below:

1. **The attacker writes part of the input.** Account names, and later request paths, are chosen by
   the sender. A model that reads them and can act is a model the attacker steers.
2. **The operator pays.** If attacker volume could start a model call, the attacker would control the
   bill.
3. **Evidence leaves the host.** Whatever the model reads goes to its provider.

## Decision

**WPShield gains an optional analyst that reads the evidence store through the same read-only tools as
the MCP server and writes reports and recommendations for the operator. It is off by default, it never
acts, it runs only when the operator asks or on a schedule the operator creates, and every run is
bounded in turns, tokens and cost.**

### 1. Off by default

Nothing leaves the host until all three hold: the setting `analyst.enabled` is `true`, a provider is
chosen, and its key is present (section 4). Enabling it prints, for the chosen provider, exactly what
will leave (section 7); the desktop shows the same text before the first run. No document, landing
page or interface says the analyst protects the server. It reads and recommends.

### 2. Advisory only

The analyst's output never becomes a block decision, a setting, an allow-list entry, a label or an
input to the ADR 0009 engine. ADR 0008, section 2 already requires its own ADR, with a human
confirmation outside the model, for any action tool; that applies here unchanged.

A recommendation that **loosens** protection is labelled as loosening. That covers adding to
`defense.allow`, raising a threshold, disabling a sensor or changing the mode. It is the
recommendation an injected account name would ask for, so it is never offered as a one-click change,
even after an action ADR exists.

### 3. One tool surface

The analyst's tools are the MCP server's tool functions, called in-process: `attacks_summary`,
`top_sources`, `source_history`, `attack_timeline`, `coverage`, `decisions`, `evidence_kinds`,
`evidence_events`, `list_settings`, `address_labels`. Reusing them keeps the following defined once:

- the `{"untrusted": ...}` wrapping of attacker text;
- the `mcp.detailed_records` gate, which the analyst honours as it is (a second setting would be a
  second definition of what leaves the host);
- the bounds and the "what this answer does not know" fields.

The analyst has no shell, file, web, code-execution or provider server tool. Its process is
elevated, so any such tool would put an elevated capability within reach of injected text.

### 4. Keys

A key is never stored in the settings catalog. `list_settings` returns every setting to the model,
and `settings_history` would keep the key forever. A key is also never stored in `appsettings*.json`,
never passed as a command-line argument (shell history and process-creation auditing record those),
never logged and never written into a report.

The key is read from an environment variable of the account that runs the analyst: `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY` or `RELAY_API_KEY`. The same names are used in the other PeopleWorks product. Use
**user** scope rather than machine scope: machine variables are readable by every process on a shared
host. The operator documentation sets the variable from `Read-Host -AsSecureString`, so the key never
appears in a typed command that PowerShell would save in its history.

The catalog holds only what is safe to show a model: `analyst.enabled`, `analyst.provider`,
`analyst.model`, `analyst.effort`, `analyst.language`, `analyst.relay_url` and the budgets.

### 5. Where it runs

The analyst lives in a new assembly, `WPShield.Analyst`. The CLI and the desktop reference it;
`WPShield.Gateway` never does, so the service never opens a connection to a model provider. It is not
one of the portable projects either, because it carries provider SDKs that the rule packages have no
reason to see.

The analyst runs when:

- the operator types `wpshield analyst ...`;
- the operator presses **Ask** in the desktop;
- a scheduled task that the operator creates by hand runs `wpshield analyst digest`. Creating that
  task stays manual, like every other server setting.

### 6. Roles

There is one loop and one tool set; each role is a different prompt.

| Role | Command | What it writes |
| --- | --- | --- |
| Digest | `wpshield analyst digest [--since 24h]` | What happened, what changed against the previous period, which sources and networks matter, and which coverage gaps make the picture incomplete |
| Investigate | `wpshield analyst investigate <address or network>` | One source in depth: history, pattern, neighbours, decisions, what to do by hand |
| Ask | `wpshield analyst ask "<question>"`, desktop **Ask** | An answer to the operator's question |
| Tune | `wpshield analyst tune` | After a week of Monitor: `would-block` and `protected` decisions against the thresholds, with proposed amendments to ADR 0009's defaults as text for the maintainer |

`wpshield analyst test` checks the provider without spending model tokens where the provider allows
it. For the Relay, it calls `/v1/auth/whoami` and names the project the token belongs to.

### 7. Providers, and what leaves the host

Each provider receives the system prompt, the operator's question and every tool result the model
asks for. By default, ADR 0008, section 7 defines that content:

- counts, source addresses and their networks, coverage, decisions and settings;
- **labels**, which name the operator's own addresses;
- with `mcp.detailed_records` set, the account names tried, which include real accounts on the server.

| Provider | Protocol | Where the data goes | Notes |
| --- | --- | --- | --- |
| Anthropic | Messages API, official `Anthropic` .NET SDK | Anthropic, under the operator's API terms | Default model `claude-opus-5-5`; adaptive thinking; effort set explicitly, default `medium`. Tools are `strict` with `tool_choice: auto`, because forced tool choice is rejected by current models |
| PeopleWorks Relay | The same SDK pointed at `analyst.relay_url`, `/v1/messages` lane in passthrough only | The Relay's host, where a Claude Code terminal answers with **its own local tools** | Its OpenAI-style lane drops tools silently and is refused. What injected text can make that terminal do is decided by the Relay's configuration, not by WPShield, and the disclosure says so. Its cost is counted as zero here, because WPShield does not pay it |
| OpenAI | Responses API, official `OpenAI` .NET SDK | OpenAI, under the operator's API terms | Phase 2. No default model: the operator names one |
| Simulated | none | nowhere | Tests and demonstrations |

Each SDK is added through central package management and gets a `NOTICE.md` row. `analyst.relay_url`
must be `https`. Examples use `https://relay.example`.

### 8. Bounded, and never started by an event

- **Per run:** at most 12 tool calls, an output cap, a 5-minute timeout and a cancellation token.
- **Per day:** `analyst.daily_runs` (default 10) and `analyst.daily_input_tokens` (default 2,000,000).
- **When a bound is reached, the run is refused** with a message that names the bound. It does not run
  a smaller analysis that would look like a complete one.

No event, detection, decision or attack volume ever starts a run.

### 9. A report is opinion, kept apart from evidence

Reports go to their own SQLite file, `wpshield-analyst.db`, in the evidence directory that install
already restricts. They never go to the evidence store: the store holds what was observed; this file
holds what a model thought about it. Keeping them apart also leaves the evidence store's one-writer
rule intact.

Each report records:

- the provider, the model, the role, the input and output tokens and the stop reason;
- every tool call, with its name and arguments;
- the text, cleaned of control and format characters and bounded at 64 KB.

Retention is 90 days and at most 1,000 reports.

The desktop shows a report as plain text under a label that reads "AI analysis: opinion, not
evidence", and it never turns text into links or runnable commands. A command in a report is text
for the operator to read before running.

A refusal (`stop_reason: refusal`, which a model may return on attack analysis) is recorded and shown
as a refusal with its category. It is never shown as an empty report. Anthropic's server-side
fallback is enabled, and the report names the model that actually answered.

### 10. Phases

1. Anthropic and the Relay, which share one protocol:
   - the CLI roles `test`, `digest`, `investigate` and `ask`;
   - budgets and the report store;
   - the desktop's reports view and **Ask** box.
2. OpenAI.
3. The `tune` role, and checking claims: every address and count in a report that no tool result
   contained is marked unverified.

## Consequences

- **Evidence leaves the host** to the chosen provider, as section 7 states. Choosing the Relay moves
  it to the Relay's host instead of to Anthropic's API.
- **Recommendations will sometimes be wrong**, and some will be written under the influence of
  attacker text. Advisory-only output, the loosening label and the separate opinion store limit what
  a wrong recommendation can do.
- **It costs money**, which the operator bounds with the budget settings. The Relay moves the cost to
  a subscription.
- **A run can be refused** by a budget, a missing key, a disabled setting or the model itself. Each
  refusal says which.
- **The Relay is a dependency.** If its service is down, a run fails and says so. Scheduled digests
  are better pointed at the Anthropic API.

## Alternatives considered

- **Only the MCP server.** That route already works, but it needs a person to open an assistant on
  the server and ask. It cannot write a morning digest, and it is not inside the tool the operator
  already has open.
- **An agent framework (Semantic Kernel, Microsoft Agent Framework).** The loop is a few dozen lines
  and must be auditable call by call. The other PeopleWorks product rejected a framework for the same
  reason.
- **Anthropic Managed Agents.** It would tie the analyst to one provider while the decision asks for
  three. It would also mean either uploading the evidence or exposing its tools beyond the host.
- **An analyst that can act.** Rejected by ADR 0008, section 2, and by the first fact in the context.
- **A local model**, through an OpenAI-compatible endpoint on the host. Nothing would leave the host,
  which is a real advantage. It is left for a later amendment, once phase 1 shows what quality the
  roles need.

## Revisiting this decision

- After phase 1 has run for two weeks on the incident host: compare the digests with what the
  operator found by hand, and the spend with the budgets.
- When an action ADR exists: decide whether any recommendation may become a proposed action. A
  loosening one never may (section 2).
