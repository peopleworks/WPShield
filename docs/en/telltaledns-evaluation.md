# TelltaleDNS: ideas worth evaluating for WPShield

Status: research reviewed 2026-11-14; evidence and offline policy preview deliveries implemented 2026-11-17, as noted below.
Remaining items are proposals. This note does not approve an upstream integration or claim production readiness.

## Evidence and limits

The upstream revision inspected was `1928cea655b3c71d27857528135ee6d768274158`, committed
2026-11-14T19:37:16Z. Documentation and selected Rust source/tests were read; the software,
benchmarks, release workflow and upstream tests were **not executed**. Source inspection establishes
that mechanisms and assertions exist, not that every advertised behavior works in deployment.
The [commit](https://github.com/paimonsoror/telltaledns/commit/1928cea655b3c71d27857528135ee6d768274158)
is the reproducible reference for this evaluation.

TelltaleDNS is a DNS resolver/filter with device policies and observability. WPShield is an HTTP
gateway for Windows/IIS with a separate experimental network filter. The useful transfer is its
explanation and operational design, not its DNS engine or deployment model. The upstream
[architecture](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/spec/02-architecture.md) describes Linux as its first-class target and a
Rust workspace; [Cargo.toml](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/Cargo.toml) declares `Apache-2.0 OR MIT`.
If source is ever copied, review the relevant file and dependency licenses and preserve applicable
notices. This review proposes independent .NET designs, with no copied implementation.

## Priorities and acceptance gates

### 1. Versioned decision evidence — first, M4 with M3 consumers

**First delivery implemented (2026-11-17).** [Request evidence](request-evidence.md) adds a versioned
final event, build versions, a configuration activation identifier, per-stage inspection completeness,
and actual outcome. The portable rule contracts remain unchanged: the gateway owns transport outcomes.
Rich offline explanations, persisted configuration snapshots and a dedicated live CLI view remain future work.

**Inspected upstream mechanism.** [explain.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-filter/src/explain.rs)
returns matching rules, precedence, winner, snapshot version and source line attribution. It also
reports absent sources and changed source hashes. The associated
[tests](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-filter/src/explain/tests.rs) assert rule/line attribution and
changed/missing-source caveats. This is an explanation facility outside the DNS query path; it can
allocate and read stored rule sources.

**Proposal for WPShield.** Extend the existing `RuleFinding`/`InspectionResult` and JSON Lines
vocabulary with an event schema version, engine/rule-set version, opaque configuration revision,
actual disposition, reason, and inspection completeness. Record Monitor's recommended action
separately from whether forwarding actually happened. Represent “not inspected”, “partially
inspected”, “no finding” and “backend unavailable” distinctly. Keep stable rule IDs and the existing
`timestamp`, `level`, `category`, `message`, `state` envelope.

**Acceptance.** Synthetic cases for Monitor, Block, Disabled, malformed multipart, capacity exhaustion,
cancellation and failed forwarding produce distinguishable records. All components use the same
resolved client. No secret or raw filename/path is added. An explanation cannot claim historical
source lines if it has only a different current revision. Rich explanations remain off the request
path. This also gives Reader-1 an explicit basis for abstaining when evidence is incomplete.

### 2. Bounded policy preview — second, M3/M4; M5 may display it

**First delivery implemented (2026-11-17).** [Offline policy preview](policy-preview.md) compares
recorded scores with candidate Monitor/Block thresholds using the serving policy calculation.
It reads one bounded JSONL input for one site, groups results by source activation/build metadata,
and reports exclusions and unknown impact explicitly. No live configuration is read or changed.
Changed content rules, rate budgets, parser limits and automatic application are not simulated.

**Inspected upstream mechanism.** [simulate.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/simulate.rs)
replays retained query records against candidate policies with bounded rows/time and explicit partial,
busy and unavailable outcomes. It reuses the serving matcher and builds separate candidate data.
[Simulation tests](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/simulate/tests.rs) check that the serving snapshot
is unchanged and that row limits are honored. This differs from startup analytics replay.

**Proposal for WPShield.** Start with an offline comparison of existing versus candidate thresholds
and modes over synthetic fixtures and privacy-safe records, using the same scoring/action engine.
Report newly refused/allowed requests per site, inspected input count, eligible count, excluded count,
missing-data reasons, rule/configuration revisions and the evaluated time window.

**Acceptance.** Preview changes no live policy or infrastructure and respects a CPU/time/row ceiling.
Missing inputs produce “cannot evaluate”, never zero impact. A logged aggregate score can support a
threshold comparison; it cannot recreate a changed content rule. WPShield deliberately does not
retain bodies/samples, so historical upload content cannot be replayed from ordinary logs. Use
harmless synthetic fixtures for such changes; do not add body retention to make preview possible.
A preview is a historical estimate, not a forecast or authorization to enable Block.

### 3. Evidence-loss metrics and explicit privacy limits — third, M4

**Inspected upstream mechanism.** [ring.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-telemetry/src/ring.rs)
emits a whole record or drops it when a bounded ring is full, and increments a dropped counter.
[event.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-telemetry/src/event.rs) transforms records for privacy levels.
[privacy.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/privacy.rs) manages a keyed name hash, but also warns
and falls back to an unkeyed hash if the key is unavailable. That fallback is a concrete reason not
to treat upstream privacy claims as a guarantee to copy unchanged.

**Proposal for WPShield.** Preserve the existing startup refusal when logs cannot be written and its
runtime availability policy. Extend the existing bounded logging queue with dropped-event counters, write-failure
counters, inspection-skipped counts, and a clear degraded-evidence state. Export explicit coverage
metadata with reports. For community exports, use a strict allowlist and synthetic identifiers;
hashing low-entropy values is not sufficient anonymization. Privacy modes may remove information
but must never permit credentials, cookies, tokens, full queries or bodies.

**Acceptance.** A full queue or full disk does not stall forwarding or allocate unbounded memory;
the loss is visible through a surviving status/counter channel. An analyst cannot mistake a partial
log for complete evidence. Export tests check structured fields and rendered messages, per-site
isolation, controls/ANSI escapes and forbidden values. Key failure must not silently weaken an
export's privacy promise.

### 4. Keep analysis independent of serving configuration — M4/M5

**Inspected upstream mechanism.** [pipeline.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale/src/pipeline.rs)
uses `ArcSwap` for shared serving state; [snapshot.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-filter/src/snapshot.rs)
contains versioned manifests and content hashes. The
[architecture specification](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/spec/02-architecture.md) describes a data/control-plane split.
The simulation tests above provide a specific assertion that candidate evaluation does not mutate
serving state; this review does not prove whole-system availability under every controller failure.

**Proposal for WPShield.** Keep reporting, Reader-1 calls and previews outside the HTTP request path.
Use an immutable, explicitly identified effective configuration for each process and report that
revision with decisions. Preserve today's startup-only configuration semantics. Hot reload would
need a separate design, validation and atomic activation tests; a dashboard save must not pretend
that a running gateway has adopted it.

**Acceptance.** A stopped dashboard, failed analysis service, exhausted analysis quota or malformed
candidate cannot delay requests, change a site's mode, or replace the effective configuration. No
cluster, automatic failover or last-good startup fallback is introduced by this proposal.

### 5. Read-only agent interface over shared application services — later, M5/M8

**Inspected upstream mechanism.** [mcp.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-api/src/mcp.rs)
wraps REST routes with caller credentials. [plans.rs](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/crates/telltale-api/src/plans.rs)
keeps bounded, expiring plans and binds application to the configuration version. Human approval is
configurable, not universal. The [agent specification](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/spec/13-agent-api-and-mcp.md)
also describes scopes, result caps and an agent kill switch. Some upstream tools mutate state;
“has MCP” does not mean the entire interface is read-only.

**Proposal for WPShield.** Only after authenticated management is designed, consider narrow local
read tools: explain a recorded decision, summarize a site's bounded time window, report evidence
coverage, inspect redacted effective configuration, and run an offline preview. Reuse the same
services and contracts as the CLI/dashboard. Reader-1 initially needs neither MCP nor write access.

**Acceptance.** Explicit per-site authorization, bounded pagination/time/cost, cancellation and safe
error responses are tested. Data inside logs is untrusted input, never an instruction. No arbitrary
SQL, shell, filesystem access, configuration mutation or block operation is exposed. Any future
write workflow requires a separate proposal and cannot expand WPShield's infrastructure authority.

### 6. Persistent fuzz corpora and release evidence — M3/M4 testing, M6 distribution

**Inspected upstream mechanism.** The [fuzz workflow](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/.github/workflows/fuzz.yml)
configures timed fuzz runs, restored corpora and saved crash artifacts. Its targets include DNS
parsers, list parsing and log segments. The [release workflow](https://github.com/paimonsoror/telltaledns/blob/1928cea655b3c71d27857528135ee6d768274158/.github/workflows/release.yml)
runs release preflight before tagging and delegates builds/publication; it is evidence of automation,
not evidence that the currently published binaries are reproducible or correctly signed.

**Proposal for WPShield.** Reuse the testing discipline for Windows filename/path normalization,
double decoding, multipart boundaries and safe event serialization. Add reproducible failure seeds
and property assertions alongside current unit/integration tests. For M6, evaluate per-artifact SBOM,
provenance and repeat-build comparison separately from Windows signing.

**Acceptance.** Fixed seeds reproduce in CI; fuzzing has time/memory/input limits, uses harmless
synthetic markers and does not publish secrets or attack payloads. Invariants include idempotent
normalization, bounded output, stable rule IDs, Monitor semantics and no disk buffering. Distribution
retains research-preview naming, checksums, prerelease status and never-latest policy until M7;
no NuGet publishing, installer or container image is introduced.

## Recommended sequence and exclusions

Begin with the M4 evidence contract and completeness states, then a small bounded preview and
loss-aware reports. Those provide useful inputs for a separate Reader-1 evaluation. Agent access
comes after authenticated management; release evidence follows M6. These are proposed tasks, not
newly completed roadmap checkboxes or a replacement for remaining IIS validation.

Do not import TelltaleDNS's resolver, DNS filtering, Rust runtime, Kubernetes deployment or clustering
into WPShield for this evaluation. Do not copy its performance numbers as WPShield targets without
an HTTP/IIS workload and a local benchmark baseline. Do not copy any “latest” release policy.

Monitor remains the default. M1/M2 listeners remain loopback-only and production activation remains
unapproved. Nothing in this plan changes IIS, DNS, certificates, firewall settings, services or public
bindings. The network filter retains only its separately authorized, handle-scoped behavior; analysis
results are never wired directly to blocks.
