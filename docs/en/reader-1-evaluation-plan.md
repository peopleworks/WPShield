# Reader-1 evaluation and conditional integration plan

Status: proposal only, 2026-11-14. No API calls, account changes, uploads or integration have been performed.
WPShield baseline: `7ec142f4561a84754b363155db30e24a91617549`. [ROADMAP](../../ROADMAP.md) remains authoritative.

## Recommendation

Evaluate Reader-1 as an optional analyst for public documentation and synthetic incident reports.
Keep it outside HTTP inspection and enforcement. First establish whether it adds value over direct
JSON parsing, deterministic calculations and source lookup. Corpus Hub participation is a separate
activity; it neither installs Reader-1 nor validates a model on WPShield data.

## Verified documentation, not independently tested behavior

- Reader-1 is a preview model distinct from Query-1 and the local search engine. The vendor explicitly
  acknowledges wrong evidence, wrong operations and incorrect answers with high confidence.
  [Announcement](https://xerj.org/blog/xerj-reader-1-waitlist).
- The documented entry points are `POST /v1/answers` and `POST /v1/execute`. Execute replays a program
  without model inference, but remains a hosted API: this is not evidence of offline replay.
  [Quickstart](https://platform.xerj.ai/docs/quickstart), [Execute](https://platform.xerj.ai/docs/api-execute).
- Document plus question has a 6,080-token model window. Evidence offsets count Unicode code points,
  use an exclusive end, and refer to the exact submitted text. `DECLINE.best_guess` is not an answer.
  [Concepts](https://platform.xerj.ai/docs/concepts).
- The vendor says API documents, questions and answers are not retained; playground inputs may be
  retained and reviewed. The preview has no uptime SLA or compliance certification. These are vendor
  statements, not an independent privacy audit. [Privacy](https://platform.xerj.ai/docs/privacy-security).
- Published preview limits are 60 requests/minute and 2,000,000 input tokens/UTC day per account;
  each question rereads its document. Recheck the account limits before a trial.
  [Limits](https://platform.xerj.ai/docs/rate-limits).

## Proposed phases and deliverables

| Phase | Work | Exit evidence | Estimated engineering effort |
| --- | --- | --- | --- |
| 0. Contract | Obtain authorized access later; confirm model/version identifiers, types/statuses, limits, retention, region/subprocessors and independent replay availability | Recorded answers to the open questions below; agreed trial budget | Half a day, excluding access wait |
| 1. Corpus | Pin public WPShield docs and create synthetic reports with known answers; deterministic reference calculations | Reviewed gold cases, source hashes, expected values and evidence | 1–2 days |
| 2. Comparison | Run the same cases through deterministic baseline and Reader-1; use development cases to select confidence thresholds | Case-level results, failure taxonomy, cost and latency | 1–2 days |
| 3. Verification | Test offsets, program replay, semantic correctness, isolation and service failures | Independent replay comparisons and safety tests | 1–2 days |
| 4. Decision | Evaluate the held-out set and document go/no-go per task | Results with denominators, limitations and a recommendation | Half a day |
| 5. Optional integration | Only after a separate implementation decision, build a standalone read-only analyst | Contract tests, bounded resource usage and removal test | Estimate after phases 0–4 |

These are planning estimates, not delivery commitments. No phase is currently implemented.

## Evaluation corpus

Propose 120 cases, split by source document into 60 development and 60 held-out cases; do not let
paraphrases of the same document cross that boundary. Include English and Spanish in every group.
Have a second human check the reference answers before using the held-out set.

| Group | Cases | Examples and expected behavior |
| --- | --- | --- |
| Direct evidence | 30 | Which mode is configured? Which rule fired? Cite exactly the relevant field or sentence |
| Derived values | 30 | Elapsed UTC time, observed refusal counts, score capped at 100; compute locally as the reference |
| Missing facts | 20 | Attack entry point, infection source or total traffic absent from the document: no invented answer |
| Ambiguity and contradictions | 20 | Two revisions, conflicting timestamps, duplicates, multiple sites, ambiguous date formats |
| Adversarial and limits | 20 | Instructions embedded in text, control characters, emoji before evidence, mixed units, oversized input |

Use harmless markers and `.example` hosts. No credentials, real topology, request bodies, upload
samples or customer logs. Public-source inputs must name their commit. Synthetic reports must name
their generator version and source events. Never equate Monitor's `WouldBlock` with an actual refusal.
Count distinct requests, not file findings. Distinguish an observed count in supplied records from
a total over a complete traffic interval. An absent or partial log cannot establish a clean host.

## Baseline, verification and metrics

1. Parse structured events and compute counts/durations deterministically first. Reader-1 competes
   for extracting relevant facts from prose; it must not replace a reliable JSON parser.
2. Store each submitted text unchanged with its hash and transformation version. Any future redaction
   happens before submission; do not reconstruct offsets against the original unredacted document.
3. Check evidence bounds and exact quotes using code-point offsets. A .NET adapter must map them to
   UTF-16 indices correctly; test emoji, combining marks, CRLF and LF. Escape output when displayed.
4. Treat the symbolic program as untrusted data. Never execute it through a shell, C#, JavaScript,
   PowerShell or general-purpose evaluation. Permit only reviewed operations in a bounded evaluator.
5. Compare `/v1/execute` with the original value, then independently verify supported operations
   locally. Repeating the vendor's executor checks reproducibility, not independent correctness.
   Until an official portable executor is established, scope local verification to documented simple
   operations with strict decimal/date semantics; unsupported operations remain unverified.
6. Check whether the selected evidence and operation actually answer the question. Exact arithmetic
   over the wrong site, month or revision is a wrong answer. A confidence number cannot override this.
7. Report answer precision, coverage on answerable cases, safe abstention, quote integrity, replay
   agreement, p50/p95 latency, tokens and cost, separately by task and language. Keep errors and
   abstentions in denominators. Re-run after model or schema changes.

Proposed initial gates, to agree before running: all accepted answers have valid evidence and pass
independent checks where applicable; zero cross-site disclosures or executed document instructions;
at least 95% precision on accepted answers, 80% coverage on answerable cases and 95% safe abstention
on missing/ambiguous cases. These are pilot gates, not production guarantees. Publish counts and
uncertainty intervals; 60 held-out cases cannot establish a rare-error rate. A larger representative
set and human review are required before any operational adoption.

Keep a task only if it passes the safety gates and improves verified analyst effort or coverage over
the deterministic baseline. Stop or narrow scope when high-confidence semantic errors remain common.

## Conditional architecture

`selected public/synthetic text -> local input checks -> optional Reader-1 adapter -> evidence/program verification -> human-readable report`

This is a separate tool/process. No Reader-1 reference in Core, rules, the HTTP request pipeline or
NetworkFilter enforcement. The gateway continues normally when the analyst is offline or unavailable.
A later M5 dashboard may display verified reports; it does not gain authority to change policies.

Proposed adapter envelope: provider/model identifier, document hash/revision, site scope, question,
status, typed value, evidence offsets/quotes, program, confidence, verification status, token usage,
latency and provider request ID. This is an internal proposal, not a claim about existing WPShield APIs.
No-answer, provider error and failed verification must remain distinct; `best_guess` is never promoted.

Bound text size, output size, concurrency, queue, deadline and spend. Begin with one outstanding request,
a 30-second deadline and at most two retries for documented transient failures, honoring Retry-After
within the job budget. Do not automatically retry authentication, invalid-input or exhausted-credit
errors. Defer daily-quota work rather than holding a process waiting until midnight. Use the documented
account headers and count every attempt against the local budget. Keep API keys outside repository
and browser code. Do not add paid credit automatically.

Chunk by document/incident with a mapping to original offsets and explicit time/site scope. No silent
truncation; missing cross-chunk evidence means abstention or a separate deterministic aggregation.
Do not claim a retrieved excerpt represents all records. Before any log-count use case, verify that
log loss and retention gaps are reliably surfaced; current logging code and documentation must not
be treated as proof of completeness. See [logging implementation](../../src/WPShield.Logging/JsonLinesLogWriter.cs).

Removal means disabling the analyst and revoking its key: no change to HTTP protection. If a future
operator needs to bypass the gateway itself, disable the IIS forwarding rewrite rule first; stopping
the service alone leaves IIS forwarding to a dead port. M1/M2 stay loopback-only, Monitor stays the
default, and this experiment makes no IIS, DNS, certificate, firewall, service or public-port changes.

## Questions to resolve with Ivan before execution

- Can the model and executor revisions be pinned, and how are breaking changes announced?
- Is a licensed local executor available? Does hosted execute use an identifiable executor revision?
- Do privacy guarantees explicitly cover execute as well as answers, error traces and subprocessors?
  Which processing region applies, and how are incident-related support samples handled?
- What are the approved account's actual quota, supported Spanish behavior and cost controls?
- Can failed cases be reported privately using synthetic reproducers, without publishing incident data?

No message has been sent to Ivan. No account enrollment or data transfer is part of this plan.
