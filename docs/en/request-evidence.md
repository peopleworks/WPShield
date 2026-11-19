# Request evidence: traceability and inspection completeness

These events can now feed the [offline policy preview](policy-preview.md) for mode/threshold
comparisons over recorded scores. Missing evidence remains unknown; content is not replayed.

Implemented: the gateway emits a final `request_completed` event for each request that enters its
forwarding endpoint. This is the first delivery from the [TelltaleDNS evaluation](telltaledns-evaluation.md),
implemented independently in .NET. WPShield remains a research preview, not approved for production
traffic. Monitor remains the default; M1/M2 listeners remain loopback-only.

## Finding, decision and outcome

Findings and inspection summaries describe what a stage learned and recommended. They do not prove
that forwarding succeeded. The final event is emitted in `finally`, after forwarding or refusal, in
category `WPShield.Gateway.Evidence` at Information level. It keeps the existing JSON Lines envelope
(`timestamp`, `level`, `category`, `message`, `state`). Read `state.EventType=request_completed` and
`state.SchemaVersion=1`, rather than parsing the rendered message.

Use `RequestId` to join the final event to existing findings and the `X-WPShield-Request-ID` response
header. `SiteId` and `Mode` identify the resolved site's policy; both are null for an unknown host.
`Client` comes from the same `ResolvedClient` used by the forwarder, including trusted-proxy handling.
It is `unknown` if no address was resolved.

| Field | Meaning |
| --- | --- |
| `ConfigurationRevision` | Opaque random identifier generated after startup configuration validation. Stable for this activation, new on every restart even if settings are unchanged. The startup activation event carries it too. It is **not** a configuration hash, snapshot, or proof that two activations used different settings. |
| `GatewayVersion`, `EngineVersion`, `WindowsRulesVersion`, `WordPressRulesVersion` | Loaded assemblies' informational versions, including the source revision when the build embeds one; `unknown` if absent. They identify build metadata, not signed provenance or an exact reconstruction of an uncommitted working tree. |
| `Disposition`, `Reason` | Actual pipeline result and stable reason, separately from inspection recommendations. |
| `ForwardingAttempted` | Whether the gateway called the forwarder. A true value does not prove delivery; a prefix may have reached the backend before a failure. |
| `StatusCode` | Gateway response status at completion, or null on cancellation/unhandled failure. A status on a failed exchange does not prove the client received a complete response. |
| `RateLimitRuleId` | The exceeded rate budget's ID, or null. Monitor records the excess and continues; Block refuses. |

`Disposition` is one of:

- `forwarded` / `exchange_completed`: the forwarder finished without a transport error. A backend
  HTTP 4xx or 5xx can still have this outcome; it does not mean WordPress accepted an upload.
- `rejected`: the gateway refused before calling the forwarder. `Reason` is its existing error token,
  such as `unknown_host`, `request_blocked`, `upload_blocked`, `multipart_not_inspectable`,
  `multipart_concurrent_limit_exceeded`, `rate_limited`, `request_timeout` or `request_too_large`.
- `forwarding_failed`: a forward was attempted but failed; for example `backend_unavailable` or
  `request_too_large` when a streaming body exceeds the limit after forwarding began.
- `cancelled` / `request_cancelled`: the request cancellation was observed during processing.
- `failed`: an unhandled exception interrupted processing; `Reason` is `pipeline_failure` or
  `forwarding_exception`. The event carries no exception text.

## What was inspected

Path and upload inspection have independent `PathStatus` / `UploadStatus` and corresponding
`Reason`, `Action`, `Score`, `RuleIds`, and `RuleIdsTruncated` fields (each prefixed with `Path` or
`Upload`). IDs are comma-separated, distinct, sorted, and limited to 16 per stage. Truncation is
explicit. Upload scores remain the maximum across file evaluations, never a sum across files.

| Status | Interpretation and reasons |
| --- | --- |
| `not_started` | The pipeline did not reach the stage (`not_reached`), for example after an unknown-host or path refusal. |
| `not_inspected` | Explicit skip: `disabled`, `inspection_disabled`, `empty_body`, `non_multipart` or `capacity_exhausted`. Action and score remain null. |
| `partial` | Work started but did not complete: `malformed`, `limit_exceeded`, `read_timeout`, `parse_timeout`, `request_too_large`, `request_cancelled` or `interrupted`. Completed file evaluations, if any, remain in the record. |
| `complete` | The configured stage finished: `rules_completed` for path rules, `sampled_scope` for uploads. Zero score and no rule IDs mean no findings **within that scope**. |

`PathAction` and `UploadAction` come from the engines after applying mode and thresholds. A Monitor
finding may therefore say `Observe` while the final disposition is `forwarded`, `forwarding_failed`
or `cancelled`. A null action means no evaluation result was obtained. A partial stage with an `Allow`
result covers only the evaluations that finished; it does not approve the uninspected remainder.

`FilesRead` is null until parsing returns, then counts the returned filename views; `FilesInspected`
counts views evaluated by the rules. `filename` and `filename*` can create two views of one physical
part. `SampleBytesInspected` sums their evaluated sample sizes and can count a shared sample twice.
`SampleLimitBytes` is the configured maximum leading sample per view. These are not total request
bytes or physical file counts. Fields are not scanned. Non-multipart bodies, archive interiors and
file content beyond the leading sample remain outside upload inspection. A complete inspection is
neither a malware-free certificate nor exhaustive content coverage.

## Compatibility, privacy and remaining limits

The existing finding and summary prefixes stay unchanged. Upload summaries now use
`Decision=forward|reject` instead of prematurely claiming `Disposition=forwarded|blocked`.
Incomplete-multipart warnings use `ForwardPermitted` instead of `Forwarded`; capacity warnings use
`ForwardUninspected` instead of `ForwardedUninspected`. Consumers requiring actual outcome must read
the final event. `wpshield watch` still shows its existing finding/summary view; a dedicated final-event
view is future work. Portable `RuleFinding` and `InspectionResult` contracts are unchanged.

The new event adds no paths, filenames, hosts, headers, query strings, body content or samples.
Its client address, configured site ID and request ID are still operational data: this is not an
anonymized community export. Keep existing log access controls and retention. No request content is
written to disk, and no historical configuration or content snapshot is retained for replay.

One final log call is made per forwarding-endpoint invocation, including early refusals and exceptions.
Health/reserved endpoints, requests rejected by the HTTP server before this endpoint, process crashes,
log filtering, queue saturation and storage failures are outside that guarantee. Keep Information
enabled for `WPShield.Gateway.Evidence` to retain these events. A missing event is **unknown**, never
evidence of a successful forward or an inspected request.

No deployment setting or infrastructure changes are needed. Applying a build still requires a restart;
configuration does not hot-reload. For a deployed gateway, bypass remains the IIS rewrite rule:
stopping the service while that rule forwards to WPShield takes the site down. This work makes no
IIS, DNS, certificate, firewall, service or public-port changes and does not integrate Reader-1.

## Measuring evidence loss

With local .NET diagnostics access, read the running gateway's meter using
`dotnet-counters monitor --process-id <PID> --counters WPShield.Evidence`. The meter remains
available while the file destination is disabled or failing. All values are untagged and reset on restart.

| Instrument (prefix `wpshield.evidence.`) | Interpretation |
| --- | --- |
| `queue_drops` | Individual log entries discarded when the file queue was full. |
| `failed_batches` | File write batches that failed. A batch can be partially written. |
| `skipped_stages` | Path or upload stages ending as `not_started` or `not_inspected`, up to two per forwarding request. Ordinary non-multipart traffic can contribute one. |
| `file_enabled` | 1 when the JSONL destination is configured, otherwise 0. |
| `degraded` | 1 after the first queue drop or failed batch in this process. It stays set after recovery. Skipped inspections alone do not set it. |

The writer attempts to record pending loss notices on a subsequent successful write. Notices can
repeat after a failed flush. A crash, earlier rotation or a log filter can leave gaps with no notice.
The operator PDF marks coverage **partial** for observed loss, unreadable input or invalid lines.
Otherwise it reports **unknown** traffic coverage. Gateway-level notices in the time window apply
even to a site-filtered report. Invalid lines have no reliable time or site and count across the file.
Keep PDFs private. For sharing, use the [community preview format](policy-preview.md#community-export).
