# Offline policy preview

Implemented: `wpshield preview` compares recorded inspection recommendations with a candidate
Monitor or Block policy. It is the second delivery from the [TelltaleDNS evaluation](telltaledns-evaluation.md).
The shared `InspectionPolicy` calculation is used by both serving engines and the preview. No
request is replayed and no content rule runs: the preview holds the recorded scores constant.

WPShield remains a research preview, not approved for production traffic. Monitor stays the default;
M1/M2 listeners remain loopback-only. Preview performs no IIS, service, DNS, certificate, firewall,
public-port, gateway configuration or Reader-1 operations.

## Run it

Use a local copy of a gateway JSON Lines file containing [schema-1 final request events](request-evidence.md):

```powershell
wpshield preview --log-file .\synthetic-evidence.jsonl --site wordpress-one.example --mode Block --observe-threshold 30 --block-threshold 80
```

`--site` selects one exact, case-sensitive `SiteId`, not an HTTP hostname lookup. Both `--site` and
`--log-file` are required. Candidate mode defaults to Monitor; thresholds default to 30/80.
Observe must be 0..100; block must be 1..100 and at least observe. Disabled is intentionally not
simulated: turning inspection back on cannot recover scores never recorded. Unknown, repeated,
valueless or invalid options are refused. `wpshield preview --help` lists the options.

The command opens only the named file for reading and writes aggregate JSON to stdout. It never
reads live configuration and has no apply option. Each invocation is independent of serving and
other previews. It neither needs elevation nor contacts another service.

## Read the result

| Field | Meaning |
| --- | --- |
| `candidate`, `candidatePolicyId`, `previewEngineVersion` | Candidate mode/thresholds, their canonical `score-policy-v1/...` identifier, and the build metadata of the scoring engine used for this preview. |
| `selectedRecords` | Final events assigned to the requested site, including excluded records. |
| `eligibleRecords`, `excludedRecords`, `exclusions` | Comparable records and records that cannot support a comparison, with explicit reasons. Eligible plus excluded equals selected. |
| `newlyRefused`, `newlyPermitted` | Eligible records changing into or out of the Block recommendation. These are policy decisions, not successful application transactions. |
| `changedRecommendations`, `unchangedRecommendations` | Changes among Allow, Observe and Block, including observe-threshold changes that cause no refusal. |
| `comparisons` | The same counts grouped by original configuration activation, mode, gateway/engine/rule versions; different activations are never silently merged. |
| `windowStart`, `windowEnd` | Earliest/latest timestamps among eligible records, regardless of input order. These are the evaluated window, not proof that every request in it is represented. |
| `linesRead`, `bytesRead`, `ignoredLines`, `invalidLines`, `otherSiteRecords`, `evidenceLossNotices` | Input coverage, unclassified/damaged lines, site isolation and observed logging-loss notices. |
| `status`, `stopReason`, `limits` | Whether comparison completed over its selected input, what interrupted it, and the scan budgets. |

If no record is eligible, impact counts and the evaluated window are **null**, not zero impact.
`status` is `complete`, `partial`, `cannot_evaluate` or `unavailable`. Corresponding exit codes are
0, 2, 3 and 1; invalid arguments also return 1. A partial comparison retains counts only for the
eligible subset. `appliesChanges` and `provesLogCompleteness` are always false.

Baseline actions come from the final events, after the original mode/thresholds were applied.
Candidate actions are calculated from the path and upload scores separately; the scores are never
added together. A skipped upload is eligible only when its explicit reason is `non_multipart` or
`empty_body` and its score/action are null. Those bodies remain outside upload inspection.

Partial or skipped inspection for other reasons, Disabled mode, exceeded rate budgets, transport
failures/cancellations, unknown schema, missing provenance, truncated rule lists and inconsistent
outcomes are excluded. A path refusal before upload inspection is also excluded: relaxing the path
policy cannot reveal what the unread body would have contained. Requests are deduplicated by
activation and request ID; repeated rows are counted as excluded. Duplicate JSON keys and malformed
UTF-8/JSON are not trusted. Known loss notices make the comparison partial.

## Bounds and limitations

| Bound | Default | Hard ceiling |
| --- | --- | --- |
| `--max-lines` (all input lines, including ignored ones) | 10,000 | 100,000 |
| `--max-bytes` (bytes read) | 16 MiB | 64 MiB |
| `--timeout-seconds` | 10 | 60 |
| One JSON line | 32 KiB | 32 KiB |
| Provenance groups | 64 | 64 |
| JSON depth | 16 | 16 |

The reader uses fixed buffers, retains no complete input file, and bounds duplicate tracking by the
line ceiling. Line/byte/deadline exhaustion, an oversized line, source truncation or an unterminated
last record is explicit. A file without a final newline is treated conservatively as potentially
torn. The byte snapshot stops at the size observed when opened; new appended bytes are not followed.
Detected length changes are reported, but a same-length rewrite is not detectable. The deadline is
cooperative after opening the source; it is not a guarantee about operating-system file-open latency.
Use a copied file for reproducibility. No source hash or authenticity proof is produced.

Only aggregate comparison and allowlisted provenance are returned: no request IDs, client addresses,
paths, filenames, headers, samples or message text are copied into the report. Site IDs and build/
activation metadata remain operational data; the output is not an anonymized community export.

`complete` means every selected record in the scanned input was comparable, not that logs cover all
traffic. Other log events are counted as ignored and never reconstructed as requests; legacy-only
logs cannot be evaluated. Filtering, missing files, rotation, process crashes and absent loss notices
can leave unseen gaps. Neither changed content rules nor new rate/size/parser limits can be simulated
from these scores. This is a historical estimate over recorded sample scope, not a forecast, security
certificate or authorization to enable Block. There is nothing to roll back: preview changes nothing.
For an independently deployed gateway, bypass remains the IIS rewrite rule before stopping its service.
