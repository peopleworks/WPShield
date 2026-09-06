# M2: Bounded multipart inspection

Until this change the inspection engine never ran on real traffic. `GatewayApplication` resolved the
site, checked the request size and forwarded; the `WPShield.Gateway` project did not even reference
`WPShield.Rules.WordPress`. Every rule this project documents executed only from the
`WPShield.Service` console demonstration. WPShield was, in practice, a reverse proxy with a size
limit and an unknown-host rejection.

This document describes what runs on gateway traffic now: which requests are inspected, what is
parsed, what is sampled, every limit and its ceiling, how findings across several files become one
decision, and what each mode answers with. The gateway is still loopback-only and still not approved
for production traffic.

## Which requests are inspected

Inspection is deliberately narrow. A request is buffered and inspected only when **all** of the
following hold, checked in this order in `UploadInspectionService.EvaluateAsync`:

1. `Gateway:Multipart:Enabled` is `true`.
2. The resolved site's `Mode` is not `Disabled`.
3. The declared `Content-Length` is not zero.
4. The request declares `multipart/form-data`, either with a boundary the gateway accepts or with
   one it refuses — see [Boundaries](#boundaries).

Everything else keeps streaming straight through with no added memory cost and no change in
behaviour: `GET` requests, `application/x-www-form-urlencoded` form posts, JSON REST calls, XML-RPC,
`application/octet-stream` PUTs, and `multipart/*` subtypes other than `form-data`. Ordinary
WordPress page traffic must not start paying for uploads it does not contain, and it does not.

> [!IMPORTANT]
> Condition 4 has two outcomes, not one. A request that declares `multipart/form-data` with a
> boundary the gateway will not parse is **not** treated as ordinary traffic — it is a finding. A
> gateway that forwards what it cannot parse hands an attacker a one-line bypass: an unusual
> boundary, and the request sails through uninspected while IIS and PHP parse it happily.

## Why the body is buffered, and what bounds it

To **block**, the gateway has to decide before forwarding. To **forward**, it has to read the body a
second time. A network stream cannot be read twice. So for multipart requests only, the
already-bounded body is buffered in memory, inspected, and then forwarded from that buffer.

Four properties make that safe, and each is a property of the code rather than of a setting:

- **Never to disk, structurally.** The buffer is `PooledRequestBuffer`, a seekable read-only
  `Stream` over a list of 64 KiB arrays rented from `ArrayPool<byte>.Shared`. It references no
  `FileStream`, no `File`, no `Path` and no memory-mapped file, so there is no disk path to prove
  unreachable. `Microsoft.AspNetCore.WebUtilities.FileBufferingReadStream` was rejected for exactly
  this reason: its spill-to-disk is disabled by a threshold value, and a guarantee a future
  contributor can undo by editing one number is not the guarantee this project promises. Two tests
  hold that guarantee. One redirects every temporary-directory environment variable the framework
  consults — `ASPNETCORE_TEMP` included, which is the one `FileBufferingReadStream` reads — runs a
  battery of bodies through the reader and requires the directory to still be empty. The other
  scans the gateway assembly's type references and fails if any type that can write a file appears
  in them, with a positive control asserting that the scan can see `MultipartReader`, so a scan that
  silently read nothing cannot pass by proving nothing.
- **Never unbounded.** `RequestBodyLimitStream` is now installed *before* the inspection step rather
  than immediately before the forward, so the drain into the buffer is itself bounded by
  `Gateway:MaximumRequestBytes`. That ordering is the point: a chunked body declaring no
  `Content-Length` would otherwise be buffered without a limit. `PooledRequestBuffer` enforces the
  same ceiling a second time and throws if it is crossed.
- **Returned on every exit path.** Chunks go back to the pool in `Dispose`, called from the same
  `finally` in `ForwardRequestAsync` that restores `HttpRequest.Body` — so they are returned on
  success, on refusal, on client disconnect, on timeout and on exception. `Dispose` is idempotent,
  because returning one array to the pool twice would hand the same buffer to two concurrent
  requests, and the symptom would be one visitor's upload appearing in another visitor's evidence.
- **Only for multipart.** A request that fails any of the four conditions above never allocates a
  chunk.

The buffer is chunked rather than one right-sized array because `ArrayPool<byte>.Shared` rounds
rentals up to a power-of-two bucket: renting 6 MiB returns an 8 MiB array, wasting a third of it and
parking a large-object-heap allocation per concurrent request. A 64 KiB chunk is returned exactly
and sits below the 85,000-byte large-object-heap threshold, and chunks grow without copying — which
matters because the attacker-controlled case is precisely the chunked body with no declared length.

### Two phases, and why the split matters

The pipeline drains the whole bounded body first, then parses the buffer. That split is what lets
every limit breach be a finding while Monitor keeps its promise to forward the request intact: once
the drain has completed the body is complete no matter what the parser then decides, because parsing
never touches the network. Only a drain-phase timeout can leave a partial body, and that is the one
case that cannot end in a forward.

## What is parsed, and what is sampled

`MultipartInspectionReader` walks the buffered body with `MultipartReader` and reduces each part to
bounded metadata. It reads each file part twice over: at most `SampleBytes` into a pooled scratch
array, copied out into a right-sized private array; then the remainder into a fixed 8 KiB scratch
buffer that is overwritten and discarded. The second pass exists only so the reported byte count is
exact — the gateway learns how large an upload was without ever holding it.

| Part shape | Treated as | Counted | Sampled | Inspected |
| --- | --- | --- | --- | --- |
| No `filename` and no `filename*` parameter | Form field | Against `MaximumFieldCount` | **No** | No |
| `filename=""` **and** a zero-byte body | Unselected `<input type="file">` | As a field | No | No |
| `filename=""` with a non-empty body | File | Against `MaximumFileCount` | Yes | Yes |
| Any other `filename` or `filename*` | File | Against `MaximumFileCount` | Yes | Yes |

Three of those rows prevent a default that ships broken:

- **Field parts are never sampled.** Sampling them would make `PHP-CONTENT-001` fire on every
  WordPress post body, theme-editor save or page-builder widget that contains a code snippet.
- **`filename=""` over an empty body is an unselected file input.** Browsers send exactly that for
  every empty file input on a submitted form, and PHP records `UPLOAD_ERR_NO_FILE`. Without this
  rule, `FILE-NAME-001` would score 60 for `emptyAfterNormalization` on routine WordPress admin
  traffic — a false positive on the first day of real use.
- **Both `filename` and `filename*` are read, and each is inspected.** `Content-Disposition` can
  carry both and they need not agree. ASP.NET Core's own `MultipartSection.AsFileSection()` prefers
  `filename*`; PHP's multipart handler reads only `filename`. So `filename*=UTF-8''photo.jpg`
  alongside `filename="shell.php"` is a request that is deliberately two files at once. When the two
  disagree the reader emits **both** names, sharing one sample, so the more severe result wins and
  the parser differential is closed rather than picked a side of. `AsFileSection()` is not used, for
  the same reason.

A part whose `Content-Disposition` is absent, or which carries **two** `filename` parameters, is
`Malformed` and stops the read. This parser takes the first such parameter and PHP's takes the last,
so the two would inspect and write different names.

Metadata is capped independently of the sample: file names at 1024 characters, field names at 1024,
the part's declared `Content-Type` at 256, and part headers at `MaximumPartHeaderBytes` across at
most 16 headers. A file name over its cap is itself a limit breach rather than a silent truncation —
chopping the tail of `aaaa….php` removes the `.php` and converts a detection into a miss.

## Limits

Every value below is bound from `Gateway:Multipart`. Configuration may **lower** a ceiling and never
raise it. The ceilings are enforced twice on purpose: `GatewayConfigurationValidator` throws at
startup, so an operator who asks for something the gateway will not do is told rather than silently
overridden; and `MultipartInspectionReader` clamps again at the point of use, so an options object
constructed directly in code cannot lift a ceiling by skipping the validator.

| Setting | Default | Allowed range | What it bounds |
| --- | ---: | ---: | --- |
| `Enabled` | `true` | `true` / `false` | Whether any body is buffered or any rule runs on live traffic |
| `MaximumFileCount` | 20 | 1 to 100 | File parts inspected before the read stops |
| `MaximumFieldCount` | 200 | 1 to 1000 | Non-file parts counted before the read stops |
| `MaximumPartHeaderBytes` | 16 KiB (`16384`) | 1 to 32 KiB (`32768`) | `MultipartReader.HeadersLengthLimit` |
| `SampleBytes` | 4096 | **512** to 64 KiB (`65536`) | Leading bytes kept per file for the content rules |
| `ReadTimeoutSeconds` | 30 | 1 to 120 | Deadline covering the drain **and** the parse |

Three further limits are fixed in code rather than configured: a boundary is 1 to 70 characters, a
part may carry at most 16 headers, and a file name is capped at 1024 characters.

> [!WARNING]
> `SampleBytes` has a floor of **512**, not 1. Below 512 bytes the text-versus-binary classification
> degrades and the `%PDF-` tolerance disappears, so `FILE-TYPE-001` and `PHP-CONTENT-002` would
> begin deciding from samples too short to decide from. Without the floor, a number that reads like
> a performance knob would quietly disable two rules while the configuration still said
> `"Enabled": true`.

### What this costs in memory

This is a real regression against the pre-M2 gateway, which held no per-request body memory at all.
At the defaults a multipart request holds roughly **6.15 MiB** for up to 30 seconds — at most
97 × 64 KiB chunks, plus 20 × 4 KiB samples, plus 12 KiB of scratch. At the worst legally
configurable values, with `MaximumRequestBytes` at its 64 MiB ceiling and 100 files at 64 KiB
samples, it is roughly **70.3 MiB** per request.

Nothing bounds the number of concurrent buffered requests today.
`KestrelServerLimits.MaxConcurrentConnections` defaults to unlimited and the gateway sets only
`MaxRequestBodySize`. Because `ReadTimeoutSeconds` caps how long each request holds its buffer,
sustaining a given quantity of pinned memory costs an attacker a proportional — and modest — upload
rate. The levers that exist today are:

- `Gateway:MaximumRequestBytes` divides the worst case directly. Lowering it to 2 MiB cuts the
  exposure by roughly two thirds.
- `Gateway:Multipart:ReadTimeoutSeconds` shortens the hold and raises the required attacker
  bandwidth proportionally.
- `Kestrel:Limits:MaxConcurrentConnections` as the blunt instrument. It is **not** exposed through
  `GatewayOptions` and must be set in the Kestrel configuration directly.

An explicit bound on concurrent buffered inspections is M3 work. Until it lands, the loopback-only
restriction is not only a statement about project maturity — it is also the only thing bounding this
memory.

## Boundaries

A boundary is accepted only in a form the gateway and the backend cannot disagree about. All five
conditions must hold:

1. Exactly **one** `Content-Type` header line. Kestrel does not reject duplicates and
   `HttpRequest.ContentType` joins them with `", "`. Two `Content-Type` lines is a classic
   parser-differential probe: if WPShield parses one value while IIS, ARR or PHP parses the other,
   WPShield inspected a different request than the one that executes.
2. Media type exactly `multipart/form-data`, ordinal case-insensitive. Other `multipart/*` subtypes
   are out of scope because PHP populates `$_FILES` only for `form-data`.
3. A `boundary` parameter, dequoted — RFC 2046 requires quoting when a boundary contains a space, so
   dequoting is not optional.
4. 1 to 70 characters after dequoting.
5. RFC 2046 `bchars` only, with a space forbidden in the final position. This is the check that
   keeps CR, LF, `"`, `;` and `\` out of the parser.

Anything else, **when the request declared `multipart/form-data`**, is `Malformed`.

**False positives.** RFC 2046 caps a boundary at 70 characters, but Kestrel's own
`FormOptions.MultipartBoundaryLengthLimit` defaults to 128 and PHP is likely to accept the longer
form too. A bespoke API client with an unusual boundary generator producing 71 to 128 characters is
therefore refused by WPShield and accepted by everything around it. That band is this rule's entire
false-positive surface. Monitor mode logs it at Warning with the observed value before Block mode
can turn it into a refusal.

## How findings across several files become one decision

`InspectionEngine.InspectAsync` runs every registered rule against one file and sums the findings,
capping the total at 100. The gateway then combines the per-file results:

- **Score is the maximum across files, and is used for logging only.** Summing across files would
  let twenty benign files at 30 each reach 600 and block a request in which nothing is wrong — and
  `FILE-NAME-001` scores 60 and fires on the full-local-path names some legacy clients send, so
  three of those would cross the block threshold on their own. Maximum also gives "one file at 90
  blocks regardless of what accompanies it" for free, and it denies the dilution attack in the other
  direction.
- **Action is the most severe `RecommendedAction` across files, read straight from the engine and
  never re-derived from the score.** The engine already applies the thresholds *and* the
  Monitor-to-Observe downgrade. A second implementation in the gateway is exactly where a future
  edit forgets the downgrade and Monitor silently starts blocking.

Exceeding a limit, or failing to parse, is **itself** a finding, emitted under the gateway
pseudo-rule identifier `GATEWAY-MULTIPART-001`. If "the reader gave up" meant "forward it", an
attacker could prefix a payload with twenty-one dummy files and buy an uninspected forward for the
twenty-second. A reader test hides a dangerous file behind the file limit and asserts it is never
inspected, and two integration tests take the same body all the way through the gateway: Block
answers 415 with `reason: limit_exceeded` and never contacts the backend, while Monitor forwards the
body byte for byte and logs the limit at Warning.

## What each mode does

| Situation | `Disabled` | `Monitor` (default) | `Block` |
| --- | --- | --- | --- |
| Not multipart, or `Enabled: false` | Forward, unbuffered | Forward, unbuffered | Forward, unbuffered |
| Multipart, no finding | Forward, unbuffered | Forward from buffer | Forward from buffer |
| Multipart, score at or above `ObserveThreshold` | Forward, unbuffered | Forward, log at Warning as `Observe` | Forward, log at Warning |
| Multipart, score at or above `BlockThreshold` | Forward, unbuffered | Forward, log at Warning as `Observe` | **403** `upload_blocked` |
| Body could not be fully inspected: `Malformed`, `LimitExceeded`, or a parse-phase timeout | Forward, unbuffered | Forward intact, log at Warning | **415** `multipart_not_inspectable` |
| Body did not fully arrive within `ReadTimeoutSeconds` | Forward, unbuffered | **408** `request_timeout` | **408** `request_timeout` |
| Body exceeded `Gateway:MaximumRequestBytes` | **413** | **413** | **413** |
| Client disconnected mid-upload | Nothing written; logged at Information | Nothing written; logged at Information | Nothing written; logged at Information |

The 408 applies in Monitor too, and that is deliberate. Monitor's promise is that WPShield never
blocks on a *finding*, and a half-arrived body is not a finding — it is a request the client failed
to deliver. Forwarding what arrived would send WordPress a body shorter than its declared
`Content-Length`, producing a corrupt upload and a backend error the operator cannot attribute to
WPShield. The 413 already set that precedent: absolute resource controls apply in all three modes.

A client disconnect writes nothing, because the connection is already gone, and logs at Information
rather than Error. A visitor closing a tab mid-upload is ordinary; `Error` in this component should
mean the gateway is broken.

## Responses

WPShield now generates a response of its own in seven situations: the four already documented —
`421` for an unknown host, `413` for an oversized body, `502` for an unreachable backend, and `404`
for a health probe that is not permitted — plus the three that are new in M2.

```json
{
  "error": "upload_blocked",
  "requestId": "correlation-id",
  "ruleIds": ["FILE-TYPE-001", "PHP-CONTENT-001", "WP-UPLOAD-001"]
}
```

```json
{
  "error": "multipart_not_inspectable",
  "requestId": "correlation-id",
  "reason": "malformed",
  "ruleIds": ["GATEWAY-MULTIPART-001"]
}
```

```json
{
  "error": "request_timeout",
  "requestId": "correlation-id"
}
```

`reason` is `malformed` when the body is not valid multipart or the boundary was refused, and
`limit_exceeded` when a file, field, header or name limit stopped the read — including a deadline
reached while parsing an already-buffered body. `ruleIds` is sorted, distinct and capped at 16.

**Why the rule identifiers are disclosed and the score is not.** WPShield is open source, and the
complete rule catalogue — identifiers, scores and matching logic — is already published in this
repository's [README](../../README.md) and in [upload rules](m2-upload-rules.md). Withholding the
identifiers protects nothing an attacker cannot read, while the cost of withholding falls entirely
on the legitimate side: an opaque 403 gives a site owner no path from the browser to the cause, and
"it blocked my file and won't say why" is how a security tool gets switched off. The score is the
opposite case. A binary allow/deny forces a blind search, but a numeric score turns evasion into
hill-climbing, because every mutation reports how much closer it got. Disclose what is published;
withhold what is derived. Should WPShield ever gain non-public rule packages, that trade has to be
revisited for those rules specifically.

Refusal bodies therefore never carry the raw or normalized file name, the field name, the sample,
the evidence, the site identifier, the destination, the score or the thresholds. No `Retry-After` is
sent either: it would imply the refusal is transient and invite a retry loop against a decision that
will not change.

Every response WPShield generates now carries `X-WPShield-Request-ID`, `X-Content-Type-Options:
nosniff` and `Cache-Control: no-store`. That is a fix rather than a restatement.
`HttpResponse.Clear()` clears headers as well as the status code, so the previous `413` and `502`
writers erased both custom headers, contradicting the documented promise that every response carries
them. The `421` path never called `Clear()`, which is why the inconsistency survived — the
difference was invisible unless you compared two failure responses side by side.

## What the logs record

One event per file **with findings**, not one per finding: a request at the absolute ceilings would
otherwise emit 100 files × 8 rules = 800 lines. Each carries the request identifier, the site
identifier, the method, the path without its query string, the gateway-assigned `PartIndex`, the
**normalized** name, the score, the action, the rule identifiers and the evidence.

One summary event per inspected request records the file and field counts, the read status, the
score, the action, the rule identifiers, the buffered byte count, and whether the request was
forwarded or refused — plus `WouldBlock`, which answers "what happens if I turn Block on for this
site?" from logs the operator already has. That is the entire point of running Monitor first.

Nothing in either line is attacker-supplied. The raw file name, the field name, the sample and every
header value are absent by construction: a raw name can carry control characters, ANSI escapes and
newlines straight into a log file or a terminal, which is why `NormalizedFileName` exists. Two
integration tests assert that neither the logs nor the refusal body contain a raw name, a sample, a
query string or a header value.

## Configuration

```json
{
  "Gateway": {
    "Urls": ["http://127.0.0.1:10000"],
    "AllowRemoteHealthChecks": false,
    "ActivityTimeoutSeconds": 100,
    "MaximumRequestBytes": 6291456,
    "Multipart": {
      "Enabled": true,
      "MaximumFileCount": 20,
      "MaximumFieldCount": 200,
      "MaximumPartHeaderBytes": 16384,
      "SampleBytes": 4096,
      "ReadTimeoutSeconds": 30
    }
  },
  "Sites": [
    {
      "Id": "wordpress-one",
      "Hosts": ["wordpress-one.example", "www.wordpress-one.example"],
      "Destination": "http://127.0.0.1:8081",
      "Mode": "Monitor",
      "ObserveThreshold": 30,
      "BlockThreshold": 80
    }
  ]
}
```

An out-of-range value prevents startup rather than being clamped, with a message naming the setting
and its range:

```text
Gateway:Multipart:MaximumFileCount must be between 1 and 100.
Gateway:Multipart:MaximumFieldCount must be between 1 and 1000.
Gateway:Multipart:MaximumPartHeaderBytes must be between 1 and 32768.
Gateway:Multipart:SampleBytes must be between 512 and 65536.
Gateway:Multipart:ReadTimeoutSeconds must be between 1 and 120.
```

The gateway prints the bounds it will actually enforce on every start, and says so loudly when
inspection is off:

```text
info: WPShield.Gateway.Configuration
      Multipart upload inspection enabled. MaximumRequestBytes=6291456 MaximumFileCount=20 MaximumFieldCount=200 MaximumPartHeaderBytes=16384 SampleBytes=4096 ReadTimeoutSeconds=30
warn: WPShield.Gateway.Configuration
      Multipart upload inspection is DISABLED by configuration. No upload rule will run on live traffic.
```

`Gateway:Multipart` is a JSON object rather than an array, so the element-by-element array merge
described in [operator configuration](operator-configuration.md) does not apply to it: an overlay
that sets one multipart value leaves the rest at their shipped defaults.

> [!IMPORTANT]
> Configuration is not hot-reloaded. These options are validated once at startup and captured for
> the lifetime of the process. Restart the gateway to apply a change, and read the line above to
> confirm it took effect.

## Operational traps

Three conditions are most likely to be met by legitimate traffic. Each logs at Warning with the
observed value in Monitor mode, so an operator sees it before Block can turn it into a refusal.

- **A slow client on a large upload gets a 408.** Thirty seconds against a 6 MiB body implies a
  sustained floor of roughly 205 KiB/s. A mobile or satellite client uploading a full-size image can
  fall below it. Raising `ReadTimeoutSeconds` to 120 drops the floor to about 51 KiB/s. This is the
  condition most likely to generate support traffic.
- **A page builder or form plugin can exceed 200 fields.** Most large WordPress admin forms are
  `application/x-www-form-urlencoded` and never reach this code, but a large form submitted *with* a
  file attached arrives as multipart. `MaximumFieldCount` goes to 1000.
- **A boundary of 71 to 128 characters is refused.** See [Boundaries](#boundaries).

Each rule's own false positives are documented in [upload rules](m2-upload-rules.md). Stay in
Monitor mode until you have reviewed your own site's upload traffic.

## What M2 still does not do

Stated plainly, because a status line reading "multipart inspection: available" invites a reader to
assume more than is true:

1. **No non-multipart body is inspected at all.** `application/x-www-form-urlencoded`, JSON,
   XML-RPC and `application/octet-stream` PUTs stream through untouched.
2. **`multipart/*` subtypes other than `form-data` stream through**, because PHP populates `$_FILES`
   only for `form-data`.
3. **Form field parts are never inspected**, by design — see the reasoning above.
4. **Archive contents are never opened.** A `.zip` plugin or theme upload containing a webshell is
   not detected, and plugin installation is a genuine WordPress upload path. This is the largest
   single gap, and no milestone is assigned to it yet.
5. **Only the leading `SampleBytes` of each file are examined.** A marker placed past the sample
   window is not seen, and neither is the tail of a large-carrier polyglot.
6. **Nothing bounds concurrent buffered inspections.** See [What this costs in
   memory](#what-this-costs-in-memory).
7. **Only requests are inspected.** Response bodies are never read.

## Rollback

Set `Gateway:Multipart:Enabled` to `false` and restart the gateway. Every request then streams
through as it did before M2: no body is buffered, no sample is taken, and no upload rule runs on
live traffic. The startup warning above will say so on every start. This is an incident escape
hatch, not a tuning knob — a gateway with inspection disabled is a reverse proxy with a size limit.

Do not alter public IIS bindings, DNS, certificates, firewall rules, or Windows services.
