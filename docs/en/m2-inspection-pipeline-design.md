# M2 — Multipart inspection pipeline design

> **Audience.** The agents implementing M2. This is an internal design note, not operator
> documentation. The operator-facing English and Spanish pages are the documentation agent's
> work; §10 and the handoff appendix list exactly what they have to say. There is deliberately
> no `docs/es` counterpart to this file — it describes code that does not exist yet, and a
> translated design note goes stale the moment the first implementer disagrees with it.

The gateway is loopback-only and `Monitor` remains the default protection mode. Nothing here
changes either.

## Why this document exists

`GatewayApplication.ForwardRequestAsync` today resolves the site, checks `Content-Length`, wraps
the body in `RequestBodyLimitStream` and calls `forwarder.SendAsync`. `WPShield.Gateway.csproj`
does not reference `WPShield.Rules.WordPress` at all. The six shipped rules run only from
`src/WPShield.Service/Program.cs`, which is a console demonstration against a hard-coded synthetic
name. **No rule has ever evaluated a real request.** M2 closes that, and this note fixes every
decision the closing requires so that three agents working in parallel produce one pipeline rather
than three.

## Decision summary

| # | Question | Decision |
| --- | --- | --- |
| 1 | Buffering mechanism | Chunked pooled buffer: `List<byte[]>` of 64 KiB arrays from `ArrayPool<byte>.Shared`, exposed as a seekable `Stream`. No disk API anywhere in the type. |
| 2 | Where inspection sits | Inline in `ForwardRequestAsync`, delegated to `UploadInspectionStage`. Not middleware. |
| 3 | Boundary extraction | Exactly one `Content-Type` header, media type exactly `multipart/form-data`, boundary dequoted, 1–70 characters, RFC 2046 `bchars` only. Anything else is `Malformed` — fail closed. |
| 4 | Is a limit hit a finding? | **Yes.** Every non-`Complete` status is a finding. An attacker cannot buy an unconditional forward by exhausting the reader. |
| 5 | Aggregation across files | **Max, never sum.** Score is the max across files; action is the most severe across files. Findings tagged with `partIndex`. |
| 6 | Action semantics | The engine owns the Block→Observe downgrade. The gateway reads `RecommendedAction` and never re-derives it from the score. |
| 7 | Block responses | 403 for a content decision, 415 for an uninspectable body, 408 for a timeout, 413 unchanged. Rule IDs **are** disclosed; score, thresholds, evidence and names are **not**. |
| 8 | Timeouts | A linked `CancellationTokenSource` with `CancelAfter`, independent of `ForwarderRequestConfig.ActivityTimeout`. |
| 9 | DoS | ~6.15 MiB per concurrent buffered request at defaults; nothing bounds concurrency. This is a **real regression**; M3 must add a bound. |
| 10 | Scope | Multipart file parts only. Everything else in §10. |

---

## 1. Buffering

### 1.1 The mechanism

Create `src/WPShield.Gateway/PooledRequestBuffer.cs`:

```
internal sealed class PooledRequestBuffer : Stream
    ChunkBytes = 64 * 1024                 // 65,536
    List<byte[]> _chunks                   // each rented from ArrayPool<byte>.Shared
    long _length, _position
    CanRead => true, CanSeek => true, CanWrite => false
```

The body is drained into a list of fixed 64 KiB arrays rented from `ArrayPool<byte>.Shared`.
`Read`/`Seek` are index arithmetic over the chunk list. `Dispose` returns every chunk and clears
the list.

**Why chunks and not one right-sized array.** Two measurements taken on the .NET 10.0.10 runtime in
this repository:

- `ArrayPool<byte>.Shared.Rent(6 * 1024 * 1024)` returns an array of **8,388,608** bytes. The pool
  rounds to power-of-two buckets, so the obvious "rent `MaximumRequestBytes`" design wastes 33% and
  parks an 8 MiB array on the large object heap for every concurrent multipart request. It is
  genuinely pooled — a second `Rent` after `Return` hands back the same instance — so the LOH array
  is long-lived rather than churning, but it is 8 MiB per concurrent request regardless of whether
  the upload was 8 MiB or 8 KiB.
- `Rent(65536)` returns exactly 65,536 bytes. 64 KiB is a bucket size, so there is no rounding
  waste, and it is below the 85,000-byte LOH threshold, so the pipeline never allocates on the LOH
  at all.

The chunked form also costs nothing to grow. A body with no `Content-Length` — a chunked upload, the
case an attacker controls — needs a buffer that can grow without knowing the final size. A
single-array design must either rent the maximum up front (8 MiB for a 40 KiB upload) or copy on
every doubling. Appending a chunk does neither.

Memory is therefore `ceil(bytes / 65536) * 65536`. A typical 180 KiB WordPress media upload costs
192 KiB. Only an actual 6 MiB upload costs 6 MiB.

### 1.2 The proof that it cannot reach disk

`PooledRequestBuffer` references `System.Buffers.ArrayPool<byte>` and nothing else. It contains no
`FileStream`, no `File`, no `Path`, no `Directory`, no `MemoryMappedFile`, no temp-path lookup. There
is no code path to disk to prove unreachable, because there is no code path to disk.

That is the whole reason for rejecting `Microsoft.AspNetCore.WebUtilities.FileBufferingReadStream`.
It is the obvious choice and it would work — it spills to disk only above its memory threshold, and
setting the threshold above `GatewayOptions.AbsoluteMaximumRequestBytes` would make the spill
unreachable. But that safety is *configurational*: it survives only as long as nobody edits the
threshold, nobody adds a second construction site with a different threshold, and the framework
never changes when it decides to spill. AGENTS.md says "Do not store suspicious uploads on disk"
without qualification, and a guarantee that a future contributor can undo by changing one number is
not the same guarantee. A type with no disk API cannot be misconfigured into writing one.

`System.IO.MemoryStream` with a pooled backing array was the other candidate. Rejected for the
growth behaviour in §1.1, not for safety — it is equally disk-free.

**Implementers must not add a disk fallback for large bodies.** If a body does not fit, the answer is
413, not a temp file.

### 1.3 Renting, returning, and every exit path

The buffer's lifetime nests inside the existing `try`/`finally` in `ForwardRequestAsync` that
restores `context.Request.Body`. That `finally` already runs on success, on forwarder failure, on
cancellation and on exception; putting the disposal in the same block means there is one place to
audit rather than five.

```csharp
PooledRequestBuffer? buffer = null;
var originalBody = context.Request.Body;
try
{
    context.Request.Body = new RequestBodyLimitStream(originalBody, gatewayOptions.MaximumRequestBytes);
    // ... inspection stage may assign `buffer` and swap it in ...
    error = await forwarder.SendAsync(...);
}
finally
{
    context.Request.Body = originalBody;
    buffer?.Dispose();
}
```

`Dispose` must be idempotent and must null out `_chunks` after returning them, so a double dispose
cannot return the same array twice — returning one array to the pool twice hands the same buffer to
two concurrent requests, which is a cross-request data leak, not merely a bug. Guard it with a
`_disposed` flag.

Do not use `ArrayPool.Return(clearArray: true)`. Clearing 6 MiB on every request is real CPU for no
security gain: the buffer is fully overwritten before it is read, because `_length` bounds every read
and `_length` only advances as bytes are written. State that reasoning in the code comment, because
"pooled buffer, no clear" looks like an oversight to a reviewer who has not thought it through.

### 1.4 The order change, and why it matters

Today `RequestBodyLimitStream` is installed *after* the site checks and immediately before
`SendAsync`. It must move **before** the inspection stage, so that the drain into the buffer is
itself bounded. Without that, a chunked body with no `Content-Length` would be buffered without a
limit — the exact hole `RequestBodyLimitStream` exists to close.

### 1.5 When the body turns out to be larger than the limit mid-read

`RequestBodyLimitStream.RecordRead` throws `RequestBodyTooLargeException` the moment `_bytesRead`
crosses `maximumBytes`. Note the deliberate off-by-one in `GetAllowedReadSize`: it permits reading
`remaining + 1` bytes so that overflow is *detectable*. The buffer must therefore tolerate holding
`MaximumRequestBytes + 1` bytes — size the chunk cap as `ceil((MaximumRequestBytes + 1) / ChunkBytes)`,
which is 97 chunks at the 6 MiB default.

Give `PooledRequestBuffer` its own independent ceiling that throws `RequestBodyTooLargeException`
if a write would exceed `MaximumRequestBytes + 1`. It is redundant today because
`RequestBodyLimitStream` already guards it. Keep it anyway: it makes the buffer bounded as a
standalone type, so a future caller that forgets the wrapper cannot make it unbounded.

Catch `RequestBodyTooLargeException` around the drain and return the existing 413 through
`WriteRequestTooLargeAsync`. **This is a strict improvement over today.** The current streamed-413
path lets a bounded prefix of the body reach the backend before overflow is detected — the
"Streaming limitation" section of `docs/en/m2-request-limits.md` documents exactly that. On the
buffered multipart path nothing is forwarded at all, because the forwarder has not been called yet.
The documentation agent must narrow that limitation to non-multipart bodies.

The existing post-forward path in `IsRequestTooLarge` stays exactly as it is. It still covers every
non-multipart request, which is most traffic.

### 1.6 When buffering happens

All three must hold, checked in this order because each is cheaper than the next:

1. `multipartOptions.Enabled` is `true`.
2. `site.Mode != ProtectionMode.Disabled`.
3. `MultipartInspectionReader.TryGetBoundary(context.Request, multipartOptions, out var boundary)`
   returns `true`, **or** the request declares `multipart/form-data` and boundary extraction failed
   (§3 — that case is a finding, not a pass).

Plus one guard that is not about policy: skip if `context.Request.ContentLength == 0`. A body of
declared length zero has nothing to inspect, and buffering it would hand `MultipartReader` an empty
stream that it correctly reports as malformed — a 415 in Block mode for a request that is merely
odd. When `ContentLength` is `null` (chunked) the size is unknown until drained; if the drain yields
zero bytes, treat it as no body, skip inspection and forward.

Everything else keeps streaming exactly as it does today: no buffer is rented, no chunk is
allocated, no extra byte is copied. Ordinary WordPress page traffic — the overwhelming majority —
must not start paying for uploads it does not contain, and it does not.

Do **not** restrict inspection by HTTP method. It is tempting to limit it to POST, since that is what
PHP's `rfc1867` multipart handler runs for, but a method allowlist is a method-shaped bypass and it
buys nothing: the `ContentLength == 0` guard already skips the bodiless methods that motivated the
idea.

---

## 2. Where the inspection step sits

**Inline in `ForwardRequestAsync`, delegated to a singleton `UploadInspectionStage`. Not
middleware.**

Three reasons, in order of weight:

1. **The site is resolved inside `ForwardRequestAsync`.** Inspection needs `SiteOptions` for
   `Mode`, `ObserveThreshold` and `BlockThreshold`. A middleware would have to either call
   `SiteResolver.Resolve` a second time or stash the result in `HttpContext.Items`. Two places that
   each decide which site a request belongs to is precisely how a multi-tenant gateway ends up
   applying site A's policy to site B's traffic, and "Preserve multi-site isolation" is an AGENTS.md
   invariant.
2. **The body swap and its `finally` already live there.** The pooled chunks must be returned on
   the same exit paths that restore `context.Request.Body`. Splitting the two across a middleware
   boundary means the buffer outlives the scope that owns it, and the disconnect path leaks.
3. **`MapFallback` already excludes the health endpoints.** `/_wpshield/health/live`, `/ready` and
   the `/_wpshield/health/{**path}` catch-all are mapped before the fallback, so they never reach
   `ForwardRequestAsync`. A middleware registered with `app.Use` runs for all of them and would have
   to re-exclude what routing already excluded.

### 2.1 Code shape

`ForwardRequestAsync` is already about 100 lines. Do not inline the pipeline into it. Add
`src/WPShield.Gateway/UploadInspectionStage.cs`:

```csharp
internal sealed class UploadInspectionStage(
    InspectionEngine engine,
    MultipartInspectionReader reader)
{
    public async ValueTask<UploadInspectionDecision> EvaluateAsync(
        HttpContext context,
        SiteOptions site,
        GatewayOptions gatewayOptions,
        MultipartInspectionOptions multipartOptions,
        ILogger logger,
        CancellationToken cancellationToken);
}

internal sealed record UploadInspectionDecision(
    PooledRequestBuffer? Body,        // non-null when the request was buffered; already rewound to 0
    GatewayRejection? Rejection,      // non-null when the gateway must answer instead of forwarding
    InspectionAction Action,          // most severe across files; Allow when nothing was inspected
    int Score,                        // max across files, for logging only
    IReadOnlyList<string> RuleIds);   // sorted, distinct, capped at 16

internal sealed record GatewayRejection(int StatusCode, string Error, string? Reason);
```

The stage returns; it never writes the response itself. Response writing stays in
`ForwardRequestAsync` beside the existing 421/413/502 writers, so every response the gateway
generates is produced in one place and can be reviewed as a set.

The call site, between the `Content-Length` check and the forward:

```csharp
// ... existing unknown-host 421 ...
// ... existing declared-Content-Length 413 ...

PooledRequestBuffer? buffer = null;
var originalBody = context.Request.Body;
try
{
    context.Request.Body = new RequestBodyLimitStream(originalBody, gatewayOptions.MaximumRequestBytes);

    var decision = await inspectionStage.EvaluateAsync(
        context, site, gatewayOptions, multipartOptions, logger, context.RequestAborted);
    buffer = decision.Body;

    if (decision.Rejection is { } rejection)
    {
        await WriteGatewayErrorAsync(context, rejection);
        return;
    }

    if (buffer is not null)
    {
        buffer.Position = 0;
        context.Request.Body = buffer;
    }

    error = await forwarder.SendAsync(context, /* unchanged */ ...);
}
catch (RequestBodyTooLargeException)
{
    logger.LogWarning(/* existing message shape */);
    if (!context.Response.HasStarted) await WriteRequestTooLargeAsync(context);
    return;
}
catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
{
    logger.LogInformation(
        "Client disconnected during multipart inspection. RequestId={RequestId} SiteId={SiteId} BufferedBytes={BufferedBytes}",
        context.TraceIdentifier, site.Id, buffer?.Length ?? 0);
    return;
}
finally
{
    context.Request.Body = originalBody;
    buffer?.Dispose();
}

// ... existing ForwarderError handling, unchanged ...
```

Do not set `Content-Length` on the forwarded request and do not touch any request header. YARP's
`StreamCopyHttpContent` reports no computed length and copies the inbound framing, so a chunked
request stays chunked and a length-delimited request keeps its declared length. The forwarded
request must be byte-identical to what arrived, framing included; anything else is a
parser-differential of our own making.

### 2.2 Wiring

`src/WPShield.Gateway/WPShield.Gateway.csproj` gains:

```xml
<ProjectReference Include="../WPShield.Rules.WordPress/WPShield.Rules.WordPress.csproj" />
```

The Gateway may reference the Rules project. The Rules project may never reference the Gateway, and
the Linux CI leg that builds `Abstractions` + `Core` + `Rules.WordPress` alone is what keeps that
falsifiable.

No `PackageReference` is needed. `Microsoft.AspNetCore.WebUtilities.dll` and
`Microsoft.Net.Http.Headers.dll` both ship in the `Microsoft.AspNetCore.App` shared framework
(verified against 10.0.10), so `MultipartReader`, `MediaTypeHeaderValue` and `HeaderUtilities` are
available to a `Microsoft.NET.Sdk.Web` project with no change to `Directory.Packages.props`.

In `GatewayApplication.Build`:

```csharp
var multipartOptions = builder.Configuration.GetSection("Gateway:Multipart")
    .Get<MultipartInspectionOptions>() ?? new MultipartInspectionOptions();
GatewayConfigurationValidator.Validate(gatewayOptions, multipartOptions, sites);

builder.Services.Configure<MultipartInspectionOptions>(builder.Configuration.GetSection("Gateway:Multipart"));

builder.Services.AddSingleton<IInspectionRule, ExecutableUploadExtensionRule>();
builder.Services.AddSingleton<IInspectionRule, DisguisedExtensionRule>();
builder.Services.AddSingleton<IInspectionRule, IisExecutableUploadRule>();
builder.Services.AddSingleton<IInspectionRule, IisConfigurationUploadRule>();
builder.Services.AddSingleton<IInspectionRule, UnsafeFileNameRule>();
builder.Services.AddSingleton<IInspectionRule, PhpContentInUploadRule>();
builder.Services.AddSingleton<IInspectionRule, FileTypeMismatchRule>();
builder.Services.AddSingleton<IInspectionRule, PhpPolyglotUploadRule>();
builder.Services.AddSingleton<InspectionEngine>();
builder.Services.AddSingleton<MultipartInspectionReader>();
builder.Services.AddSingleton<UploadInspectionStage>();
```

Singletons are correct: every shipped rule is stateless — none has a mutable instance field, and
`DangerousUploadExtensions` exposes `FrozenSet` — so they are safe to share across concurrent
requests. `InspectionEngine` copies its rules into an array in the constructor and holds no
per-request state.

`multipartOptions` is captured by the `ForwardRequestAsync` local function the same way
`gatewayOptions` already is, rather than injected. Same pattern, one fewer parameter.

### 2.3 Configuration validation

Add `ValidateMultipartInspection` to `GatewayConfigurationValidator` and a three-argument `Validate`
overload; keep the existing two-argument overload delegating with `new MultipartInspectionOptions()`
so `GatewayConfigurationValidatorTests` keeps compiling.

**Throw at startup, do not clamp.** The repository has both precedents —
`Gateway:MaximumRequestBytes` throws, `ActivityTimeoutSeconds` is silently `Math.Clamp`ed — and the
throwing one is right here. These are safety ceilings, and AGENTS.md says configuration must never
appear to do something it does not. An operator who sets `MaximumFileCount: 100000` and gets a
silent 100 has been told nothing.

Messages follow the existing shape exactly, so the README troubleshooting table stays uniform:

```
Gateway:Multipart:MaximumFileCount must be between 1 and 100.
Gateway:Multipart:MaximumFieldCount must be between 1 and 1000.
Gateway:Multipart:MaximumPartHeaderBytes must be between 1 and 32768.
Gateway:Multipart:SampleBytes must be between 512 and 65536.
Gateway:Multipart:ReadTimeoutSeconds must be between 1 and 120.
```

### 2.4 `appsettings.json`

```json
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
}
```

Ship every value explicitly even though each equals its `init` default. `Gateway:Multipart` is a
nested object, so the array-merge trap that `ValidateNoPartiallyAppliedOverlay` exists to catch does
not apply — but an operator reading `appsettings.json` to learn what they can tune should not have
to read C# to find out these settings exist.

---

## 3. Boundary extraction

```csharp
public static bool TryGetBoundary(HttpRequest request, MultipartInspectionOptions options, out string boundary);
```

Returns `true` only when **all** of the following hold. The caller separately needs to know whether
the request *declared* `multipart/form-data`, so pair it with a `DeclaresMultipartFormData(HttpRequest)`
helper; "declared but `TryGetBoundary` returned false" is the fail-closed case and must not be
confused with "not multipart at all".

1. **Exactly one `Content-Type` header line.** Read `request.Headers.ContentType` as `StringValues`
   and require `Count == 1`. Kestrel does not reject duplicate `Content-Type` headers, and
   `HttpRequest.ContentType` joins them with `", "`. Two `Content-Type` lines is a classic
   parser-differential probe: IIS, ARR and PHP need not agree on whether the first or the last one
   wins, and if WPShield parses one while the backend parses the other, WPShield is inspecting a
   different request than the one that gets executed. If any of the values parses as
   `multipart/form-data`, this is `Malformed`, not a pass.
2. **`MediaTypeHeaderValue.TryParse` succeeds** and `MediaType` equals `multipart/form-data`
   (ordinal, case-insensitive). Other `multipart/*` subtypes — `mixed`, `related`, `byteranges` —
   are **out of scope** and stream through: PHP's multipart handler populates `$_FILES` only for
   `multipart/form-data`, so those subtypes cannot become an upload through the path WPShield
   defends. Record it in §10 as a known gap rather than pretending it is covered.
3. **A `boundary` parameter is present.** Take `mediaType.Boundary` and dequote it with
   `HeaderUtilities.RemoveQuotes`. `MediaTypeHeaderValue.Boundary` returns the raw `StringSegment`
   including quotes; RFC 2046 requires quoting when the boundary contains a space, so dequoting is
   not optional.
4. **Length is 1 to 70 characters** after dequoting. RFC 2046 §5.1.1 caps a boundary at 70.
5. **Every character is in RFC 2046 `bchars`**: `A–Z a–z 0–9` and `' ( ) + _ , - . / : = ?` and
   space, with space not permitted in the final position. This is the check that matters most: it
   rejects CR, LF, `"`, `;` and `\` outright, so a boundary can never carry header-injection
   structure into `MultipartReader`.

Pass the dequoted value to `MultipartReader` **without** a leading `--`; `MultipartReader` prepends
the delimiter itself. Passing `--boundary` produces a reader that matches nothing and reports a
clean, empty, malformed-looking body — a silent false negative that is very hard to spot in review.

### 3.1 A malformed boundary fails closed

"Declares `multipart/form-data`, boundary unusable" produces `MultipartReadStatus.Malformed`, which
§4 makes a finding: Monitor logs and forwards, Block returns 415.

The alternative — forward anything we cannot parse — hands an attacker a one-line bypass. Send a
boundary of 200 characters, or with an embedded `;`, and WPShield waves the request through
uninspected while IIS and PHP parse it happily. A gateway that fails open on unparseable input is
not a gateway.

### 3.2 The false positive, stated honestly

Kestrel's own `FormOptions.MultipartBoundaryLengthLimit` defaults to **128**, not 70. So ASP.NET
Core, and very likely PHP, accept boundaries in the 71–128 range that WPShield will call malformed.
No mainstream HTTP client generates one — browsers emit boundaries well under 70 — but a bespoke
API client or an SDK with an unusual boundary generator could land in that window and receive a 415
once the site is in Block mode.

The mitigation is the one the project already relies on: `Monitor` is the default, the finding is
logged at Warning with the observed length, and an operator sees it before they enable Block. The
80-character band is where this rule's entire false-positive surface lives, and it should be named
in the operator documentation rather than discovered in production.

---

## 4. Limits

### 4.1 The table

| Limit | Default | Absolute ceiling | Enforced by | On hit |
| --- | ---: | ---: | --- | --- |
| `MaximumFileCount` | 20 | 100 | reader's own counter | stop reading, `LimitExceeded` |
| `MaximumFieldCount` | 200 | 1000 | reader's own counter | stop reading, `LimitExceeded` |
| Total part count | 220 (derived: files + fields) | 1100 | reader's own counter | stop reading, `LimitExceeded` |
| `MaximumPartHeaderBytes` | 16 KiB | 32 KiB | `MultipartReader.HeadersLengthLimit` | `InvalidDataException` → `Malformed` |
| Part header count | 16 | 16 | `MultipartReader.HeadersCountLimit` | `InvalidDataException` → `Malformed` |
| File name length | 1024 chars | 1024 chars | reader | truncate **and** `LimitExceeded` (§4.2) |
| `SampleBytes` | 4096 | 512 min, 64 KiB max | reader | truncate sample; **not** a limit hit |
| `ReadTimeoutSeconds` | 30 | 120 | linked `CancellationTokenSource` | `TimedOut` (§8) |
| Body bytes | 6 MiB | 64 MiB | `RequestBodyLimitStream` | `RequestBodyTooLargeException` → 413 |

The `SampleBytes` **floor of 512 is a cross-agent contract**, not a stylistic choice. The content
rules design note (`docs/en/m2-content-rules-design.md`) records that below 512 bytes the text-versus-binary
classification degrades and the `%PDF-` tolerance disappears, so `FILE-TYPE-001` and `PHP-CONTENT-002`
start deciding from samples too short to decide from. The contract's `MultipartInspectionOptions`
default of 4096 is comfortably above it; the validator enforces the floor so configuration cannot
quietly disable two rules by shrinking a number that looks like a performance knob.

`MultipartReader.HeadersCountLimit` is left at the framework default of 16 but **set explicitly**, so
the value is a decision in WPShield's source rather than an inherited accident that a framework
update can change. A legitimate file part carries two or three headers.

`MultipartReader.BodyLengthLimit` stays `null`. It bounds each individual section, and the source
stream is already bounded by `MaximumRequestBytes`; adding a per-part number buys no additional
guarantee and creates a second value to keep in sync. Say so in the code, because a reviewer will
ask.

`MultipartReader`'s buffer size stays at the default 4096. The reader needs the boundary to fit in
its buffer, and §3 caps the boundary at 70 characters, so 4 KiB is ample.

### 4.2 File name length

The raw `filename` parameter is already bounded by `MaximumPartHeaderBytes` — but 16 KiB is not a
file name, and `InspectionContext.NormalizedFile` recomputes `NormalizedFileName.Create` on every
access, so a 16 KiB name would be re-scanned once per rule per file.

Truncate the raw name at **1024 characters** before constructing `InspectedUpload`. The cap must stay
comfortably above `NormalizedFileName.MaximumSafeLength` (255) so that `UnsafeFileNameRule` can still
report `excessiveLength`.

**Truncation alone is not safe**, and this is the trap: chopping the tail of
`aaaa…aaaa.php` removes the `.php` and turns a detection into a miss. So an over-cap file name is
also a limit hit — set `LimitExceeded` on the outcome. Because §4.4 makes every limit hit a finding,
a name too long to inspect honestly can never be forwarded silently in Block mode.

### 4.3 What counts as a file, and what does not

This distinction decides both the counters and what gets inspected, and getting it wrong ships a
gateway that fires on ordinary traffic.

- **No `filename` parameter** → form field. Counts toward `MaximumFieldCount`. **Never sampled,
  never inspected.** This is not an optimisation, it is a correctness requirement:
  `PhpContentInUploadRule` matches `<?php` anywhere in the sample, and a WordPress post body, a
  theme editor save or an Elementor widget containing a code snippet legitimately contains that
  string. Sampling fields would make the rule fire on routine editorial traffic.
- **`filename` present but empty after dequoting, and the part body is 0 bytes** → an unselected
  `<input type="file">`. Browsers send exactly this for every empty file input on a submitted form,
  and PHP records it as `UPLOAD_ERR_NO_FILE` and writes nothing. Count it as a **field**, produce no
  `InspectedUpload`. Without this rule, `UnsafeFileNameRule` fires `emptyAfterNormalization` for 60
  points on ordinary WordPress admin form posts — a false positive on the first day of real traffic.
- **`filename` empty but the body is non-empty** → a file. Anomalous, and `UnsafeFileNameRule` should
  see it.
- **`filename` non-empty** → a file. Counts toward `MaximumFileCount`, sampled and inspected.

### 4.4 A limit hit is itself a finding

**Yes, unconditionally.** This is the most important decision in this document.

An attacker who prefixes their payload with 10,000 dummy parts makes the reader stop before it
reaches the payload. If "the reader gave up" meant "forward it", that attacker has a one-request,
zero-knowledge bypass of every rule WPShield ships. Every non-`Complete` status must therefore
constrain the outcome:

| `MultipartReadStatus` | Body complete? | Monitor | Block |
| --- | --- | --- | --- |
| `Complete` | yes | per findings | per findings |
| `LimitExceeded` | yes | forward, log Warning | **415** |
| `Malformed` | yes | forward, log Warning | **415** |
| `TimedOut` | **no** | **408** | **408** |

Two orthogonal axes, and keeping them separate is what makes this tractable:

- **"Is the body complete?"** decides whether forwarding is even possible. Only a drain-phase
  timeout leaves a partial buffer, and a partial body forwarded to WordPress is a corrupt upload and
  a confused backend, so it is 408 in every mode. That is a resource control, not an inspection
  finding, which is why it applies in Monitor too — exactly like the existing 413, which
  `docs/en/m2-request-limits.md` already documents as applying in all three modes.
- **"Did inspection complete?"** decides whether the request is a finding. Monitor never blocks on a
  finding; Block does.

This is why the pipeline is **two-phase**: drain the entire bounded body into the buffer first, then
parse the buffer. Parsing never touches the network, so `LimitExceeded` and `Malformed` always have a
complete body available and Monitor can forward it intact. Interleaving parse and network read would
make every parse failure also a partial-body failure, and Monitor could no longer honour its promise
to forward.

Emit these under the pseudo-rule ID **`GATEWAY-MULTIPART-001`** in logs and in the 415 response's
rule list, so the event is as explainable as a real finding. It is emitted by the Gateway, not by a
rule in `WPShield.Rules.WordPress`, and it does not participate in scoring — it is a policy outcome,
not a score contribution. M4 should promote it to a first-class inspection event.

### 4.5 Honest false positives from the count limits

`MaximumFileCount: 20` is generous. WordPress's media uploader posts one file per request to
`async-upload.php`; so do Elementor and every multi-file form plugin worth naming. Twenty is already
an order of magnitude above observed legitimate traffic.

`MaximumFieldCount: 200` is the one that can bite. Most large WordPress admin forms are
`application/x-www-form-urlencoded` and never reach this code, but a page builder or a form plugin
that posts a large form *with* a file attached arrives as multipart and can exceed 200 fields. The
operator's lever is `Gateway:Multipart:MaximumFieldCount` up to 1000, and Monitor mode surfaces the
Warning — with the observed count — before Block mode can turn it into a 415. Document the lever
next to the limit, not in a separate tuning page.

---

## 5. Aggregation across files

### 5.1 Max, never sum

`InspectionEngine.InspectAsync` already sums findings *within* one context and caps the total at 100.
Aggregation *across* files is a separate question, and the answer is **max**:

- Twenty benign files scoring 30 each would sum to 600 and block a request in which nothing is
  wrong. `FILE-NAME-001` scores 60 and fires on the full-local-path names some legacy clients send;
  three such files would sum past the block threshold on their own.
- One file scoring 90 must block regardless of what accompanies it. `max` gives that for free.

Score is a property of a file, not of a request. Summing across files means an attacker can dilute a
malicious file with benign ones, or — worse in practice — a benign bulk upload can cross a threshold
no individual file came close to.

### 5.2 Take the action, not the score

Call `engine.InspectAsync` once per `InspectedUpload`. Aggregate:

- `Score` = `Max(result.Score)` across results, **for logging only**.
- `Action` = the most severe `RecommendedAction` across results (`Block` > `Observe` > `Allow`).

Do **not** take the max score and re-derive the action from `site.BlockThreshold`. The engine already
applies the thresholds and already downgrades `Block` to `Observe` when the site is in Monitor mode:

```csharp
var action = score >= site.BlockThreshold
    ? site.Mode == ProtectionMode.Block ? InspectionAction.Block : InspectionAction.Observe
    : score >= site.ObserveThreshold ? InspectionAction.Observe : InspectionAction.Allow;
```

Re-deriving in the gateway duplicates that policy in a second place, and the second place is where a
future edit forgets the Monitor downgrade and Monitor silently starts blocking. Read
`RecommendedAction` and nothing else.

With zero files (a multipart request that carried only fields), `Action` is `Allow` and `Score` is 0.
The status policy from §4.4 still applies on top.

### 5.3 Tagging findings with their file

The gateway wraps each `RuleFinding` before logging, merging into its evidence:

- **`partIndex`** — the zero-based index of the file part within the request, as an invariant-culture
  string. This is the key that answers "which file was this about". It is a gateway-assigned integer,
  so it is safe by construction; it cannot carry attacker bytes.
- **`normalizedName`** — `context.NormalizedFile.BaseName`, added only when the rule did not already
  supply it. Four of the six shipped rules set it; `PhpContentInUploadRule` supplies no evidence at
  all, so a PHP-content finding would otherwise be untraceable to a file.

Merge into a **new** dictionary. Never mutate a rule's evidence: it belongs to the rule, some rules
pass `null`, and mutating a dictionary a rule might have cached is a cross-request hazard.

Both keys are camelCase, matching every existing evidence key (`normalizedName`,
`executableExtension`, `presentedExtension`, `extension`, `position`, `anomalies`).

**Never the raw name.** Evidence carries `NormalizedFileName.BaseName`, never `.Raw`. The raw name is
attacker-controlled and can carry control characters, ANSI escape sequences and newlines straight
into a log file, a terminal or a future dashboard. That is why `NormalizedFileName` exists and why
`UnsafeFileNameRule` reports anomaly *kinds* rather than the offending bytes.

**Never the field name either.** `InspectedUpload.FieldName` is equally attacker-controlled and is
not needed to identify the part — `partIndex` does that. Keep it out of evidence, out of logs and out
of responses.

### 5.4 Building each `InspectionContext`

```csharp
new InspectionContext(
    site.Id,
    context.Request.Host.Host,          // the same value passed to SiteResolver.Resolve
    context.Request.Method,
    context.Request.Path.Value ?? "/",  // path only — never the query string
    upload.FileName,                    // raw; rules use NormalizedFile, never this
    upload.DeclaredContentType,
    upload.Sample)
```

`Request.Path.Value` excludes the query string, which satisfies the "never log full query strings"
invariant at the source rather than by remembering to redact later. Use `Host.Host` so that the value
the rules see is the value host resolution used; anything else risks two answers to "which site is
this".

### 5.5 A note on `NormalizedFile` and repeated normalization

`InspectionContext.NormalizedFile` recomputes on every access — deliberately, so a `with` expression
cannot hand a rule a stale normalization. Its own remarks say "When the M2 multipart pipeline
evaluates many rules per file it should hoist this into a local."

The pipeline **cannot** hoist it. Each rule reaches for `context.NormalizedFile` itself, so the cost
is one normalization per rule per file: 8 rules × 20 files = 160 calls at the defaults, over names
capped at 1024 characters. That is a handful of string scans and a small list per call —
microseconds in total, against a request that just did network I/O. Leave it alone in M2. Caching it
would require changing `InspectionContext`, which is the public surface community rule packages will
implement against, and that is not a change to make casually for a cost nobody has measured as
mattering. Revisit under M4 if profiling disagrees.

### 5.6 Two names per part, not one

`ContentDispositionHeaderValue` exposes both `FileName` and `FileNameStar` — the RFC 5987
`filename*=UTF-8''…` form, which the header parser percent-decodes. ASP.NET Core's own
`MultipartSection.AsFileSection()` **prefers `FileNameStar`** when present. PHP's multipart handler
reads only `filename`.

That is a parser differential and it is exploitable: set `filename*=UTF-8''photo.jpg` and
`filename="shell.php"`, and a WPShield built on `AsFileSection()` inspects `photo.jpg` while PHP
writes `shell.php`.

**Do not use `AsFileSection()`.** Read `GetContentDispositionHeader()` and take both values,
dequoting each with `HeaderUtilities.RemoveQuotes`. When they are both present and differ, evaluate
the rules against **both** and keep the more severe result — the request has already told you it is
trying to be two different things. When only one is present, use it. Cover this with a test; it is
precisely the kind of gap that looks like nothing in review.

---

## 6. Action semantics

### 6.1 The matrix

| `ProtectionMode` | `InspectionAction` | Forward? | Status | Body | Log |
| --- | --- | --- | --- | --- | --- |
| `Disabled` | — (never inspected) | yes | backend's | backend's | existing Information line |
| `Monitor` | `Allow` | yes | backend's | backend's | existing Information forwarding line |
| `Monitor` | `Observe` | yes | backend's | backend's | **Warning**, with score, rule IDs, part indexes, normalized names, `WouldBlock` |
| `Monitor` | `Block` | *unreachable* | — | — | — |
| `Block` | `Allow` | yes | backend's | backend's | existing Information forwarding line |
| `Block` | `Observe` | yes | backend's | backend's | **Warning**, as above |
| `Block` | `Block` | **no** | **403** | `upload_blocked` | **Warning** |

Plus the status policy from §4.4, applied independently and taking the more restrictive outcome.

`Disabled` never buffers at all — §1.6 checks the mode before boundary extraction — so the engine's
own `Disabled` short-circuit is never even reached from this path. Both guards stay: the engine's
because it is the contract, the gateway's because it is what avoids the memory cost.

**`Monitor` + `Block` is unreachable by construction.** The engine emits `Block` only when
`site.Mode == ProtectionMode.Block`. Do not add a defensive branch that handles it; add a test that
asserts it cannot happen. A defensive branch is a second implementation of the downgrade, and the
next person to edit it will not know which one is authoritative.

Log level `Warning`, not `Error`, for a block. A blocked upload is WPShield working correctly.
`Error` is reserved for the gateway failing — it is what the existing "Proxy failure" line uses, and
an operator alerting on `Error` should not be paged because someone tried to upload `web.config`.

### 6.2 `WouldBlock`, and the one thing the gateway may read from the thresholds

In Monitor mode, log `WouldBlock={score >= site.BlockThreshold}`. This is the field that lets an
operator answer "what would happen if I turned Block on for this site?" from existing logs, which is
the whole point of running Monitor first.

It reads `site.BlockThreshold` — but only to produce a log field, never to decide an action. That
boundary is the rule: **the gateway may read the thresholds for reporting and must never read them
for control.** State it in the code comment, because the line between the two is exactly one
careless refactor wide.

### 6.3 One log event per file, not one per finding

A request at the absolute ceilings could produce 100 files × 8 rules = 800 findings. Emit one
Warning per *file* that produced findings, carrying `PartIndex`, `NormalizedName`, `Score`, `Action`
and a comma-joined `RuleIds`, plus one summary line per request. That bounds log volume at
`MaximumFileCount` lines, which is a number the operator configured.

Never log: the sample, any part of the body, the raw file name, the field name, or the full query
string. The existing forwarding line already logs `Path` without the query; keep that shape.

---

## 7. Block responses

### 7.1 Which status code, and when

| Status | Condition | `error` | Extra |
| --- | --- | --- | --- |
| **403** Forbidden | Block mode, engine returned `InspectionAction.Block`. The request was fully understood and policy forbids it. | `upload_blocked` | `ruleIds` |
| **415** Unsupported Media Type | Block mode, body complete, `MultipartReadStatus` is `Malformed` or `LimitExceeded`. WPShield could not finish inspecting the body it was given. | `multipart_not_inspectable` | `reason`: `malformed` \| `limit_exceeded` |
| **408** Request Timeout | Any mode, drain-phase timeout, body incomplete (§8). | `request_timeout` | — |
| **413** Content Too Large | Unchanged: declared `Content-Length` over the limit, or the streamed body crossed it. | `request_too_large` | — |

415 rather than 403 for the structural cases because the two mean different things to whoever reads
the log: 403 says "we understood this and refuse it", 415 says "we cannot accept this media type as
presented". Collapsing both into 403 destroys the distinction between a detection and a parser
giving up, which is the single most useful signal for tuning limits.

**408 is not in the roadmap's "403, 413 or 415" list.** It is a deliberate addition, argued in §8.3:
a timeout leaves a partial body, and there is no honest way to answer a partial body with any of the
other three. The documentation agent must add the row to the README response table and to
`ROADMAP.md`.

### 7.2 Bodies

```json
{ "error": "upload_blocked", "requestId": "…", "ruleIds": ["IIS-CONFIG-001", "WP-UPLOAD-001"] }
{ "error": "multipart_not_inspectable", "requestId": "…", "reason": "limit_exceeded" }
{ "error": "request_timeout", "requestId": "…" }
```

`ruleIds` is sorted ordinal, de-duplicated, and capped at 16 entries so a 100-file request cannot
inflate the response.

The 415 body carries `"ruleIds": ["GATEWAY-MULTIPART-001"]` as well, so the pseudo-rule is
discoverable from the response the same way a real rule is.

### 7.3 What must never appear in a block response

- **The raw file name.** Attacker-controlled bytes echoed into a JSON body that a browser dev tool, a
  log viewer or a future dashboard will render. `nosniff` and a JSON content type help; they are not
  a licence to reflect input.
- **The normalized name.** Safer, but still derived from attacker input and still worth nothing to
  the person who sent the request.
- **The sample, or any body bytes.**
- **The score and the thresholds.** This is the real oracle. A binary allow/deny signal forces an
  attacker to search blind; a numeric score turns the search into hill-climbing, because every
  mutation reports how much closer it got. Withholding the number is the single highest-value
  omission in this section.
- **The site ID, the destination, the evidence dictionary, the field name, the part count.**

### 7.4 Should the response name the rules? Argued both ways

**Against.** It is an oracle. An attacker uploading `shell.php.jpg` learns that `WP-UPLOAD-001` and
`WP-UPLOAD-002` fired, and therefore that the file *name* is what betrayed them — so they know to
attack the name rather than the content. Without the IDs they still get a binary signal, but they
must guess which of several signals to defeat, and when four rules fire they must defeat all four
without knowing there were four.

**For.** WPShield is open source. The complete rule catalogue, every ID, every score and every
false-positive note is published in `README.md` and `docs/en/m2-upload-rules.md`, and the source is
on GitHub. An attacker does not need the response to learn that `IIS-CONFIG-001` exists; they can
read it, along with the exact matching logic. Withholding the IDs protects nothing that is actually
secret. Meanwhile the cost of withholding falls entirely on the legitimate side: a site owner whose
genuine upload is refused sees an opaque 403 with no path from the browser to the cause, and the
support burden of "WPShield blocked my file and won't say why" is exactly how a security tool gets
switched off.

**Decision: disclose the rule IDs.** The asymmetry decides it — the IDs are already public, the score
is not. Disclose what is published, withhold what is derived. If WPShield ever gains non-public
rules (a community package an operator does not publish), this decision must be revisited for those
rules specifically, and the note should say so.

### 7.5 Headers — and a bug in the existing responses

Every gateway-generated response must carry:

```
Content-Type: application/json; charset=utf-8     (from WriteAsJsonAsync)
X-WPShield-Request-ID: <TraceIdentifier>
X-Content-Type-Options: nosniff
Cache-Control: no-store
```

`Cache-Control: no-store` is new: a block decision depends on the request body, and no intermediary
should ever serve a cached 403 for a different body.

Do **not** add `Retry-After` — it implies the refusal is transient and invites a retry loop against a
decision that will not change.

**The existing code loses two of these headers, and this is a real pre-existing bug the implementer
must fix rather than replicate.** `HttpResponse.Clear()` is an extension method that clears status,
reason phrase **and headers**. `WriteRequestTooLargeAsync` and the 502 path both call it, which wipes
the `X-WPShield-Request-ID` and `X-Content-Type-Options` headers that the first middleware set.
Measured on .NET 10.0.10 with a minimal Kestrel app:

```
/clear   -> 413   headers: Date | Server | Transfer-Encoding
/noclear -> 413   headers: Date | Server | Transfer-Encoding | X-WPShield-Request-ID | X-Content-Type-Options
```

So today's 413 and 502 responses carry neither header, which contradicts `README.md`: *"Every
response, forwarded or generated, carries an `X-WPShield-Request-ID` correlation header and
`X-Content-Type-Options: nosniff`."* The 421 path does not call `Clear()` and is unaffected.

Fix it with one shared writer that every gateway-generated error goes through:

```csharp
static async Task WriteGatewayErrorAsync(HttpContext context, int statusCode, object body)
{
    if (context.Response.HasStarted) return;
    context.Response.Clear();
    context.Response.StatusCode = statusCode;
    context.Response.Headers["X-WPShield-Request-ID"] = context.TraceIdentifier;
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers.CacheControl = "no-store";
    await context.Response.WriteAsJsonAsync(body, context.RequestAborted);
}
```

Route the existing 413, 502 and 421 writers through it too. One writer means one place where the
header set can drift, and the integration suite should assert the headers on every generated status
— 421, 403, 408, 413, 415, 502 — rather than only on the forwarded 200 as it does today.

---

## 8. Cancellation, disconnect and timeouts

### 8.1 Threading the token

`context.RequestAborted` is the root. It is passed to `UploadInspectionStage.EvaluateAsync` and from
there into the drain loop, `MultipartReader.ReadNextSectionAsync`, every sample read, and
`engine.InspectAsync` (whose loop already calls `ThrowIfCancellationRequested` between rules).

### 8.2 The read timeout

```csharp
using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
timeoutCts.CancelAfter(TimeSpan.FromSeconds(
    Math.Clamp(options.ReadTimeoutSeconds, 1, MultipartInspectionOptions.AbsoluteMaximumReadTimeoutSeconds)));
```

A linked source with `CancelAfter` is enforceable **independently of `ForwarderRequestConfig.ActivityTimeout`**,
which is a YARP setting that only governs the forwarding leg and does not exist yet at the point the
body is being drained. The forwarder has not been called; nothing else is watching this read.

The timeout covers **both** phases — the network drain and the in-memory parse. The drain is where it
earns its keep: it is the only window in which a slow client can hold a pooled buffer open, and
bounding that window is what stops a slow-loris upload from pinning memory indefinitely. Keeping it
active through the parse costs nothing and covers a pathological body that makes the boundary scan
do more work than expected.

### 8.3 Telling the three cancellations apart

On `OperationCanceledException`, check which token fired:

- **`context.RequestAborted.IsCancellationRequested`** → the client disconnected. Write nothing —
  the connection is gone and `WriteAsJsonAsync` would throw on top of the original exception. Log at
  Information with `RequestId`, `SiteId` and `BufferedBytes`. Return the buffer. Never contact the
  backend.
- **The linked token fired but `RequestAborted` did not, during the drain** → timeout with an
  **incomplete** body. `MultipartReadStatus.TimedOut`, and **408 in every mode**, including Monitor.
- **The linked token fired during the parse** → timeout with a **complete** body. Treat it exactly
  like `LimitExceeded`: Monitor forwards and logs, Block returns 415. The body is intact, so
  Monitor's promise still holds.

That last split is why `UploadInspectionDecision` needs a "body complete" fact separate from the
status. §4.4's two-axis table is the whole policy.

**Why 408 in Monitor mode.** Monitor's promise is that WPShield never blocks *on a finding*. A
half-arrived body is not a finding — it is a request the client failed to deliver. Forwarding the
truncated buffer would send WordPress a body shorter than its declared `Content-Length`, producing a
hung or corrupt upload and a backend error the operator cannot attribute to WPShield. The precedent
is already set: `docs/en/m2-request-limits.md` says the 413 limit "applies in `Monitor`, `Block`, and
`Disabled` modes because it is an absolute resource-safety control." 408 is the same category.

The rejected alternative — forward what arrived — was considered and is worse in every mode.

### 8.4 Swallowing cancellation, deliberately and narrowly

AGENTS.md says never swallow cancellation. The client-disconnect branch does swallow it: it catches
`OperationCanceledException`, logs, and returns without rethrowing.

That is a deliberate, narrow exception, and it is justified because `ForwardRequestAsync` is the top
of the request pipeline — there is no caller left to observe the exception. Rethrowing turns an
entirely normal client abort (a user who closed the tab mid-upload) into an unhandled-exception
`Error` line, which is noise in a component whose `Error` level should mean "the gateway is broken".
The `when (context.RequestAborted.IsCancellationRequested)` filter keeps it narrow: a timeout
cancellation does not match it and is handled as a timeout. Write the reasoning in the code comment.

### 8.5 The timeout's honest false positive

30 seconds against a 6 MiB body implies a sustained floor of about **205 KiB/s**. A genuinely slow
mobile or satellite client uploading a full-size image will trip it and receive a 408.

That is a real operational trap and it must be in the operator documentation, not discovered in
production. The levers, in order: most uploads are far smaller than 6 MiB, so the practical floor is
much lower; `ReadTimeoutSeconds` can go to 120, which drops the floor to about 51 KiB/s; and
`MaximumRequestBytes` can be lowered, which reduces the worst case directly. An operator on a slow
link should raise the timeout before they enable Block anywhere.

---

## 9. DoS surface

### 9.1 The arithmetic

Per concurrent buffered request, at the shipped defaults:

| Component | Bytes |
| --- | ---: |
| Body chunks: `ceil((6 MiB + 1) / 64 KiB) × 64 KiB` = 97 × 65,536 | 6,356,992 |
| Samples: `MaximumFileCount × SampleBytes` = 20 × 4,096 | 81,920 |
| Scratch drain buffer | 8,192 |
| **Total** | **≈ 6.15 MiB** |

At the worst legal configuration (`MaximumRequestBytes` 64 MiB, `MaximumFileCount` 100,
`SampleBytes` 64 KiB): 67,108,864 + 65,536 + 6,553,600 + 8,192 = **≈ 70.3 MiB per request**.

Samples are copied into right-sized `byte[]` arrays rather than aliased into the pooled chunks. That
costs the 80 KiB above, and it buys the guarantee that no rule can hold a `ReadOnlyMemory<byte>`
pointing into a buffer that has been returned to the pool and handed to another request. Do not
"optimise" it into a slice.

### 9.2 What bounds concurrency today

**Nothing.** `KestrelServerLimits.MaxConcurrentConnections` defaults to `null`, meaning unlimited,
and `GatewayApplication` sets only `MaxRequestBodySize`. There is no connection cap, no request
queue limit, and no rate limiting until M3.

So the bound on total buffered memory is the attacker's bandwidth. Because
`ReadTimeoutSeconds` caps how long one buffer can be held, sustaining `B` bytes of pinned memory
costs roughly `B / ReadTimeoutSeconds` bytes per second of attacker upload:

- Pinning 1 GiB at the 30-second default ≈ **36 MB/s ≈ 286 Mbit/s** sustained, across about 171
  concurrent connections.
- Pinning 6 GiB ≈ 1.7 Gbit/s.

Over loopback — where the gateway lives today — that cost is effectively zero.

### 9.3 This is a real regression, stated plainly

Before M2 the gateway streamed every request and held no per-request body memory. After M2 a
multipart request holds up to ~6.15 MiB for up to 30 seconds, with nothing bounding how many such
requests exist at once. That is a genuine new denial-of-service surface and the documentation must
say so rather than describing the buffer as merely "bounded".

The loopback-only restriction has changed character because of it. It used to be a statement about
project maturity. It is now also the only thing bounding this memory, and it should be described
that way in the threat model.

### 9.4 What M3 must add, and what operators get in the meantime

**M3 prerequisite** — alongside `Gateway:TrustedProxies`, which the roadmap already names as a
blocker: an explicit bound on concurrent buffered inspections. The right shape is a `SemaphoreSlim`
gating only the buffered path, sized so `MaxConcurrentBufferedRequests × MaximumRequestBytes` is a
number the operator chose, with requests beyond it either queued briefly or answered 503. It is
deliberately **not** added in M2, because `MultipartInspectionOptions` is a fixed contract that other
agents implement against and adding a setting to it mid-milestone is how three agents end up with
three shapes. Record it as an M3 item.

**In the meantime**, the operator documentation must give:

- The arithmetic in §9.1, so an operator can compute their own worst case.
- `Gateway:MaximumRequestBytes` as the one in-contract lever: it divides the worst case directly, and
  most WordPress sites do not need 6 MiB. Lowering it to 2 MiB cuts the exposure by two thirds.
- `Gateway:Multipart:ReadTimeoutSeconds` as the second lever: lowering it shortens how long each
  buffer is held and raises the attacker's required bandwidth proportionally, at the cost of §8.5's
  false positive.
- `Kestrel:Limits:MaxConcurrentConnections` as the blunt instrument, with the explicit note that it
  is **not** exposed through `GatewayOptions` today and must be set through the standard Kestrel
  configuration section.
- The statement that WPShield does not provide volumetric DoS mitigation, which `README.md` already
  makes and which this section makes more load-bearing.

### 9.5 Pool retention

Chunks are 64 KiB, below the 85,000-byte LOH threshold, so the pipeline never allocates on the large
object heap. `ArrayPool<byte>.Shared` retains returned arrays per core and trims them under memory
pressure via its Gen 2 callback, so a burst does not leave memory pinned indefinitely the way a
hand-rolled cache would. Per-request retention is bounded by our own chunk-count cap, which is where
the bound belongs.

---

## 10. What M2 still does NOT do

The README status table must stay honest. After this work lands, WPShield still does none of the
following, and the documentation agent should treat this as the source list.

**Not inspected at all:**

1. **Any non-multipart body.** `application/x-www-form-urlencoded`, raw JSON, XML-RPC
   (`xmlrpc.php`), `application/octet-stream` PUT bodies. A plugin endpoint that accepts a
   base64-encoded file inside a JSON payload is completely invisible.
2. **`multipart/*` subtypes other than `form-data`** — `mixed`, `related`, `byteranges` — stream
   through uninspected (§3).
3. **Form field parts.** Never sampled, never inspected, deliberately (§4.3). A payload smuggled
   through a text field is not seen.
4. **Responses.** Inspection is request-only. A compromised site serving a webshell is not detected.
5. **Nested multipart.** A part whose own `Content-Type` is multipart is not recursed into.
6. **`Content-Transfer-Encoding: base64` parts** are not decoded. PHP's `rfc1867` ignores the header
   too, so WPShield and the backend agree — but a plugin that decodes it manually is uncovered.
7. **Archive contents.** A `.zip` plugin or theme upload containing a webshell is not opened. Plugin
   and theme installation is a genuine WordPress upload path and this is the largest single gap.

**Inspected, but only partially:**

8. **Only the first `SampleBytes` (4 KiB) of each file.** A payload appended after 4 KiB of valid
   JPEG data is not seen by any content rule, including `PHP-CONTENT-002`.
9. **File names are capped at 1024 characters** before normalization; a longer name is a limit hit
   rather than an inspection (§4.2).
10. **Duplicate `Content-Type` headers** are only treated as an anomaly when one of the values is
    `multipart/form-data`. Duplicated `Content-Type` on any other request streams through.

**Not present at all:**

11. **No bound on concurrent buffered inspections** (§9.3). This is the one item on this list that is
    a regression rather than an absence.
12. **No rate limiting**, per IP or per site — M3.
13. **No structured inspection events, no metrics, no JSON Lines log with rotation and retention** —
    M4. Findings exist only as `ILogger` output.
14. **No dashboard** — M5.
15. **The real client IP is still unknown.** Every forwarding header is stripped and
    `Gateway:TrustedProxies` does not exist. Per ADR 0001 that must land before M3.
16. **No image or document structural validation** beyond `FILE-TYPE-001`'s magic-byte table. No EXIF
    parsing, no polyglot detection past the sample window.
17. **Loopback only, HTTP/1.1 on Kestrel, still not approved for production traffic.**

### 10.1 Documentation the doc agent owns

- **README status table**: `Streaming multipart inspection | Planned` becomes
  `Bounded multipart inspection | Available`. Drop the word *streaming* — it is now wrong. Note
  "buffered in memory, never to disk, multipart only".
- **README response table**: add 403, 415 and **408** rows.
- **README troubleshooting table**: add the five `Gateway:Multipart:*` startup messages from §2.3.
- **README line 143** ("Multipart parsing is not yet connected to the gateway") must go.
- **AGENTS.md**: "Avoid buffering complete uploads in memory" is now imprecise. Restate as the actual
  guarantee: *never to disk; never unbounded; only for `multipart/form-data`; only when the site is
  not `Disabled` and inspection is enabled.*
- **ROADMAP.md M2**: "Parse multipart requests without buffering complete uploads or writing them to
  disk" — same restatement.
- **`.github/instructions/csharp.instructions.md`** carries the same "Do not buffer complete request
  bodies" line and needs the same treatment.
- **`docs/en/m2-request-limits.md` "Streaming limitation"**: narrow it to non-multipart bodies. On
  the buffered multipart path nothing reaches the backend before the 413 (§1.5).
- **THREAT_MODEL.md**: §9.3 — loopback-only is now a memory control, not only a maturity statement.
- **New operator page** (English and Spanish) covering the `Gateway:Multipart` settings, the §9.1
  arithmetic, and the two named false positives: the 71–128 character boundary band (§3.2) and the
  205 KiB/s upload floor (§8.5).

---

## Appendix A — file manifest

| File | Owner | Note |
| --- | --- | --- |
| `src/WPShield.Gateway/MultipartInspectionOptions.cs` | gateway agent | Exactly the fixed contract. |
| `src/WPShield.Gateway/InspectedUpload.cs` | gateway agent | `InspectedUpload`, `MultipartReadStatus`, `MultipartInspectionOutcome`. |
| `src/WPShield.Gateway/MultipartInspectionReader.cs` | gateway agent | `TryGetBoundary` + `ReadAsync`. |
| `src/WPShield.Gateway/PooledRequestBuffer.cs` | gateway agent | §1. |
| `src/WPShield.Gateway/UploadInspectionStage.cs` | gateway agent | §2.1. |
| `src/WPShield.Gateway/GatewayApplication.cs` | gateway agent | Call site, DI, shared error writer (§7.5). |
| `src/WPShield.Gateway/GatewayConfigurationValidator.cs` | gateway agent | §2.3. |
| `src/WPShield.Gateway/appsettings.json` | gateway agent | §2.4. |
| `src/WPShield.Gateway/WPShield.Gateway.csproj` | gateway agent | Rules project reference. |
| `src/WPShield.Rules.WordPress/FileSignatures.cs` | rules agent | `internal static` magic-byte table. |
| `src/WPShield.Rules.WordPress/FileTypeMismatchRule.cs` | rules agent | `FILE-TYPE-001`. |
| `src/WPShield.Rules.WordPress/PhpPolyglotUploadRule.cs` | rules agent | `PHP-CONTENT-002`. |

`MultipartInspectionReader.ReadAsync` contract detail: the caller passes the buffer positioned at
**0**; the reader reads forward and does not seek; on return the position is undefined and the caller
seeks to 0 before forwarding.

## Appendix B — `MultipartReader` wiring, verified

Against `Microsoft.AspNetCore.WebUtilities` in the 10.0.10 shared framework:

```csharp
var reader = new MultipartReader(boundary, seekableBody)   // default bufferSize 4096
{
    HeadersCountLimit = 16,
    HeadersLengthLimit = options.MaximumPartHeaderBytes,
    BodyLengthLimit = null
};
MultipartSection? section = await reader.ReadNextSectionAsync(cancellationToken);
ContentDispositionHeaderValue? disposition = section.GetContentDispositionHeader();
// disposition.Name, disposition.FileName, disposition.FileNameStar — all still quoted;
// dequote each with HeaderUtilities.RemoveQuotes. See §5.6 before using AsFileSection().
```

`ReadNextSectionAsync` drains the previous section before advancing, so a part whose body you chose
not to read fully does not need manual draining — but read it anyway, because `ByteCount` is part of
the `InspectedUpload` contract and the drain does not report it.

Map `InvalidDataException` from the reader to `MultipartReadStatus.Malformed`. Do not string-match its
message to separate header-limit overflows from genuine corruption; both produce the same policy and
the only cost is a slightly less precise `reason`. Log the exception **type name** and WPShield's own
counters, never the exception message and never the body.

## Appendix C — test checklist

The ROADMAP asks for "malformed, truncated, Unicode, cancellation, disconnect, limit, false-positive,
and multi-file tests". Concretely, in the established `SyntheticGatewayIntegrationTests` style with
synthetic backends on dynamically allocated ports:

1. Non-multipart POST: no buffer rented, body byte-identical at the backend.
2. Benign single-file multipart in Monitor: forwarded, body byte-identical, no Warning.
3. `web.config` part in Block mode: 403, `ruleIds` contains `IIS-CONFIG-001`, backend received nothing.
4. Same request in Monitor mode: forwarded, Warning logged, `WouldBlock=true`.
5. Twenty files each scoring 30: forwarded (proves max, not sum).
6. One file at 90 among nineteen benign: blocked in Block mode (proves max).
7. Empty file input (`filename=""`, zero-byte body): forwarded, no finding (proves §4.3).
8. Field part containing `<?php echo 'synthetic marker';`: forwarded, no finding (proves fields are
   not sampled).
9. `filename*` and `filename` disagreeing: the more severe of the two decides (§5.6).
10. Boundary of 71 characters: `Malformed`; Monitor forwards, Block 415.
11. Two `Content-Type` headers, both multipart: `Malformed`.
12. 21 files: `LimitExceeded`; Monitor forwards, Block 415; backend received the complete body in
    Monitor.
13. Truncated multipart (body ends mid-part): `Malformed`, complete-body policy.
14. Chunked multipart with no `Content-Length` exceeding the limit: 413, backend received nothing.
15. Slow client that never finishes the body: 408 in Monitor *and* Block, backend received nothing.
16. Client disconnect mid-upload: no response written, no backend contact, no pooled array leaked.
17. Unicode file name (`фото.jpg`, `写真.jpg`): forwarded, no finding.
18. Every gateway-generated status — 421, 403, 408, 413, 415, 502 — carries
    `X-WPShield-Request-ID`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` (§7.5).
19. No response body contains a raw file name, a score, a threshold or a sample byte.
20. `Disabled` mode: multipart request forwarded with no buffering and no inspection.

Use harmless synthetic markers only. `<?php echo 'synthetic marker';` is the established one; never a
working webshell.
