namespace WPShield.Gateway;

/// <summary>
/// One file part of a <c>multipart/form-data</c> body, reduced to bounded metadata plus a bounded
/// leading sample.
/// </summary>
/// <param name="FieldName">
/// The dequoted <c>name</c> parameter of the part's <c>Content-Disposition</c>, truncated to
/// 1024 characters. Attacker-controlled; it is carried so the caller can correlate parts, and it
/// must never reach a log line, a response body or a finding's evidence.
/// </param>
/// <param name="FileName">
/// The dequoted, 1024-character-capped file name. Raw and attacker-controlled: rules must match
/// against <c>InspectionContext.NormalizedFile</c>, never against this.
/// </param>
/// <param name="DeclaredContentType">
/// The part's own <c>Content-Type</c> header, truncated to 256 characters. It is what the client
/// claims, not what the bytes are, and a rule that fires on it fires on every non-browser client.
/// </param>
/// <param name="Sample">
/// The leading bytes of the part, at most <see cref="MultipartInspectionOptions.SampleBytes"/>.
/// Backed by a private right-sized array owned by this record — never by a pooled buffer — so the
/// caller may hold it for the lifetime of the request without a use-after-return hazard.
/// </param>
/// <param name="ByteCount">
/// The full length of the part in bytes, including everything past the sample. The remainder is
/// read and discarded to obtain this, so the count is exact and the content is not retained.
/// </param>
/// <remarks>
/// <para>
/// <b>One part can produce two of these.</b> <c>Content-Disposition</c> can carry both
/// <c>filename</c> and the RFC 5987 <c>filename*</c>, and they need not agree. ASP.NET Core's own
/// <c>MultipartSection.AsFileSection()</c> prefers <c>filename*</c>; PHP's multipart handler reads
/// only <c>filename</c>. So <c>filename*=UTF-8''photo.jpg</c> alongside
/// <c>filename="shell.php"</c> is a request that is deliberately two different files at once, and a
/// gateway that picks one inspects a file the backend will not write. When the two names differ,
/// the reader emits an entry for each — <c>filename</c> first, because that is the name PHP acts on
/// — sharing one sample. The caller's existing most-severe-wins aggregation then evaluates both
/// without needing to know the differential exists.
/// </para>
/// <para>
/// A consequence worth stating: <c>MultipartInspectionOutcome.Files.Count</c> counts <i>names
/// inspected</i>, not parts, and can exceed
/// <see cref="MultipartInspectionOptions.MaximumFileCount"/> by up to a factor of two. The file
/// count limit is applied per part.
/// </para>
/// </remarks>
public sealed record InspectedUpload(
    string? FieldName,
    string? FileName,
    string? DeclaredContentType,
    ReadOnlyMemory<byte> Sample,
    long ByteCount);

/// <summary>
/// How far the multipart read got. Anything other than <see cref="Complete"/> is itself a finding.
/// </summary>
/// <remarks>
/// This enum is the answer to the single most dangerous question in the pipeline: what happens when
/// the reader gives up? If "gave up" meant "forward it", an attacker would prefix a payload with
/// ten thousand dummy parts and buy a one-request, zero-knowledge bypass of every rule WPShield
/// ships. So every non-<see cref="Complete"/> status constrains the outcome — Monitor forwards and
/// logs a warning, Block refuses.
/// </remarks>
public enum MultipartReadStatus
{
    /// <summary>
    /// The body parsed cleanly and every limit held.
    /// </summary>
    Complete = 0,

    /// <summary>
    /// A file, field or file-name limit was hit and the read stopped early.
    /// </summary>
    /// <remarks>
    /// The body itself is intact — parsing runs against an already-buffered body and never touches
    /// the network — so Monitor can still forward it whole.
    /// <see cref="MultipartInspectionOutcome.Files"/> holds whatever was read before the limit, and
    /// those findings still count.
    /// </remarks>
    LimitExceeded = 1,

    /// <summary>
    /// The body is not valid <c>multipart/form-data</c>, or it declared multipart with a boundary
    /// the gateway refuses to parse.
    /// </summary>
    /// <remarks>
    /// Fail closed. Forwarding what we cannot parse is a one-line bypass: a 200-character boundary,
    /// or one with an embedded <c>;</c>, and the request sails through uninspected while IIS and
    /// PHP parse it happily.
    /// </remarks>
    Malformed = 2,

    /// <summary>
    /// The read deadline elapsed.
    /// </summary>
    /// <remarks>
    /// Whether the body is complete depends on which phase timed out, and only the caller knows:
    /// a deadline reached while draining the network leaves a partial body (408 in every mode,
    /// because a truncated forward is a corrupt upload), while a deadline reached while parsing the
    /// already-buffered body leaves it intact and is treated exactly like
    /// <see cref="LimitExceeded"/>. This status alone does not distinguish them.
    /// </remarks>
    TimedOut = 3
}

/// <summary>
/// Everything the gateway learned from one multipart body: the file parts worth inspecting, how
/// many non-file parts there were, and how far the read got.
/// </summary>
/// <param name="Files">
/// The inspectable file parts, in body order. Empty when the body carried none — or when the read
/// stopped before reaching any. See <see cref="InspectedUpload"/> for why this can hold more
/// entries than the body had file parts.
/// </param>
/// <param name="FieldCount">
/// Non-file parts. Counted and never sampled: <c>PhpContentInUploadRule</c> matches <c>&lt;?php</c>
/// anywhere in a sample, and a WordPress post body, a theme-editor save or an Elementor widget
/// containing a code snippet legitimately contains that string. Sampling fields would make the rule
/// fire on routine editorial traffic, so this is a correctness requirement rather than an
/// optimisation.
/// </param>
/// <param name="Status">
/// How far the read got. See <see cref="MultipartReadStatus"/>: anything other than
/// <see cref="MultipartReadStatus.Complete"/> is a finding in its own right.
/// </param>
public sealed record MultipartInspectionOutcome(
    IReadOnlyList<InspectedUpload> Files,
    int FieldCount,
    MultipartReadStatus Status);
