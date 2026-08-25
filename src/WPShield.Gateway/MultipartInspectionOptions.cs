namespace WPShield.Gateway;

/// <summary>
/// Bounds for the <c>multipart/form-data</c> inspection pass, bound from the
/// <c>Gateway:Multipart</c> configuration section.
/// </summary>
/// <remarks>
/// <para>
/// Every value here exists because inspecting an upload means holding part of it. Before M2 the
/// gateway streamed every request straight through and held no per-request body memory at all; a
/// multipart request now costs a bounded buffer plus a bounded sample per file, for a bounded
/// length of time. These settings are the only thing bounding that cost, so each one is paired
/// with an <c>Absolute…</c> ceiling that configuration may lower but never raise.
/// </para>
/// <para>
/// The ceilings are enforced twice, deliberately. <c>GatewayConfigurationValidator</c> throws at
/// startup, so an operator who asks for something the gateway will not do is told rather than
/// silently overridden; and <see cref="MultipartInspectionReader"/> clamps again at the point of
/// use, so an options instance constructed directly in code — a test, a future call site — cannot
/// lift a ceiling by skipping the validator.
/// </para>
/// </remarks>
public sealed class MultipartInspectionOptions
{
    /// <summary>
    /// Hard ceiling on <see cref="MaximumFileCount"/>.
    /// </summary>
    /// <remarks>
    /// Each inspected file retains a sample of up to <see cref="SampleBytes"/> for the life of the
    /// request and is evaluated by every registered rule, so the file count multiplies both memory
    /// and CPU. WordPress posts one file per request to <c>async-upload.php</c>, and so do the
    /// multi-file uploaders worth naming, so 100 already sits an order of magnitude above anything
    /// legitimate traffic produces.
    /// </remarks>
    public const int AbsoluteMaximumFileCount = 100;

    /// <summary>
    /// Hard ceiling on <see cref="MaximumFieldCount"/>.
    /// </summary>
    /// <remarks>
    /// Field parts are counted but never sampled, so they cost only the walk past them. The ceiling
    /// exists so a body made of a million empty fields cannot turn the parse into an unbounded
    /// loop; it is not a memory control.
    /// </remarks>
    public const int AbsoluteMaximumFieldCount = 1000;

    /// <summary>
    /// Hard ceiling on <see cref="MaximumPartHeaderBytes"/>.
    /// </summary>
    /// <remarks>
    /// This becomes <c>MultipartReader.HeadersLengthLimit</c>. A legitimate file part carries a
    /// <c>Content-Disposition</c>, a <c>Content-Type</c> and occasionally a transfer encoding — a
    /// few hundred bytes. 32 KiB is the point past which a part header is no longer plausibly a
    /// header and is instead a way to make the gateway read something it will never use.
    /// </remarks>
    public const int AbsoluteMaximumPartHeaderBytes = 32 * 1024;

    /// <summary>
    /// Hard ceiling on <see cref="SampleBytes"/>.
    /// </summary>
    /// <remarks>
    /// The sample is the only part of an upload WPShield keeps. At the ceiling a request holding
    /// the maximum number of files retains 100 × 64 KiB = 6.25 MiB of samples on top of the body
    /// buffer, which is why the ceiling is not higher.
    /// </remarks>
    public const int AbsoluteMaximumSampleBytes = 64 * 1024;

    /// <summary>
    /// Floor on <see cref="SampleBytes"/>. Below this the content rules cannot decide.
    /// </summary>
    /// <remarks>
    /// A cross-agent contract, not a stylistic bound. <c>docs/en/m2-content-rules-design.md</c>
    /// records that below 512 bytes the text-versus-binary classification degrades and the
    /// <c>%PDF-</c> tolerance disappears, so <c>FILE-TYPE-001</c> and <c>PHP-CONTENT-002</c> begin
    /// deciding from samples too short to decide from. Without the floor, a number that reads like
    /// a performance knob would quietly disable two rules while the configuration still said
    /// <c>Enabled: true</c> — configuration appearing to do something it does not.
    /// </remarks>
    public const int MinimumSampleBytes = 512;

    /// <summary>
    /// Hard ceiling on <see cref="ReadTimeoutSeconds"/>.
    /// </summary>
    /// <remarks>
    /// The timeout bounds how long a slow client can pin a pooled body buffer, so it is a memory
    /// control as much as a latency one. Two minutes is the longest hold the gateway will grant a
    /// single request.
    /// </remarks>
    public const int AbsoluteMaximumReadTimeoutSeconds = 120;

    /// <summary>
    /// Whether multipart bodies are buffered and inspected at all. Default <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Turning this off returns the gateway to pure streaming: no body is buffered, no sample is
    /// taken, and no upload rule ever runs on real traffic. It is the operator's escape hatch if
    /// inspection is implicated in an incident, not a tuning knob — a gateway with inspection
    /// disabled is a reverse proxy with a size limit.
    /// </remarks>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Maximum file parts inspected in one request before the read stops with
    /// <see cref="MultipartReadStatus.LimitExceeded"/>. Default 20, ceiling
    /// <see cref="AbsoluteMaximumFileCount"/>.
    /// </summary>
    /// <remarks>
    /// Stopping is not the same as passing. Exceeding this limit is itself a finding, because
    /// otherwise an attacker could prefix a payload with twenty dummy files and buy an uninspected
    /// forward for the twenty-first.
    /// </remarks>
    public int MaximumFileCount { get; init; } = 20;

    /// <summary>
    /// Maximum non-file parts counted in one request before the read stops with
    /// <see cref="MultipartReadStatus.LimitExceeded"/>. Default 200, ceiling
    /// <see cref="AbsoluteMaximumFieldCount"/>.
    /// </summary>
    /// <remarks>
    /// This is the limit most likely to be met by legitimate traffic. Most large WordPress admin
    /// forms are <c>application/x-www-form-urlencoded</c> and never reach this code, but a page
    /// builder or form plugin that posts a large form <i>with</i> a file attached arrives as
    /// multipart and can exceed 200 fields. Monitor mode surfaces the observed count as a warning
    /// before Block mode can turn it into a refusal, and this setting is the lever.
    /// </remarks>
    public int MaximumFieldCount { get; init; } = 200;

    /// <summary>
    /// Maximum bytes of headers on a single part, passed to <c>MultipartReader.HeadersLengthLimit</c>.
    /// Default 16 KiB, ceiling <see cref="AbsoluteMaximumPartHeaderBytes"/>.
    /// </summary>
    /// <remarks>
    /// Exceeding it produces <see cref="MultipartReadStatus.Malformed"/> rather than a truncated
    /// header, and that distinction matters: a header WPShield read only part of is a header
    /// WPShield and the backend disagree about, and the disagreement is the whole attack.
    /// </remarks>
    public int MaximumPartHeaderBytes { get; init; } = 16 * 1024;

    /// <summary>
    /// Leading bytes captured from each file part for the content rules. Default 4096, floor
    /// <see cref="MinimumSampleBytes"/>, ceiling <see cref="AbsoluteMaximumSampleBytes"/>.
    /// </summary>
    /// <remarks>
    /// Only the leading bytes are kept; the remainder of the part is read and discarded so that
    /// <see cref="InspectedUpload.ByteCount"/> stays accurate without the content ever being
    /// retained. Raising this widens the window in which a marker appended past the sample can be
    /// found, at a linear cost in retained memory per file.
    /// </remarks>
    public int SampleBytes { get; init; } = 4096;

    /// <summary>
    /// Deadline covering the whole inspection read. Default 30, ceiling
    /// <see cref="AbsoluteMaximumReadTimeoutSeconds"/>.
    /// </summary>
    /// <remarks>
    /// 30 seconds against a 6 MiB body implies a sustained floor of roughly 205 KiB/s, so a
    /// genuinely slow mobile or satellite client uploading a full-size image can trip it and
    /// receive a 408. That is a real operational trap rather than a theoretical one: an operator on
    /// slow links should raise this toward 120 — which drops the floor to about 51 KiB/s — before
    /// enabling Block anywhere.
    /// </remarks>
    public int ReadTimeoutSeconds { get; init; } = 30;
}
