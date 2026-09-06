using System.Buffers;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace WPShield.Gateway;

/// <summary>
/// Reduces a buffered <c>multipart/form-data</c> body to bounded per-file metadata and a bounded
/// leading sample, so the inspection rules can run without the gateway ever holding a whole upload
/// or touching disk.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the framework parser.</b> The parse itself is delegated to
/// <see cref="MultipartReader"/> from the ASP.NET Core shared framework. Hand-written multipart
/// parsers are a well-documented source of security bugs — boundary confusion, header smuggling,
/// off-by-one CRLF handling — and every one of those bugs in a gateway is a parser differential
/// against the backend, which is the exact failure this component exists to prevent. What WPShield
/// adds is the policy the framework has no opinion about: which parts count as files, how much of
/// each is kept, and what happens when a limit is reached.
/// </para>
/// <para>
/// <b>Stream contract.</b> <see cref="ReadAsync"/> reads forward from the stream's current
/// position and never calls <c>Seek</c> or assigns <c>Position</c>, so it works against a
/// forward-only stream as well as a seekable one. The caller passes the buffer positioned at 0.
/// On return the position is at or near the end of the parsed content and is deliberately
/// <i>undefined</i>: rewinding before the body is forwarded is the caller's job, and doing it here
/// would hide that responsibility from the one place — the call site that swaps the buffer into
/// <c>HttpRequest.Body</c> — where forgetting it would send WordPress a truncated upload.
/// </para>
/// <para>
/// Forward-only is what <see cref="ClosingDelimiterAudit"/> depends on. The audit answers "did the
/// parse actually reach the end of the body?" by watching every byte as the parser pulls it, which
/// is only sound while the bytes arrive once, in order. A seek-and-rescan would have answered the
/// same question, but it would have made the reader require a seekable stream and it would have
/// read the body twice. See <see cref="ReadAsync"/>.
/// </para>
/// <para>
/// <b>Statelessness.</b> Every piece of state lives in a local, so a single instance is safe to
/// register as a singleton and share across concurrent requests.
/// </para>
/// </remarks>
internal sealed class MultipartInspectionReader
{
    /// <summary>
    /// The only multipart subtype in scope.
    /// </summary>
    /// <remarks>
    /// <c>multipart/mixed</c>, <c>multipart/related</c> and friends stream through uninspected, and
    /// that is a deliberate scope decision rather than an oversight: PHP's multipart handler
    /// populates <c>$_FILES</c> only for <c>form-data</c>, so those subtypes cannot become an
    /// upload through the path WPShield defends. It is recorded as a known gap in the M2
    /// documentation rather than papered over.
    /// </remarks>
    public const string MultipartFormData = "multipart/form-data";

    /// <summary>
    /// RFC 2046 §5.1.1 caps a boundary at 70 characters. Longer is
    /// <see cref="MultipartReadStatus.Malformed"/>.
    /// </summary>
    /// <remarks>
    /// Kestrel's own <c>FormOptions.MultipartBoundaryLengthLimit</c> defaults to 128, so ASP.NET
    /// Core — and very likely PHP — accept boundaries in the 71–128 band that WPShield calls
    /// malformed. That band is this rule's entire false-positive surface. No mainstream client
    /// generates one; browsers emit boundaries well under 70. A bespoke API client with an unusual
    /// boundary generator could land there and receive a 415 once the site is in Block mode, which
    /// is why Monitor is the default and the observed length is logged.
    /// </remarks>
    public const int MaximumBoundaryLength = 70;

    /// <summary>
    /// Longest raw file name carried into an <see cref="InspectedUpload"/>. Exceeding it truncates
    /// the name <i>and</i> reports <see cref="MultipartReadStatus.LimitExceeded"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The raw name is already bounded by <see cref="MultipartInspectionOptions.MaximumPartHeaderBytes"/>,
    /// but 16 KiB is not a file name, and <c>InspectionContext.NormalizedFile</c> recomputes the
    /// Windows-aware normalization on every access — once per rule per file — so an unbounded name
    /// is re-scanned eight times over.
    /// </para>
    /// <para>
    /// <b>Truncation alone would be unsafe, and this is the trap.</b> Chopping the tail off
    /// <c>aaaa…aaaa.php</c> removes the <c>.php</c> and converts a detection into a miss. Reporting
    /// the truncation as a limit hit is what stops a name too long to inspect honestly from being
    /// forwarded silently in Block mode. The cap stays comfortably above
    /// <c>NormalizedFileName.MaximumSafeLength</c> (255) so <c>UnsafeFileNameRule</c> can still
    /// report <c>excessiveLength</c>.
    /// </para>
    /// </remarks>
    public const int MaximumFileNameLength = 1024;

    /// <summary>
    /// Longest <c>name</c> parameter carried into an <see cref="InspectedUpload"/>. Truncated
    /// silently.
    /// </summary>
    /// <remarks>
    /// Silent, unlike the file-name cap, because the asymmetry is real: no rule matches against a
    /// field name, so truncating one cannot erase a detection the way chopping <c>.php</c> off a
    /// file name can. The cap exists only to bound what is retained per part.
    /// </remarks>
    public const int MaximumFieldNameLength = 1024;

    /// <summary>
    /// Longest per-part <c>Content-Type</c> carried into an <see cref="InspectedUpload"/>.
    /// Truncated silently.
    /// </summary>
    /// <remarks>
    /// The declared type is a claim, never evidence, and the content rules already reduce anything
    /// over 100 characters to an opaque token — so a value truncated at 256 reaches exactly the
    /// same verdict as the untruncated one, while bounding what a hostile header can make the
    /// gateway retain across a whole request.
    /// </remarks>
    public const int MaximumDeclaredContentTypeLength = 256;

    /// <summary>
    /// Headers permitted on one part, passed to <c>MultipartReader.HeadersCountLimit</c>.
    /// </summary>
    /// <remarks>
    /// This is the framework default, set explicitly on purpose: the value is then a decision in
    /// WPShield's source that a reviewer can argue with, rather than an inherited accident that a
    /// framework update can change underneath the gateway. A legitimate file part carries two or
    /// three headers.
    /// </remarks>
    public const int PartHeaderCountLimit = 16;

    /// <summary>
    /// Scratch buffer used to read and discard everything past the sample.
    /// </summary>
    /// <remarks>
    /// One 8 KiB array is rented per <see cref="ReadAsync"/> call and reused for every part, so the
    /// discard costs a fixed 8 KiB regardless of how large the upload is. It is a bucket size for
    /// <see cref="ArrayPool{T}"/> and sits well below the 85,000-byte large-object-heap threshold.
    /// </remarks>
    private const int DrainScratchBytes = 8 * 1024;

    private static readonly SearchValues<char> BoundaryCharacters = SearchValues.Create(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=? ");

    /// <summary>
    /// The characters that end the media type inside a <c>Content-Type</c> value.
    /// </summary>
    /// <remarks>
    /// <c>;</c> and <c>,</c> and space are exactly what PHP's <c>sapi_read_post_data</c> terminates
    /// on before it looks the type up in <c>known_post_content_types</c>. HTAB is added because PHP
    /// does <i>not</i> terminate on it — <c>multipart/form-data\t;boundary=x</c> reaches PHP as the
    /// unknown type <c>multipart/form-data\t</c> and never populates <c>$_FILES</c> — and the
    /// direction WPShield must err in is inspecting a request the backend will ignore, never
    /// ignoring one the backend will act on.
    /// </remarks>
    private static readonly SearchValues<char> MediaTypeTerminators = SearchValues.Create("; ,\t");

    /// <summary>
    /// Whether the request claims to be <c>multipart/form-data</c> at all, regardless of whether a
    /// usable boundary can be extracted from it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The caller needs this separately from <see cref="TryGetBoundary"/> because "declared
    /// multipart but the boundary is unusable" and "not multipart at all" must not be confused. The
    /// first is a finding — the gateway fails closed on a body it cannot parse — and the second is
    /// ordinary traffic that keeps streaming through untouched. Collapsing them either blocks every
    /// GET or hands an attacker a bypass, depending on which way they collapse.
    /// </para>
    /// <para>
    /// <b>The match is textual, and that is the whole point.</b> This used to ask
    /// <c>MediaTypeHeaderValue.TryParse</c>, which is a strict whole-value parser and treats a comma
    /// as a value separator — so <c>multipart/form-data; boundary=aaa,</c> answered
    /// <see langword="false"/> here <i>and</i> <see langword="false"/> in
    /// <see cref="TryGetBoundary"/>, and the fail-closed pairing in <c>UploadInspectionService</c>
    /// concluded "not multipart at all". The request then streamed through with no rule running and
    /// no buffer, while PHP took <c>boundary_end = strpbrk(boundary, ",;")</c>, got <c>aaa</c>, and
    /// wrote <c>$_FILES</c>. One trailing comma was a complete bypass of every rule WPShield ships.
    /// A strict parser may decide whether a value is <i>usable</i>; it must never decide whether the
    /// request is <i>in scope</i>.
    /// </para>
    /// <para>
    /// <b>What must match</b>, because each one can become an upload on the backend:
    /// <c>multipart/form-data; boundary=x</c> and <c>multipart/form-data;boundary=x</c> (ordinary
    /// traffic); <c>MULTIPART/FORM-DATA; …</c> (HTTP media types are case-insensitive and PHP
    /// lowercases before its lookup); a bare <c>multipart/form-data</c> with no boundary (declared,
    /// unusable, therefore a finding); <c>multipart/form-data ; …</c> and
    /// <c>multipart/form-data\t; …</c>; and every comma form —
    /// <c>…boundary=aaa,</c>, <c>…boundary=aaa,bbb</c>, <c>…boundary=aaa, application/json</c> —
    /// which are the F3 bypass and now reach <see cref="MultipartReadStatus.Malformed"/>.
    /// </para>
    /// <para>
    /// <b>What must not match</b>, because matching it would buffer and possibly refuse ordinary
    /// traffic: <c>application/json</c>, <c>application/x-www-form-urlencoded</c> and every other
    /// unrelated type; <c>application/json; x=multipart/form-data</c>, which is why this compares
    /// the leading token for equality instead of searching the value for a substring;
    /// <c>multipart/form-data-x</c> and <c>multipart/form-datax</c>, which is why it compares the
    /// whole token instead of using <c>StartsWith</c> — PHP's hash lookup is an exact match too, so
    /// neither reaches <c>rfc1867_post_handler</c>; <c>multipart/mixed</c> and
    /// <c>multipart/related</c>, out of scope per <see cref="MultipartFormData"/>; and a quoted
    /// <c>"multipart/form-data"</c>, which PHP's lookup also misses.
    /// </para>
    /// </remarks>
    /// <param name="request">The inbound request.</param>
    /// <returns>
    /// <see langword="true"/> when any <c>Content-Type</c> header line names
    /// <c>multipart/form-data</c> as its media type. Duplicate headers are all examined, because a
    /// request that declares multipart in its second <c>Content-Type</c> line has still declared it.
    /// </returns>
    public static bool DeclaresMultipartFormData(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        foreach (var value in request.Headers.ContentType)
        {
            if (NamesMultipartFormData(value))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Whether one raw <c>Content-Type</c> value names <c>multipart/form-data</c> as its media type.
    /// </summary>
    private static bool NamesMultipartFormData(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        // Leading optional whitespace is stripped by Kestrel in practice, but this method's answer
        // decides whether a request is inspected at all, so it does not depend on somebody else
        // having normalised the value first.
        var remainder = value.AsSpan().TrimStart(" \t");
        var terminator = remainder.IndexOfAny(MediaTypeTerminators);
        var mediaType = terminator < 0 ? remainder : remainder[..terminator];

        return mediaType.Equals(MultipartFormData, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Extracts the multipart boundary, accepting only a form the gateway and the backend cannot
    /// disagree about.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every condition below is a fail-closed check, and the method never throws on a malformed
    /// header — a hostile <c>Content-Type</c> must produce a <see langword="false"/> the caller
    /// turns into <see cref="MultipartReadStatus.Malformed"/>, not an exception that unwinds the
    /// request pipeline.
    /// </para>
    /// <list type="number">
    /// <item>
    /// <description>
    /// <b>Exactly one <c>Content-Type</c> header line.</b> Kestrel does not reject duplicates, and
    /// <c>HttpRequest.ContentType</c> joins them with <c>", "</c>. Two <c>Content-Type</c> lines is
    /// a classic parser-differential probe: IIS, ARR and PHP need not agree on whether the first or
    /// the last one wins, and if WPShield parses one while the backend parses the other, WPShield
    /// has inspected a different request than the one that executes.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>Media type exactly <c>multipart/form-data</c></b>, ordinal case-insensitive. See
    /// <see cref="MultipartFormData"/> for why the other subtypes are out of scope.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>Exactly one <c>boundary</c> parameter, and no second thing in the value that PHP will
    /// read as one.</b> See <see cref="HasAmbiguousBoundaryParameter"/>: this is the same
    /// differential as a doubled <c>filename</c>, in the header that decides how the whole body is
    /// framed.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>A <c>boundary</c> parameter, dequoted.</b> <c>MediaTypeHeaderValue.Boundary</c> returns
    /// the raw segment including quotes, and RFC 2046 requires quoting when the boundary contains a
    /// space, so dequoting is not optional.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>1 to <see cref="MaximumBoundaryLength"/> characters</b> after dequoting.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>RFC 2046 <c>bchars</c> only</b>, with a space forbidden in the final position. This is
    /// the check that matters most: it rejects CR, LF, <c>"</c>, <c>;</c> and <c>\</c> outright, so
    /// a boundary can never carry header-injection structure into the parser.
    /// </description>
    /// </item>
    /// </list>
    /// <para>
    /// The value is returned <b>without</b> a leading <c>--</c>. <see cref="MultipartReader"/>
    /// prepends the delimiter itself; passing <c>--boundary</c> produces a reader that matches
    /// nothing and reports a clean, empty, malformed-looking body — a silent false negative that is
    /// very hard to spot in review.
    /// </para>
    /// </remarks>
    /// <param name="request">The inbound request.</param>
    /// <param name="options">
    /// The active bounds. No property is read today — the boundary grammar is fixed by RFC 2046
    /// rather than by configuration — but the parameter is part of the fixed cross-agent signature,
    /// so a future boundary policy becomes a change of behaviour rather than a change of contract.
    /// </param>
    /// <param name="boundary">
    /// The dequoted boundary, or <see cref="string.Empty"/> when the method returns
    /// <see langword="false"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the request declares <c>multipart/form-data</c> and a usable
    /// boundary was extracted.
    /// </returns>
    public static bool TryGetBoundary(
        HttpRequest request,
        MultipartInspectionOptions options,
        out string boundary)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);

        boundary = string.Empty;

        var contentTypes = request.Headers.ContentType;
        if (contentTypes.Count != 1)
        {
            return false;
        }

        var declared = contentTypes[0];
        if (string.IsNullOrEmpty(declared) ||
            !MediaTypeHeaderValue.TryParse(declared, out var mediaType) ||
            !mediaType.MediaType.Equals(MultipartFormData, StringComparison.OrdinalIgnoreCase) ||
            HasAmbiguousBoundaryParameter(declared, mediaType))
        {
            return false;
        }

        var candidate = HeaderUtilities.RemoveQuotes(mediaType.Boundary);
        if (!candidate.HasValue || candidate.Length == 0 || candidate.Length > MaximumBoundaryLength)
        {
            return false;
        }

        var value = candidate.ToString();
        if (value.AsSpan().ContainsAnyExcept(BoundaryCharacters) || value[^1] == ' ')
        {
            return false;
        }

        boundary = value;
        return true;
    }

    /// <summary>
    /// Reads bounded metadata and a bounded leading sample from each file part of an
    /// already-buffered multipart body.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Never to disk, never a whole file.</b> Each part is read twice over: at most
    /// <see cref="MultipartInspectionOptions.SampleBytes"/> into a pooled scratch array, which is
    /// copied into a right-sized array owned by the returned <see cref="InspectedUpload"/>, and
    /// then the remainder into a fixed 8 KiB scratch array that is overwritten and discarded. That
    /// second pass exists only so <see cref="InspectedUpload.ByteCount"/> is exact: the gateway
    /// learns how large the upload was without ever holding it.
    /// </para>
    /// <para>
    /// <b>Pooled buffers never escape.</b> Both scratch arrays are rented from
    /// <see cref="ArrayPool{T}"/> and returned in a <c>finally</c>, so they come back on every exit
    /// path including cancellation and a malformed body. The sample is copied out before the
    /// rental is returned rather than being exposed as a window onto the pooled array: handing the
    /// caller a <see cref="ReadOnlyMemory{T}"/> over a returned rental is a use-after-return, and
    /// the array's next tenant is a different concurrent request, so the bug would present as one
    /// request's upload appearing in another request's evidence.
    /// </para>
    /// <para>
    /// <b>Errors do not escape; cancellation does.</b> A malformed body becomes
    /// <see cref="MultipartReadStatus.Malformed"/> and an exhausted limit becomes
    /// <see cref="MultipartReadStatus.LimitExceeded"/> — neither throws, because both are ordinary
    /// policy outcomes the caller has to act on rather than failures. Cancellation is the
    /// exception: if <paramref name="cancellationToken"/> fires, the
    /// <see cref="OperationCanceledException"/> propagates so the caller can tell a disconnected
    /// client from a slow one. Only this method's own deadline is converted, into
    /// <see cref="MultipartReadStatus.TimedOut"/>.
    /// </para>
    /// <para>
    /// <b>Partial results are kept.</b> When a limit is hit or the body turns out to be malformed
    /// part-way through, the files read so far are still returned and still inspected. The status
    /// constrains what the caller may do with the request; it does not discard what was learned.
    /// </para>
    /// <para>
    /// <b><see cref="MultipartReadStatus.Complete"/> means the parse reached the end of the
    /// body</b>, which is not the same thing as <c>MultipartReader</c> having stopped, and the
    /// difference was a complete bypass. Every byte therefore passes through a
    /// <see cref="ClosingDelimiterAudit"/> on its way to the parser, and anything the parser never
    /// asked for is pulled through the audit afterwards. It is <b>not</b> inferred from the stream
    /// position: <c>MultipartReader</c> wraps the stream in a <c>BufferedReadStream</c> that reads
    /// ahead, so a body whose parse consumed 5 of 223 bytes still leaves the position at 223.
    /// </para>
    /// </remarks>
    /// <param name="seekableBody">
    /// The buffered body, positioned at the start of the multipart content. Read forward only; the
    /// position on return is undefined and the caller must rewind before forwarding.
    /// </param>
    /// <param name="boundary">The dequoted boundary from <see cref="TryGetBoundary"/>, with no leading <c>--</c>.</param>
    /// <param name="options">
    /// The active bounds. Every value is clamped to its <c>Absolute…</c> ceiling here as well as at
    /// startup, so an options instance that never met the validator cannot raise a ceiling.
    /// </param>
    /// <param name="cancellationToken">
    /// The request's cancellation token — normally <c>HttpContext.RequestAborted</c>. The read
    /// deadline is linked to it rather than replacing it, so a client that disconnects mid-parse
    /// stops the work immediately instead of waiting out the timeout.
    /// </param>
    /// <returns>What was found, and how far the read got.</returns>
    public async ValueTask<MultipartInspectionOutcome> ReadAsync(
        Stream seekableBody,
        string boundary,
        MultipartInspectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(seekableBody);
        ArgumentException.ThrowIfNullOrEmpty(boundary);
        ArgumentNullException.ThrowIfNull(options);

        var sampleBytes = Math.Clamp(
            options.SampleBytes,
            MultipartInspectionOptions.MinimumSampleBytes,
            MultipartInspectionOptions.AbsoluteMaximumSampleBytes);
        var maximumFiles = Math.Clamp(
            options.MaximumFileCount, 1, MultipartInspectionOptions.AbsoluteMaximumFileCount);
        var maximumFields = Math.Clamp(
            options.MaximumFieldCount, 1, MultipartInspectionOptions.AbsoluteMaximumFieldCount);
        var partHeaderBytes = Math.Clamp(
            options.MaximumPartHeaderBytes, 1, MultipartInspectionOptions.AbsoluteMaximumPartHeaderBytes);
        var timeoutSeconds = Math.Clamp(
            options.ReadTimeoutSeconds, 1, MultipartInspectionOptions.AbsoluteMaximumReadTimeoutSeconds);

        // Linked, not standalone. The deadline bounds how long one request may hold a pooled buffer;
        // the caller's token is how a closed browser tab stops the work at once. Replacing the
        // caller's token with a timeout would keep parsing for a client that has already gone.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var files = new List<InspectedUpload>();
        var fieldCount = 0;
        var fileCount = 0;
        var status = MultipartReadStatus.Complete;

        var sampleScratch = ArrayPool<byte>.Shared.Rent(sampleBytes);
        var drainScratch = ArrayPool<byte>.Shared.Rent(DrainScratchBytes);

        try
        {
            // Every byte the parser pulls passes through the audit first. See ClosingDelimiterAudit
            // for what it watches for and why the check cannot be inferred from the stream position.
            using var audited = new ClosingDelimiterAudit(seekableBody, boundary);

            // BodyLengthLimit stays null on purpose. It bounds each individual section, and the
            // source stream is already bounded by Gateway:MaximumRequestBytes before a byte of it
            // was buffered, so a per-part number buys no additional guarantee and creates a second
            // value to keep in sync with the first. The reader's buffer size stays at the framework
            // default of 4096: it only has to be large enough to hold a boundary, and TryGetBoundary
            // caps that at 70 characters.
            var reader = new MultipartReader(boundary, audited)
            {
                HeadersCountLimit = PartHeaderCountLimit,
                HeadersLengthLimit = partHeaderBytes,
                BodyLengthLimit = null
            };

            while (true)
            {
                var section = await reader.ReadNextSectionAsync(deadline.Token);
                if (section is null)
                {
                    break;
                }

                // Before the disposition is parsed, not after: the whole point of an obs-fold is
                // that the smuggled filename never reaches disposition.Parameters, so by the time
                // GetContentDispositionHeader() has answered there is nothing left to notice.
                if (HasFoldedPartHeader(section.Headers))
                {
                    status = MultipartReadStatus.Malformed;
                    break;
                }

                var disposition = section.GetContentDispositionHeader();

                // Fail closed on a part whose Content-Disposition we cannot read the same way the
                // backend will. An absent header is not form-data at all; a header with two
                // filename parameters is a differential, because this parser takes the first and
                // PHP's takes the last, so the two of us would inspect and write different names.
                if (disposition is null || HasRepeatedFileNameParameter(disposition))
                {
                    status = MultipartReadStatus.Malformed;
                    break;
                }

                var declaredName = Dequote(disposition.FileName);
                var extendedName = Dequote(disposition.FileNameStar);

                // No filename parameter at all: a form field. Counted, never sampled, never
                // inspected — see MultipartInspectionOutcome.FieldCount for why that is a
                // correctness requirement rather than an optimisation. The body is left unread;
                // ReadNextSectionAsync drains the previous section before it advances.
                if (declaredName is null && extendedName is null)
                {
                    if (fieldCount >= maximumFields)
                    {
                        status = MultipartReadStatus.LimitExceeded;
                        break;
                    }

                    fieldCount++;
                    continue;
                }

                // Sticky, not terminal: a name too long to carry honestly is a finding, but the
                // remaining parts are still worth inspecting.
                var nameTruncated = CapFileName(ref declaredName);
                nameTruncated |= CapFileName(ref extendedName);
                if (nameTruncated)
                {
                    status = MultipartReadStatus.LimitExceeded;
                }

                var sampleLength = await FillAsync(
                    section.Body, sampleScratch, sampleBytes, deadline.Token);

                // Copy out of the rental now. The array goes back to the pool in the finally below,
                // and InspectedUpload outlives this method.
                var sample = new ReadOnlyMemory<byte>(sampleScratch.AsSpan(0, sampleLength).ToArray());
                var byteCount = sampleLength + await DiscardRemainderAsync(
                    section.Body, drainScratch, deadline.Token);

                // An empty filename over an empty body is an unselected <input type="file">.
                // Browsers send exactly this for every empty file input on a submitted form, and
                // PHP records UPLOAD_ERR_NO_FILE and writes nothing. Without this rule
                // UnsafeFileNameRule scores 60 for emptyAfterNormalization on routine WordPress
                // admin traffic — a false positive on the first day of real use. An empty name over
                // a non-empty body is a different thing entirely, and stays a file.
                if (byteCount == 0 && IsEmpty(declaredName) && IsEmpty(extendedName))
                {
                    if (fieldCount >= maximumFields)
                    {
                        status = MultipartReadStatus.LimitExceeded;
                        break;
                    }

                    fieldCount++;
                    continue;
                }

                // The limit is counted per part, not per emitted name, so a part that carries two
                // disagreeing names still costs one file. The part that trips the limit is read but
                // never inspected: stopping here is what makes "the reader gave up" impossible to
                // convert into "the reader waved it through".
                if (fileCount >= maximumFiles)
                {
                    status = MultipartReadStatus.LimitExceeded;
                    break;
                }

                fileCount++;

                var fieldName = Truncate(Dequote(disposition.Name), MaximumFieldNameLength);
                var declaredContentType = Truncate(section.ContentType, MaximumDeclaredContentTypeLength);

                // filename first: that is the name PHP acts on, so it is the one an operator reading
                // findings in body order should meet first.
                files.Add(new InspectedUpload(
                    fieldName, declaredName ?? extendedName, declaredContentType, sample, byteCount));

                if (declaredName is not null &&
                    extendedName is not null &&
                    !string.Equals(declaredName, extendedName, StringComparison.Ordinal))
                {
                    files.Add(new InspectedUpload(
                        fieldName, extendedName, declaredContentType, sample, byteCount));
                }
            }

            // Complete has to mean "the parse reached the end of the body", and until now it only
            // meant "MultipartReader stopped". Those differ the moment a closing delimiter appears
            // anywhere but the end, so the audit gets to see the whole body before Complete is
            // allowed to stand. Only on the Complete path: every other status is already a finding,
            // and reading the tail to confirm a finding we have would be work for nothing.
            if (status == MultipartReadStatus.Complete)
            {
                // MultipartReader stops at the closing delimiter and its buffered read-ahead may
                // have stopped well before the end of the body, so the bytes it never asked for are
                // pulled through the audit here. They go through the same fixed 8 KiB scratch as
                // any other discard, and the body is already whole in memory, so this is a memory
                // walk of a length Gateway:MaximumRequestBytes has already bounded.
                await DiscardRemainderAsync(audited, drainScratch, deadline.Token);

                if (audited.SawDelimiterAfterClose)
                {
                    status = MultipartReadStatus.Malformed;
                }
            }
        }
        catch (InvalidDataException)
        {
            // The framework parser's verdict on a body that is not valid multipart, and on a part
            // whose headers overflowed HeadersLengthLimit or HeadersCountLimit. Both produce the
            // same policy, so they are deliberately not told apart by string-matching the message —
            // and neither the message nor any part of the body is ever logged.
            status = MultipartReadStatus.Malformed;
        }
        catch (IOException exception) when (exception is not RequestBodyTooLargeException)
        {
            // A body that ends mid-part reaches the caller as an unexpected end of stream rather
            // than as InvalidDataException. It is the same finding: we could not parse what was
            // sent. RequestBodyTooLargeException is excluded because it is not a parse failure —
            // it is the size limit reporting itself, and it belongs to the 413 path.
            status = MultipartReadStatus.Malformed;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Our own deadline, not the caller's cancellation. The filter is what keeps the
            // distinction: a client that disconnected leaves the caller's token cancelled, does not
            // match here, and the exception propagates so the caller can log a disconnect instead of
            // answering a connection that is already gone.
            status = MultipartReadStatus.TimedOut;
        }
        finally
        {
            // No clearArray. The scratch arrays are written before they are read on every path —
            // FillAsync only exposes the prefix it filled, and the discard buffer is never read at
            // all — so zeroing them would be real CPU on every request for no confidentiality gain.
            ArrayPool<byte>.Shared.Return(sampleScratch);
            ArrayPool<byte>.Shared.Return(drainScratch);
        }

        return new MultipartInspectionOutcome(files, fieldCount, status);
    }

    /// <summary>
    /// Fills <paramref name="scratch"/> with up to <paramref name="count"/> leading bytes of the
    /// part, tolerating short reads.
    /// </summary>
    /// <remarks>
    /// A single <c>ReadAsync</c> may legitimately return fewer bytes than asked for, and treating
    /// that as end-of-part would hand the content rules a sample that stops in the middle of a
    /// magic-byte signature. Looping until the buffer is full or the part genuinely ends is what
    /// makes the sample deterministic.
    /// </remarks>
    private static async ValueTask<int> FillAsync(
        Stream body,
        byte[] scratch,
        int count,
        CancellationToken cancellationToken)
    {
        var filled = 0;
        while (filled < count)
        {
            var read = await body.ReadAsync(scratch.AsMemory(filled, count - filled), cancellationToken);
            if (read == 0)
            {
                break;
            }

            filled += read;
        }

        return filled;
    }

    /// <summary>
    /// Reads and throws away everything left in the part, returning how many bytes there were.
    /// </summary>
    /// <remarks>
    /// This is the whole reason <see cref="InspectedUpload.ByteCount"/> can be exact without the
    /// upload being retained: the bytes pass through one fixed 8 KiB array that is overwritten on
    /// every iteration and never read. A 6 MiB upload costs 6 MiB of reads and 8 KiB of memory.
    /// </remarks>
    private static async ValueTask<long> DiscardRemainderAsync(
        Stream body,
        byte[] scratch,
        CancellationToken cancellationToken)
    {
        long discarded = 0;
        while (true)
        {
            var read = await body.ReadAsync(scratch, cancellationToken);
            if (read == 0)
            {
                break;
            }

            discarded += read;
        }

        return discarded;
    }

    /// <summary>
    /// Detects a <c>Content-Disposition</c> that names the file more than once.
    /// </summary>
    /// <remarks>
    /// <c>filename="a.jpg"; filename="shell.php"</c> is not a client mistake, it is a probe. The
    /// header parser used here returns the first match while PHP's multipart handler keeps the
    /// last, so accepting it would mean inspecting one name and letting the backend write another.
    /// Nothing legitimate repeats the parameter, so refusing to parse it costs nothing.
    /// </remarks>
    private static bool HasRepeatedFileNameParameter(ContentDispositionHeaderValue disposition)
    {
        var fileNames = 0;
        var extendedFileNames = 0;

        foreach (var parameter in disposition.Parameters)
        {
            if (StringSegment.Equals(parameter.Name, "filename", StringComparison.OrdinalIgnoreCase))
            {
                fileNames++;
            }
            else if (StringSegment.Equals(parameter.Name, "filename*", StringComparison.OrdinalIgnoreCase))
            {
                extendedFileNames++;
            }
        }

        return fileNames > 1 || extendedFileNames > 1;
    }

    /// <summary>
    /// Detects a <c>Content-Type</c> whose boundary the gateway and PHP would read differently.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <see cref="HasRepeatedFileNameParameter"/> applied one level up. A doubled
    /// <c>filename</c> makes the two ends disagree about one file; a doubled — or merely
    /// PHP-visible — <c>boundary</c> makes them disagree about where every part of the body begins,
    /// which is worse. Confirmed with a probe: one body can be valid multipart under two different
    /// boundaries at once, presenting <c>photo.jpg</c> to the reading WPShield takes and
    /// <c>shell.php</c> to the reading PHP takes.
    /// </para>
    /// <para>
    /// Two shapes are refused.
    /// </para>
    /// <list type="number">
    /// <item>
    /// <description>
    /// <b>More than one <c>boundary</c> parameter.</b>
    /// <c>boundary=aaa; boundary=bbb</c> — <c>MediaTypeHeaderValue.Boundary</c> returns the first
    /// match, and nothing says IIS, ARR and PHP agree with it.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <b>More assignable <c>boundary</c> tokens in the raw value than there are real parameters.</b>
    /// <c>xboundary=bbb; boundary=aaa</c> parses as one parameter named <c>xboundary</c> and one
    /// named <c>boundary</c>, so WPShield gets <c>aaa</c> — but PHP does
    /// <c>strstr(content_type, "boundary")</c>, which matches inside <c>xboundary</c>, then
    /// <c>strchr(…, '=')</c>, and gets <c>bbb</c>. No parameter parser can see that, so the check
    /// is textual.
    /// </description>
    /// </item>
    /// </list>
    /// <para>
    /// <b>The false positives, stated honestly.</b> Requiring a <c>=</c> after the token is what
    /// keeps <c>boundary=boundary</c> and <c>boundary="boundary"</c> acceptable: the second
    /// occurrence is a value, PHP reads the same boundary WPShield does, and a client that picks the
    /// literal string <c>boundary</c> as its delimiter is unusual but not hostile. What is still
    /// refused without a differential behind it is a decoy that appears <i>after</i> the real
    /// parameter — <c>boundary=aaa; xboundary=bbb</c> — where PHP's <c>strstr</c> finds the real one
    /// first and agrees with us. Counting occurrences cannot tell the two orders apart without
    /// re-implementing PHP's scan, and imitating PHP's parser is an arms race this gateway loses, so
    /// the ordering costs a 415 in Block mode for a request no real client sends.
    /// </para>
    /// </remarks>
    private static bool HasAmbiguousBoundaryParameter(string declared, MediaTypeHeaderValue mediaType)
    {
        var parameters = 0;
        foreach (var parameter in mediaType.Parameters)
        {
            if (StringSegment.Equals(parameter.Name, "boundary", StringComparison.OrdinalIgnoreCase))
            {
                parameters++;
            }
        }

        return parameters > 1 || CountAssignableBoundaryTokens(declared) > parameters;
    }

    /// <summary>
    /// Counts the occurrences of the literal <c>boundary</c> that PHP's <c>strstr</c> plus
    /// <c>strchr(…, '=')</c> pair would accept as a boundary declaration.
    /// </summary>
    /// <remarks>
    /// Overlapping matches are counted by advancing one character at a time rather than by the
    /// token length, because the point is to find every position PHP's scan could land on, not to
    /// tokenize the header. The value is a header line, so the walk is bounded by Kestrel's header
    /// size limit and runs once per multipart request.
    /// </remarks>
    private static int CountAssignableBoundaryTokens(string declared)
    {
        const string Token = "boundary";

        var count = 0;
        var index = 0;

        while (index < declared.Length)
        {
            var found = declared.AsSpan(index).IndexOf(Token, StringComparison.OrdinalIgnoreCase);
            if (found < 0)
            {
                break;
            }

            var cursor = index + found + Token.Length;
            while (cursor < declared.Length && declared[cursor] is ' ' or '\t')
            {
                cursor++;
            }

            if (cursor < declared.Length && declared[cursor] == '=')
            {
                count++;
            }

            index += found + 1;
        }

        return count;
    }

    /// <summary>
    /// Detects a part header line that ASP.NET Core and PHP read as two different things.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the obs-fold differential, and it is worth spelling out because the two parsers are
    /// each doing something defensible. A part header line beginning with SP or HTAB is a folded
    /// continuation of the previous header under RFC 5322, and PHP's <c>multipart_buffer_headers</c>
    /// implements exactly that — <c>/* space in the beginning means same header */</c> — appending
    /// the line to the previous value and then keeping the <b>last</b> <c>filename</c> it finds.
    /// <c>MultipartReader.ReadHeadersAsync</c> has no concept of folding: it splits every line at
    /// the first colon regardless of what precedes it, so
    /// </para>
    /// <code>
    /// Content-Disposition: form-data; name="f"
    ///  ; filename="shell.php" : x
    /// </code>
    /// <para>
    /// reaches this reader as an untouched <c>Content-Disposition</c> plus a junk header whose
    /// <i>name</i> is <c>&#32;; filename="shell.php"&#32;</c>. The smuggled parameter never enters
    /// <c>disposition.Parameters</c>, so <see cref="HasRepeatedFileNameParameter"/> cannot see it:
    /// measured, WPShield reported a form field — never sampled, never inspected — while PHP wrote
    /// <c>$_FILES['f']</c> with <c>shell.php</c>. With a benign <c>filename="photo.jpg"</c> left on
    /// the first line it is worse, because WPShield inspects and passes a file that is not the one
    /// the backend writes. A tab folds identically. The trailing <c>&#32;: x</c> exists only to give
    /// ASP.NET Core a colon to split on; without it the reader already fails closed.
    /// </para>
    /// <para>
    /// So the test is on the header <i>name</i>, not on the disposition: a name the framework
    /// produced that begins with SP or HTAB is a line the backend is going to fold and we are not.
    /// An empty name is refused with it — that is a line whose first character was the colon, which
    /// no client sends and whose header we therefore cannot name at all. Nothing legitimate reaches
    /// either branch: a real part carries <c>Content-Disposition</c>, sometimes
    /// <c>Content-Type</c>, occasionally a transfer encoding, none of them folded.
    /// </para>
    /// </remarks>
    private static bool HasFoldedPartHeader(IDictionary<string, StringValues>? headers)
    {
        if (headers is null)
        {
            return false;
        }

        foreach (var name in headers.Keys)
        {
            if (name.Length == 0 || name[0] is ' ' or '\t')
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns the parameter value with its surrounding quotes removed, or <see langword="null"/>
    /// when the parameter was absent.
    /// </summary>
    /// <remarks>
    /// The distinction between absent and empty is load-bearing: absent means "this part is a form
    /// field", while empty means "this part is a file input the user left blank". They are counted
    /// differently and only one of them can turn into an upload.
    /// </remarks>
    private static string? Dequote(StringSegment value)
    {
        return value.HasValue ? HeaderUtilities.RemoveQuotes(value).ToString() : null;
    }

    /// <summary>
    /// Truncates a file name to <see cref="MaximumFileNameLength"/>, reporting whether it had to.
    /// </summary>
    private static bool CapFileName(ref string? name)
    {
        if (name is null || name.Length <= MaximumFileNameLength)
        {
            return false;
        }

        name = name[..MaximumFileNameLength];
        return true;
    }

    /// <summary>
    /// Truncates an attacker-controlled string that carries no detection signal, silently.
    /// </summary>
    private static string? Truncate(string? value, int maximumLength)
    {
        return value is null || value.Length <= maximumLength ? value : value[..maximumLength];
    }

    private static bool IsEmpty(string? value)
    {
        return value is null or { Length: 0 };
    }

    /// <summary>
    /// A read-only pass-through over the body that answers one question: did a delimiter appear
    /// after the closing delimiter?
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The attack.</b> Prefix a body with a single closing delimiter line:
    /// </para>
    /// <code>
    /// --X--
    /// --X
    /// Content-Disposition: form-data; name="f"; filename="shell.php"
    ///
    /// &lt;?php … ?&gt;
    /// --X--
    /// </code>
    /// <para>
    /// <c>MultipartReaderStream</c> finds <c>--X</c> at offset 0, sees the trailing <c>--</c>, sets
    /// <c>FinalBoundaryFound</c> and hands back <see langword="null"/> on the very first
    /// <c>ReadNextSectionAsync</c>. Measured, the whole body reported <c>Complete</c> with zero
    /// fields and zero files, scored 0, and was forwarded in Block mode with nothing above
    /// Information in the log. PHP has no concept of a terminating boundary at all —
    /// <c>find_boundary</c> reads lines until one matches <c>--X</c>, and
    /// <c>multipart_buffer_headers</c> drops lines without a colon — so PHP parses the smuggled part
    /// and writes <c>$_FILES['f']</c>. Every byte the gateway inspected was a byte the backend
    /// ignored, and vice versa. The same shape works with the stray closing delimiter in the middle
    /// of an otherwise ordinary body, where it hides every part after a benign first one.
    /// </para>
    /// <para>
    /// <b>Why a pass-through and not a rescan.</b> The audit has to see the bytes the parser
    /// consumed, and the parser consumes them through a <c>BufferedReadStream</c> that has already
    /// read past them — so there is no position to rescan from, and the stream position cannot
    /// stand in for "how far the parse got". Watching the reads is also the only form of the check
    /// that keeps <see cref="ReadAsync"/> working against a forward-only stream and reads the body
    /// once.
    /// </para>
    /// <para>
    /// <b>Cost, because this runs on every multipart request.</b> One byte-oriented state machine
    /// with no allocation past a delimiter array of at most 72 bytes, over a body
    /// <c>Gateway:MaximumRequestBytes</c> has already bounded to 6 MiB by default. It is not a
    /// second pass: it rides the pass the parser was making anyway, apart from the tail
    /// <see cref="ReadAsync"/> pulls when the parse stopped before the end. A delimiter can only
    /// begin at a line start, so outside a candidate match the scan jumps to the next CR or LF with
    /// a vectorized <c>IndexOfAny</c> and never touches the bytes between — file content costs a
    /// <c>memchr</c>, not a branch per byte. There is no backtracking and no window buffer: a failed
    /// match cannot hide a line start, because a delimiter contains neither CR nor LF.
    /// </para>
    /// <para>
    /// Measured on this repository's runtime, a full 6 MiB upload takes about 3.5 ms through
    /// <see cref="ReadAsync"/> with the audit in place. The worst input for it is a 6 MiB body of
    /// nothing but CRLF, which defeats the skip and forces the state machine to step every byte:
    /// about 16 ms, one linear pass, no allocation, and still bounded by the same request ceiling.
    /// An attacker gets a small constant multiple of the work the gateway was already doing to read
    /// their upload — not a new amplification surface.
    /// </para>
    /// <para>
    /// <b>What is deliberately still allowed.</b> A prose epilogue after the closing delimiter is
    /// legal under RFC 2046 §5.1.1 and real clients send one, so only a <i>delimiter</i> after the
    /// close is refused, not any trailing bytes. And a delimiter counts only at a line start — the
    /// body's first byte, or a byte after CR or LF — which is a superset of what
    /// <c>MultipartReaderStream</c> requires (a leading CRLF) and of what PHP's line-oriented
    /// <c>find_boundary</c> requires (a leading LF), so it cannot miss an occurrence either parser
    /// would act on. Requiring the line start is what keeps a file whose own bytes happen to contain
    /// the client's boundary mid-line from being called malformed.
    /// </para>
    /// </remarks>
    private sealed class ClosingDelimiterAudit : Stream
    {
        private const byte Dash = (byte)'-';
        private const byte CarriageReturn = (byte)'\r';
        private const byte LineFeed = (byte)'\n';

        private readonly Stream _inner;

        /// <summary>
        /// <c>--</c> plus the boundary, encoded the same way <c>MultipartBoundary</c> encodes it, so
        /// the audit and the parser cannot disagree about which bytes are a delimiter.
        /// </summary>
        private readonly byte[] _delimiter;

        private bool _atLineStart = true;
        private int _matched;
        private int _trailingDashes;
        private bool _closed;
        private bool _delimiterAfterClose;
        private bool _positionMoved;

        public ClosingDelimiterAudit(Stream inner, string boundary)
        {
            _inner = inner;
            _delimiter = Encoding.UTF8.GetBytes("--" + boundary);
        }

        /// <summary>
        /// Whether a delimiter was observed after the body's closing delimiter — or whether the
        /// audit was made unverifiable by a seek.
        /// </summary>
        /// <remarks>
        /// A seek would leave a gap in what the audit saw, and an audit with a gap cannot claim the
        /// parse reached the end. Nothing seeks today — <c>MultipartReader</c> reads
        /// <c>Position</c> to record a section's offset and never assigns it, which
        /// <c>ReadAsync_NeitherSeeksNorRewinds</c> pins — so this is here for the framework update
        /// that changes that. It fails in the loud direction, turning every upload into a Monitor
        /// warning or a Block-mode 415 rather than quietly vouching for a body nobody watched.
        /// </remarks>
        public bool SawDelimiterAfterClose => _delimiterAfterClose || _positionMoved;

        public override bool CanRead => true;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set
            {
                _positionMoved = true;
                _inner.Position = value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ValidateBufferArguments(buffer, offset, count);

            var read = _inner.Read(buffer, offset, count);
            Observe(buffer.AsSpan(offset, read));
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _inner.ReadAsync(buffer, cancellationToken);
            Observe(buffer.Span[..read]);
            return read;
        }

        public override async Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            ValidateBufferArguments(buffer, offset, count);
            return await ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            _positionMoved = true;
            return _inner.Seek(offset, origin);
        }

        public override void Flush()
        {
        }

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        /// <summary>
        /// Does not dispose the body. The buffer belongs to the caller, which forwards it to
        /// WordPress after this method has returned; disposing it here would return its pooled
        /// chunks while the forwarder is still reading from them.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        private void Observe(ReadOnlySpan<byte> data)
        {
            if (_delimiterAfterClose)
            {
                return;
            }

            var index = 0;
            while (index < data.Length)
            {
                if (!_atLineStart && _matched == 0 && _trailingDashes == 0)
                {
                    // Nothing between here and the next line break can begin a delimiter, so skip
                    // to it instead of stepping. This is the branch that keeps a 6 MiB upload's
                    // worth of file content cheap.
                    var lineBreak = data[index..].IndexOfAny(CarriageReturn, LineFeed);
                    if (lineBreak < 0)
                    {
                        return;
                    }

                    index += lineBreak;
                }

                Observe(data[index]);
                if (_delimiterAfterClose)
                {
                    return;
                }

                index++;
            }
        }

        private void Observe(byte value)
        {
            if (_trailingDashes > 0)
            {
                // A full delimiter was just matched; two dashes after it make it the closing one.
                if (value == Dash)
                {
                    _trailingDashes--;
                    if (_trailingDashes == 0)
                    {
                        _closed = true;
                    }
                }
                else
                {
                    _trailingDashes = 0;
                }
            }
            else if (_matched > 0)
            {
                if (value == _delimiter[_matched])
                {
                    _matched++;
                    if (_matched == _delimiter.Length)
                    {
                        _matched = 0;
                        if (_closed)
                        {
                            _delimiterAfterClose = true;
                            return;
                        }

                        _trailingDashes = 2;
                    }
                }
                else
                {
                    // No backtracking is needed. Everything consumed by the failed match was a
                    // delimiter byte, and a delimiter holds no CR or LF, so no line start — and
                    // therefore no candidate the audit cares about — can be hiding inside it.
                    _matched = 0;
                }
            }
            else if (_atLineStart && value == _delimiter[0])
            {
                // The delimiter is "--" plus a boundary of at least one character, so a one-byte
                // match can never be a complete one.
                _matched = 1;
            }

            _atLineStart = value is CarriageReturn or LineFeed;
        }
    }
}
