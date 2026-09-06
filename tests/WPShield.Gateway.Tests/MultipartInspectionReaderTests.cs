using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using WPShield.Abstractions;
using WPShield.Rules.WordPress;

namespace WPShield.Gateway.Tests;

/// <summary>
/// Unit coverage for <see cref="MultipartInspectionReader"/>, the component that turns a buffered
/// <c>multipart/form-data</c> body into the bounded metadata the rules run against.
/// </summary>
/// <remarks>
/// <para>
/// These are deliberately not integration tests. Every interesting failure of this component is
/// invisible from outside the process: a boundary the gateway refuses to parse, a limit that stops
/// the read, a sample one byte short of a magic-byte signature, a file name carried through with a
/// trailing dot intact. Driving it over HTTP would mean inferring
/// <see cref="MultipartReadStatus"/> from a response code, which pins the gateway's policy mapping
/// rather than the reader's behaviour — and it is the reader's behaviour that decides what the
/// rules ever get to see. <c>SyntheticGatewayIntegrationTests</c> covers the policy half.
/// </para>
/// <para>
/// Bodies are assembled as raw bytes rather than through <c>MultipartFormDataContent</c>, because
/// half of what is asserted here is what happens to bodies <c>HttpClient</c> would refuse to
/// produce: a missing final delimiter, LF-only line endings, a part with no headers at all, a
/// <c>Content-Disposition</c> that names the file twice.
/// </para>
/// <para>
/// Markers are synthetic throughout. <c>&lt;?php echo 'synthetic marker';</c> is the established
/// one in this repository and it is inert; nothing here is a working webshell, and every host is a
/// placeholder.
/// </para>
/// </remarks>
public sealed class MultipartInspectionReaderTests
{
    private const string Boundary = "----WPShieldSyntheticBoundary";

    /// <summary>
    /// The synthetic PHP marker used wherever a test needs upload content that looks hostile
    /// without being hostile. It is echoed text, not a shell.
    /// </summary>
    private const string SyntheticPhpMarker = "<?php echo 'synthetic marker';";

    // =================================================================================================
    // 1. Well-formed bodies: every field of InspectedUpload, exactly
    // =================================================================================================

    /// <summary>
    /// The base case the whole pipeline rests on. If any one of these five values is wrong, a rule
    /// downstream is matching against something the backend will not receive.
    /// </summary>
    [Fact]
    public async Task SingleFile_ProducesExactMetadataAndSample()
    {
        var content = "GIF89a synthetic pixels"u8.ToArray();
        var body = new MultipartBodyBuilder()
            .File("async-upload", "photo.jpg", "image/jpeg", content)
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(0, outcome.FieldCount);
        var file = Assert.Single(outcome.Files);
        Assert.Equal("async-upload", file.FieldName);
        Assert.Equal("photo.jpg", file.FileName);
        Assert.Equal("image/jpeg", file.DeclaredContentType);
        Assert.Equal(content, file.Sample.ToArray());
        Assert.Equal(content.Length, file.ByteCount);
    }

    /// <summary>
    /// A part with no <c>Content-Type</c> of its own is normal — curl and wp-cli both omit it — and
    /// must not be confused with a part that declared an empty one.
    /// </summary>
    [Fact]
    public async Task FileWithoutPartContentType_ReportsNullDeclaredType()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", "photo.jpg", contentType: null, "synthetic"u8.ToArray())
            .Build();

        var file = Assert.Single((await ReadAsync(body)).Files);

        Assert.Null(file.DeclaredContentType);
    }

    /// <summary>
    /// A zero-byte file the user actually selected. Distinct from the unselected-input case below:
    /// this one has a name, so it is a file, and WordPress will happily create a zero-byte
    /// attachment from it.
    /// </summary>
    [Fact]
    public async Task NamedZeroByteFile_IsAFileNotAField()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", "empty.php", "application/octet-stream", [])
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(0, outcome.FieldCount);
        var file = Assert.Single(outcome.Files);
        Assert.Equal("empty.php", file.FileName);
        Assert.Equal(0, file.ByteCount);
        Assert.True(file.Sample.IsEmpty);
    }

    [Fact]
    public async Task MultipleFiles_AreReturnedInBodyOrderWithTheirOwnSamples()
    {
        var body = new MultipartBodyBuilder()
            .File("file-a", "a.jpg", "image/jpeg", Filled(0xA1, 40))
            .File("file-b", "b.png", "image/png", Filled(0xB2, 80))
            .File("file-c", "c.txt", "text/plain", Filled(0xC3, 120))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(0, outcome.FieldCount);
        Assert.Equal(["a.jpg", "b.png", "c.txt"], outcome.Files.Select(file => file.FileName));
        Assert.Equal([40L, 80L, 120L], outcome.Files.Select(file => file.ByteCount));
        Assert.Equal(Filled(0xA1, 40), outcome.Files[0].Sample.ToArray());
        Assert.Equal(Filled(0xB2, 80), outcome.Files[1].Sample.ToArray());
        Assert.Equal(Filled(0xC3, 120), outcome.Files[2].Sample.ToArray());
    }

    /// <summary>
    /// The shape real WordPress traffic has: an <c>async-upload.php</c> post is one file plus a
    /// handful of nonce and action fields.
    /// </summary>
    [Fact]
    public async Task MixedFieldsAndFiles_CountFieldsSeparatelyFromFiles()
    {
        var body = new MultipartBodyBuilder()
            .Field("action", "upload-attachment")
            .Field("_wpnonce", "synthetic-nonce-value")
            .File("async-upload", "photo.jpg", "image/jpeg", Filled(0x5A, 64))
            .Field("post_id", "42")
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(3, outcome.FieldCount);
        var file = Assert.Single(outcome.Files);
        Assert.Equal("photo.jpg", file.FileName);
    }

    /// <summary>
    /// Field parts are never sampled. This is the assertion that keeps <c>PHP-CONTENT-001</c> from
    /// firing on every WordPress post body, theme-editor save or page-builder widget that happens
    /// to contain a code snippet — the outcome exposes a count and nothing else, so a field's bytes
    /// cannot reach a rule even by accident.
    /// </summary>
    [Fact]
    public async Task FieldCarryingPhpMarker_IsCountedAndNeverSampled()
    {
        var body = new MultipartBodyBuilder()
            .Field("content", $"Here is a snippet for the post: {SyntheticPhpMarker}")
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(1, outcome.FieldCount);
        Assert.Empty(outcome.Files);
    }

    /// <summary>
    /// Browsers send <c>filename=""</c> with a zero-byte body for every empty
    /// <c>&lt;input type="file"&gt;</c> on a submitted form, and PHP records
    /// <c>UPLOAD_ERR_NO_FILE</c>. Counting it as a file would score 60 for
    /// <c>emptyAfterNormalization</c> under <c>UnsafeFileNameRule</c> on routine admin traffic.
    /// </summary>
    [Fact]
    public async Task UnselectedFileInput_IsCountedAsAFieldAndProducesNoUpload()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", string.Empty, "application/octet-stream", [])
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(1, outcome.FieldCount);
        Assert.Empty(outcome.Files);
    }

    /// <summary>
    /// An empty name over a non-empty body is the opposite case and must stay a file: the bytes are
    /// real, so they are inspectable, and <c>UnsafeFileNameRule</c> is right to have an opinion
    /// about the name.
    /// </summary>
    [Fact]
    public async Task EmptyFileNameWithContent_StaysAFile()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", string.Empty, "application/octet-stream", Filled(0x7F, 16))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(0, outcome.FieldCount);
        var file = Assert.Single(outcome.Files);
        Assert.Equal(string.Empty, file.FileName);
        Assert.Equal(16, file.ByteCount);
    }

    /// <summary>
    /// The <c>filename</c> / <c>filename*</c> parser differential, which is the reason
    /// <c>MultipartSection.AsFileSection()</c> is not used: it prefers <c>filename*</c> while PHP's
    /// multipart handler reads only <c>filename</c>, so picking either one inspects a file the
    /// backend will not write. Both names are emitted, <c>filename</c> first, sharing one sample.
    /// </summary>
    [Fact]
    public async Task DisagreeingFileNameAndFileNameStar_EmitBothNamesSharingOneSample()
    {
        var content = Encoding.ASCII.GetBytes(SyntheticPhpMarker);
        var body = new MultipartBodyBuilder()
            .Part(
                "Content-Disposition: form-data; name=\"async-upload\"; " +
                "filename=\"shell.php\"; filename*=UTF-8''photo.jpg\r\n" +
                "Content-Type: image/jpeg",
                content)
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(2, outcome.Files.Count);
        Assert.Equal("shell.php", outcome.Files[0].FileName);
        Assert.Equal("photo.jpg", outcome.Files[1].FileName);
        Assert.Equal(content, outcome.Files[0].Sample.ToArray());
        Assert.Equal(content, outcome.Files[1].Sample.ToArray());
        Assert.Equal(outcome.Files[0].ByteCount, outcome.Files[1].ByteCount);
    }

    /// <summary>
    /// When the two names agree there is no differential, so only one entry is emitted. Without
    /// this the common RFC 5987 case would double every file against
    /// <see cref="MultipartInspectionOptions.MaximumFileCount"/>.
    /// </summary>
    [Fact]
    public async Task AgreeingFileNameAndFileNameStar_EmitOneEntry()
    {
        var body = new MultipartBodyBuilder()
            .Part(
                "Content-Disposition: form-data; name=\"async-upload\"; " +
                "filename=\"photo.jpg\"; filename*=UTF-8''photo.jpg",
                Filled(0x11, 8))
            .Build();

        var file = Assert.Single((await ReadAsync(body)).Files);

        Assert.Equal("photo.jpg", file.FileName);
    }

    // =================================================================================================
    // 2. Sampling bounds
    // =================================================================================================

    /// <summary>
    /// The sample is capped and the count is not. This is what lets the gateway report how large an
    /// upload was without ever holding it: the remainder is read into a fixed 8 KiB scratch array
    /// and discarded.
    /// </summary>
    [Fact]
    public async Task FileLargerThanSampleBytes_TruncatesSampleAndKeepsExactByteCount()
    {
        var options = Options(sampleBytes: MultipartInspectionOptions.MinimumSampleBytes);
        var content = Sequential(4000);
        var body = new MultipartBodyBuilder()
            .File("async-upload", "large.bin", "application/octet-stream", content)
            .Build();

        var file = Assert.Single((await ReadAsync(body, options)).Files);

        Assert.Equal(MultipartInspectionOptions.MinimumSampleBytes, file.Sample.Length);
        Assert.Equal(
            content.AsSpan(0, MultipartInspectionOptions.MinimumSampleBytes).ToArray(),
            file.Sample.ToArray());
        Assert.Equal(4000, file.ByteCount);
    }

    /// <summary>
    /// Not just "the sample is short enough" but "nothing longer than the sample was retained".
    /// The backing array is right-sized and starts at offset zero, which is what distinguishes an
    /// owned copy from a window onto a pooled rental that a concurrent request is about to reuse.
    /// </summary>
    [Fact]
    public async Task Sample_IsBackedByARightSizedPrivateArray()
    {
        var options = Options(sampleBytes: MultipartInspectionOptions.MinimumSampleBytes);
        var body = new MultipartBodyBuilder()
            .File("async-upload", "large.bin", "application/octet-stream", Sequential(4000))
            .Build();

        var file = Assert.Single((await ReadAsync(body, options)).Files);

        Assert.True(MemoryMarshal.TryGetArray(file.Sample, out var segment));
        Assert.NotNull(segment.Array);
        Assert.Equal(0, segment.Offset);
        Assert.Equal(MultipartInspectionOptions.MinimumSampleBytes, segment.Count);
        Assert.Equal(MultipartInspectionOptions.MinimumSampleBytes, segment.Array.Length);
    }

    /// <summary>
    /// A file shorter than the sample bound is sampled whole, with no trailing padding from the
    /// pooled scratch array. Padding would be read by the content rules as file content that is not
    /// in the file — and on a pooled array, as another request's content.
    /// </summary>
    [Fact]
    public async Task FileShorterThanSampleBytes_IsSampledWholeWithNoPadding()
    {
        var content = Filled(0x2C, 37);
        var body = new MultipartBodyBuilder()
            .File("async-upload", "small.bin", "application/octet-stream", content)
            .Build();

        var file = Assert.Single((await ReadAsync(body, Options(sampleBytes: 1024))).Files);

        Assert.Equal(37, file.Sample.Length);
        Assert.Equal(content, file.Sample.ToArray());
        Assert.Equal(37, file.ByteCount);
    }

    /// <summary>
    /// <see cref="MultipartInspectionOptions.MinimumSampleBytes"/> is a cross-agent contract, not a
    /// style bound: below 512 bytes the content rules' text-versus-binary classification degrades.
    /// The reader clamps as well as the startup validator, so an options instance built in code —
    /// a test, a future call site — cannot disable <c>FILE-TYPE-001</c> by asking for a 64-byte
    /// sample.
    /// </summary>
    [Fact]
    public async Task SampleBytesBelowTheFloor_IsRaisedToTheFloorRatherThanHonoured()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", "large.bin", "application/octet-stream", Sequential(4000))
            .Build();

        var file = Assert.Single((await ReadAsync(body, Options(sampleBytes: 1))).Files);

        Assert.Equal(MultipartInspectionOptions.MinimumSampleBytes, file.Sample.Length);
    }

    /// <summary>
    /// And the ceiling, from the other side: an options instance that skipped the validator cannot
    /// make the gateway retain 1 MiB per file.
    /// </summary>
    [Fact]
    public async Task SampleBytesAboveTheCeiling_IsLoweredToTheCeiling()
    {
        var body = new MultipartBodyBuilder()
            .File(
                "async-upload",
                "large.bin",
                "application/octet-stream",
                Sequential(MultipartInspectionOptions.AbsoluteMaximumSampleBytes * 2))
            .Build();

        var file = Assert.Single((await ReadAsync(body, Options(sampleBytes: 1024 * 1024))).Files);

        Assert.Equal(MultipartInspectionOptions.AbsoluteMaximumSampleBytes, file.Sample.Length);
        Assert.Equal(MultipartInspectionOptions.AbsoluteMaximumSampleBytes * 2, file.ByteCount);
    }

    // =================================================================================================
    // 3. Limits — every one of them is a finding, never a silent pass
    // =================================================================================================

    /// <summary>
    /// The attack this limit exists for: prefix the payload with dummy files until the reader gives
    /// up, then attach the real one. "Gave up" must never mean "forwarded uninspected", so the read
    /// stops and the status is a finding the caller has to act on.
    /// </summary>
    [Fact]
    public async Task MoreFilesThanTheLimit_ReportsLimitExceededAndStopsReading()
    {
        var builder = new MultipartBodyBuilder();
        for (var index = 0; index < 5; index++)
        {
            builder.File($"file-{index}", $"file-{index}.jpg", "image/jpeg", Filled(0x40, 8));
        }

        var body = builder.Build();

        var limited = await ReadAsync(body, Options(maximumFileCount: 2));

        Assert.Equal(MultipartReadStatus.LimitExceeded, limited.Status);
        Assert.Equal(2, limited.Files.Count);
        Assert.Equal(["file-0.jpg", "file-1.jpg"], limited.Files.Select(file => file.FileName));

        // Control. Without it this test would still pass if the body were simply unparseable.
        var permitted = await ReadAsync(body, Options(maximumFileCount: 5));

        Assert.Equal(MultipartReadStatus.Complete, permitted.Status);
        Assert.Equal(5, permitted.Files.Count);
    }

    /// <summary>
    /// The file that trips the limit is read but never inspected, and nothing after it is reached
    /// at all — including a part that would otherwise have produced a blocking finding. That is the
    /// point: the caller sees <see cref="MultipartReadStatus.LimitExceeded"/> and refuses rather
    /// than trusting an incomplete verdict.
    /// </summary>
    [Fact]
    public async Task PayloadHiddenBehindTheFileLimit_IsNeverInspected()
    {
        var builder = new MultipartBodyBuilder()
            .File("decoy-0", "a.jpg", "image/jpeg", Filled(0x40, 8))
            .File("decoy-1", "b.jpg", "image/jpeg", Filled(0x40, 8))
            .File("decoy-2", "c.jpg", "image/jpeg", Filled(0x40, 8))
            .File("payload", "shell.php", "image/jpeg", Encoding.ASCII.GetBytes(SyntheticPhpMarker));

        var outcome = await ReadAsync(builder.Build(), Options(maximumFileCount: 2));

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        Assert.DoesNotContain(outcome.Files, file => file.FileName == "shell.php");
    }

    [Fact]
    public async Task MoreFieldsThanTheLimit_ReportsLimitExceededAndStopsReading()
    {
        var builder = new MultipartBodyBuilder();
        for (var index = 0; index < 5; index++)
        {
            builder.Field($"field-{index}", "synthetic");
        }

        builder.File("payload", "shell.php", "image/jpeg", Encoding.ASCII.GetBytes(SyntheticPhpMarker));

        var outcome = await ReadAsync(builder.Build(), Options(maximumFieldCount: 2));

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        Assert.Equal(2, outcome.FieldCount);
        Assert.Empty(outcome.Files);
    }

    /// <summary>
    /// Unselected file inputs are counted as fields, so they consume the field budget and can trip
    /// the same limit. A page-builder form with a long field list plus a file attachment is the
    /// realistic way to meet this in production, which is why the observed count is what an
    /// operator tunes against.
    /// </summary>
    [Fact]
    public async Task UnselectedFileInputs_ConsumeTheFieldBudget()
    {
        var builder = new MultipartBodyBuilder();
        for (var index = 0; index < 4; index++)
        {
            builder.File($"file-{index}", string.Empty, "application/octet-stream", []);
        }

        var outcome = await ReadAsync(builder.Build(), Options(maximumFieldCount: 2));

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        Assert.Equal(2, outcome.FieldCount);
        Assert.Empty(outcome.Files);
    }

    /// <summary>
    /// A name too long to carry honestly is truncated <i>and</i> reported. Truncation alone would
    /// be an evasion: chopping the tail off <c>aaaa…aaaa.php</c> removes the <c>.php</c> and turns
    /// a detection into a miss, which this test pins by asserting the truncated name no longer ends
    /// in the executable extension the client actually sent.
    /// </summary>
    [Fact]
    public async Task FileNameOverTheCap_IsTruncatedAndReportedAsLimitExceeded()
    {
        var overlongName = new string('a', MultipartInspectionReader.MaximumFileNameLength - 3) + ".php";
        var body = new MultipartBodyBuilder()
            .File("async-upload", overlongName, "image/jpeg", Filled(0x33, 16))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        var file = Assert.Single(outcome.Files);
        Assert.NotNull(file.FileName);
        Assert.Equal(MultipartInspectionReader.MaximumFileNameLength, file.FileName.Length);
        Assert.EndsWith(".ph", file.FileName, StringComparison.Ordinal);
        Assert.False(file.FileName.EndsWith(".php", StringComparison.Ordinal));
    }

    /// <summary>
    /// A name exactly at the cap is not a limit hit. Off-by-one here would report
    /// <see cref="MultipartReadStatus.LimitExceeded"/> on legitimate traffic, and in Block mode
    /// that is a 415 for a long but ordinary file name.
    /// </summary>
    [Fact]
    public async Task FileNameExactlyAtTheCap_IsNotALimitHit()
    {
        var name = new string('a', MultipartInspectionReader.MaximumFileNameLength - 4) + ".jpg";
        var body = new MultipartBodyBuilder()
            .File("async-upload", name, "image/jpeg", Filled(0x33, 16))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(name, Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// The file-name cap is sticky but not terminal, unlike the file and field counts: the status
    /// is raised and the read continues, so a payload sitting behind an over-long name is still
    /// inspected rather than being hidden by it.
    /// </summary>
    [Fact]
    public async Task FileNameOverTheCap_DoesNotStopTheRead()
    {
        var overlongName = new string('a', MultipartInspectionReader.MaximumFileNameLength + 64);
        var body = new MultipartBodyBuilder()
            .File("first", overlongName, "image/jpeg", Filled(0x33, 16))
            .File("second", "shell.php", "image/jpeg", Encoding.ASCII.GetBytes(SyntheticPhpMarker))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        Assert.Equal(2, outcome.Files.Count);
        Assert.Equal("shell.php", outcome.Files[1].FileName);
    }

    /// <summary>
    /// Field names and per-part content types are truncated silently, and the asymmetry is
    /// deliberate: no rule matches against either, so truncating one cannot erase a detection the
    /// way chopping <c>.php</c> off a file name can.
    /// </summary>
    [Fact]
    public async Task OverlongFieldNameAndContentType_AreTruncatedSilently()
    {
        var fieldName = new string('n', MultipartInspectionReader.MaximumFieldNameLength + 50);
        var contentType = "image/" + new string('t', MultipartInspectionReader.MaximumDeclaredContentTypeLength);
        var body = new MultipartBodyBuilder()
            .File(fieldName, "photo.jpg", contentType, Filled(0x44, 8))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        var file = Assert.Single(outcome.Files);
        Assert.NotNull(file.FieldName);
        Assert.NotNull(file.DeclaredContentType);
        Assert.Equal(MultipartInspectionReader.MaximumFieldNameLength, file.FieldName.Length);
        Assert.Equal(MultipartInspectionReader.MaximumDeclaredContentTypeLength, file.DeclaredContentType.Length);
    }

    /// <summary>
    /// A part header block past <see cref="MultipartInspectionOptions.MaximumPartHeaderBytes"/>
    /// produces <see cref="MultipartReadStatus.Malformed"/>, not
    /// <see cref="MultipartReadStatus.LimitExceeded"/>, and that is the documented intent rather
    /// than a slip: a header WPShield read only part of is a header WPShield and the backend
    /// disagree about, which is the whole attack. Both statuses are findings and both reach the
    /// same policy, so nothing is waved through either way.
    /// </summary>
    [Fact]
    public async Task PartHeadersOverTheByteLimit_ReportMalformed()
    {
        var body = new MultipartBodyBuilder()
            .Part(
                "Content-Disposition: form-data; name=\"async-upload\"; filename=\"photo.jpg\"\r\n" +
                "X-Synthetic-Padding: " + new string('p', 4096),
                Filled(0x55, 8))
            .Build();

        Assert.Equal(
            MultipartReadStatus.Malformed,
            (await ReadAsync(body, Options(maximumPartHeaderBytes: 256))).Status);

        // Control: the same body is well formed, so the limit is what rejected it.
        Assert.Equal(
            MultipartReadStatus.Complete,
            (await ReadAsync(body, Options(maximumPartHeaderBytes: 8 * 1024))).Status);
    }

    /// <summary>
    /// The header <i>count</i> limit is a separate ceiling and is fixed in source rather than
    /// configurable, so a framework update cannot change it underneath the gateway.
    /// </summary>
    [Fact]
    public async Task PartWithMoreHeadersThanTheCountLimit_ReportsMalformed()
    {
        var headers = new StringBuilder(
            "Content-Disposition: form-data; name=\"async-upload\"; filename=\"photo.jpg\"");
        for (var index = 0; index <= MultipartInspectionReader.PartHeaderCountLimit; index++)
        {
            headers.Append("\r\nX-Synthetic-").Append(index).Append(": v");
        }

        var body = new MultipartBodyBuilder().Part(headers.ToString(), Filled(0x66, 8)).Build();

        Assert.Equal(MultipartReadStatus.Malformed, (await ReadAsync(body)).Status);

        // Control: one header fewer — the disposition plus fifteen padding headers — parses.
        var withinLimit = new StringBuilder(
            "Content-Disposition: form-data; name=\"async-upload\"; filename=\"photo.jpg\"");
        for (var index = 0; index < MultipartInspectionReader.PartHeaderCountLimit - 1; index++)
        {
            withinLimit.Append("\r\nX-Synthetic-").Append(index).Append(": v");
        }

        Assert.Equal(
            MultipartReadStatus.Complete,
            (await ReadAsync(new MultipartBodyBuilder()
                .Part(withinLimit.ToString(), Filled(0x66, 8))
                .Build())).Status);
    }

    /// <summary>
    /// Absolute ceilings are re-applied at the point of use. An options instance that never met
    /// <c>GatewayConfigurationValidator</c> cannot raise one.
    /// </summary>
    [Fact]
    public async Task FileCountAboveTheAbsoluteCeiling_IsClampedToTheCeiling()
    {
        var builder = new MultipartBodyBuilder();
        for (var index = 0; index < MultipartInspectionOptions.AbsoluteMaximumFileCount + 5; index++)
        {
            builder.File($"file-{index}", $"file-{index}.jpg", "image/jpeg", Filled(0x40, 4));
        }

        var outcome = await ReadAsync(
            builder.Build(), Options(maximumFileCount: int.MaxValue, sampleBytes: 512));

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        Assert.Equal(MultipartInspectionOptions.AbsoluteMaximumFileCount, outcome.Files.Count);
    }

    [Fact]
    public async Task FieldCountAboveTheAbsoluteCeiling_IsClampedToTheCeiling()
    {
        var builder = new MultipartBodyBuilder();
        for (var index = 0; index < MultipartInspectionOptions.AbsoluteMaximumFieldCount + 5; index++)
        {
            builder.Field($"field-{index}", "v");
        }

        var outcome = await ReadAsync(builder.Build(), Options(maximumFieldCount: int.MaxValue));

        Assert.Equal(MultipartReadStatus.LimitExceeded, outcome.Status);
        Assert.Equal(MultipartInspectionOptions.AbsoluteMaximumFieldCount, outcome.FieldCount);
    }

    // =================================================================================================
    // 4. Malformed bodies — a finding, never an exception
    // =================================================================================================

    /// <summary>
    /// Every one of these is a body a hostile client can send for free. None of them may unwind the
    /// request pipeline: an exception escaping here becomes a 500 from a component whose errors are
    /// supposed to mean "the gateway is broken".
    /// </summary>
    [Theory]
    [MemberData(nameof(MalformedBodies))]
    public async Task MalformedBody_ReportsMalformedWithoutThrowing(string caseName, byte[] body)
    {
        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);
        Assert.NotNull(caseName);
    }

    public static TheoryData<string, byte[]> MalformedBodies()
    {
        var data = new TheoryData<string, byte[]>
        {
            // Nothing at all. A declared multipart request with an empty body is not a body we can
            // parse, so it fails closed rather than being treated as "no files, nothing to see".
            { "empty body", [] },

            // Content that never contains the boundary the Content-Type promised. If this were
            // forwarded, "declare a boundary that does not appear in your own body" would be a
            // one-line bypass of every rule.
            { "boundary never appears", "not multipart at all"u8.ToArray() },

            // Parts parse, then the stream ends without the closing --boundary-- delimiter. IIS and
            // PHP are more forgiving here than we are, and that difference is exactly why we refuse.
            {
                "missing final delimiter",
                new MultipartBodyBuilder()
                    .File("async-upload", "photo.jpg", "image/jpeg", Filled(0x77, 32))
                    .BuildWithoutFinalDelimiter()
            },

            // Cut off in the middle of a part body: the classic aborted upload, and also what a
            // deliberately truncated request looks like.
            {
                "truncated mid-part",
                Truncate(
                    new MultipartBodyBuilder()
                        .File("async-upload", "photo.jpg", "image/jpeg", Filled(0x77, 256))
                        .Build(),
                    keepBytes: 160)
            },

            // A part with no headers at all. GetContentDispositionHeader() returns null, and a part
            // whose disposition we cannot read is a part we cannot classify as field or file.
            {
                "part with no headers",
                new MultipartBodyBuilder().Part(string.Empty, "synthetic"u8.ToArray()).Build()
            },

            // Content-Disposition present but not form-data at all.
            {
                "part header that is not Content-Disposition",
                new MultipartBodyBuilder()
                    .Part("Content-Type: image/jpeg", "synthetic"u8.ToArray())
                    .Build()
            },

            // filename="a.jpg"; filename="shell.php" is a probe, not a mistake: this header parser
            // keeps the first and PHP's keeps the last, so accepting it would mean inspecting one
            // name while the backend writes another.
            {
                "Content-Disposition naming the file twice",
                new MultipartBodyBuilder()
                    .Part(
                        "Content-Disposition: form-data; name=\"async-upload\"; " +
                        "filename=\"photo.jpg\"; filename=\"shell.php\"",
                        "synthetic"u8.ToArray())
                    .Build()
            },

            // LF-only line endings. RFC 2046 requires CRLF; some parsers accept bare LF and some do
            // not, and a gateway that guesses which one the backend is has guessed wrong.
            {
                "LF-only line endings",
                Encoding.ASCII.GetBytes(
                    $"--{Boundary}\n" +
                    "Content-Disposition: form-data; name=\"async-upload\"; filename=\"shell.php\"\n" +
                    "\n" +
                    SyntheticPhpMarker + "\n" +
                    $"--{Boundary}--\n")
            },

            // A CR with no LF inside the header block.
            {
                "bare CR in the header block",
                Encoding.ASCII.GetBytes(
                    $"--{Boundary}\r\n" +
                    "Content-Disposition: form-data; name=\"async-upload\"; filename=\"shell.php\"\r" +
                    "Content-Type: image/jpeg\r\n\r\n" +
                    SyntheticPhpMarker + $"\r\n--{Boundary}--\r\n")
            }
        };

        return data;
    }

    /// <summary>
    /// A body that carries only the closing delimiter is well formed and carries no upload, so it
    /// is <see cref="MultipartReadStatus.Complete"/> with nothing in it rather than a finding.
    /// Calling it malformed would put every empty multipart POST — and there are real ones — on the
    /// fail-closed path.
    /// </summary>
    [Fact]
    public async Task BodyWithNoParts_IsCompleteAndEmpty()
    {
        var body = Encoding.ASCII.GetBytes($"--{Boundary}--\r\n");

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Empty(outcome.Files);
        Assert.Equal(0, outcome.FieldCount);
    }

    /// <summary>
    /// RFC 2046 allows text before the first delimiter and after the closing one, and real clients
    /// send both. Rejecting either would be a false positive on ordinary traffic, so the reader has
    /// to tolerate them without letting anything in them count as a part.
    /// </summary>
    /// <remarks>
    /// <b>This test is deliberately narrower than it was.</b> It used to say that anything at
    /// all could follow the closing delimiter, and F1 turned that tolerance into a bypass: a body
    /// prefixed with a lone <c>--X--</c> line reported <c>Complete</c> with no files, no fields
    /// and nothing above Information in the log, while PHP — which has no concept of a
    /// terminating boundary — parsed the part behind the decoy and wrote <c>$_FILES</c>. What is
    /// tolerated now is an epilogue of <i>prose</i>, which is what RFC 2046 §5.1.1 is actually
    /// about and what real clients send. An epilogue containing the delimiter is
    /// <see cref="MultipartReadStatus.Malformed"/>; see
    /// <c>DelimiterInsideTheEpilogue_IsMalformedWithNoPartBehindIt</c> and the three F1 tests
    /// beside it. The narrowing is the fix, not collateral damage from it.
    /// </remarks>
    [Fact]
    public async Task PreambleAndEpilogue_AreToleratedAndCountAsNothing()
    {
        var core = new MultipartBodyBuilder()
            .File("async-upload", "photo.jpg", "image/jpeg", "GIF89a"u8.ToArray())
            .Build();
        var body = Concat(
            Encoding.ASCII.GetBytes("This is a preamble a client may legally send.\r\n"),
            core,
            Encoding.ASCII.GetBytes("And this is an epilogue.\r\n"));

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(0, outcome.FieldCount);
        Assert.Equal("photo.jpg", Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// <c>Content-Transfer-Encoding</c> is not honoured, and that is correct rather than a gap:
    /// PHP's own multipart handler ignores it too and writes the part's bytes to disk verbatim, so
    /// a base64-encoded part lands on the server as base64 text — which is not PHP and is not
    /// executed. Sampling the decoded form would have WPShield reasoning about a file that never
    /// exists. Pinned here so a future "helpful" decode is a deliberate change.
    /// </summary>
    [Fact]
    public async Task ContentTransferEncoding_IsNotDecoded()
    {
        var encoded = Convert.ToBase64String(Encoding.ASCII.GetBytes(SyntheticPhpMarker));
        var body = new MultipartBodyBuilder()
            .Part(
                "Content-Disposition: form-data; name=\"async-upload\"; filename=\"photo.jpg\"\r\n" +
                "Content-Transfer-Encoding: base64",
                Encoding.ASCII.GetBytes(encoded))
            .Build();

        var file = Assert.Single((await ReadAsync(body)).Files);

        Assert.Equal(encoded, Encoding.ASCII.GetString(file.Sample.Span));
        Assert.Equal(encoded.Length, file.ByteCount);
    }

    /// <summary>
    /// Whatever was read before the body turned out to be unparseable is still returned and still
    /// inspected. The status constrains what the caller may do with the request; it does not throw
    /// away what was already learned, so a payload in part one is not laundered by corrupting part
    /// two.
    /// </summary>
    [Fact]
    public async Task MalformedAfterAValidPart_KeepsWhatWasAlreadyRead()
    {
        var complete = new MultipartBodyBuilder()
            .File("async-upload", "shell.php", "image/jpeg", Encoding.ASCII.GetBytes(SyntheticPhpMarker))
            .File("second", "photo.jpg", "image/jpeg", Filled(0x88, 512))
            .Build();

        var outcome = await ReadAsync(Truncate(complete, complete.Length - 300));

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);
        Assert.Equal("shell.php", outcome.Files[0].FileName);
    }

    /// <summary>
    /// Guard on the reader's own preconditions. These are programming errors in the caller, not
    /// hostile input, and they must not be quietly turned into a status.
    /// </summary>
    [Fact]
    public async Task NullOrEmptyArguments_Throw()
    {
        var reader = new MultipartInspectionReader();
        using var stream = new MemoryStream([]);

        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await reader.ReadAsync(null!, Boundary, new MultipartInspectionOptions(), default));
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await reader.ReadAsync(stream, string.Empty, new MultipartInspectionOptions(), default));
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await reader.ReadAsync(stream, Boundary, null!, default));
    }

    // =================================================================================================
    // 5. Boundary extraction
    // =================================================================================================

    [Theory]
    [InlineData("multipart/form-data; boundary=simpleboundary", "simpleboundary")]
    [InlineData("multipart/form-data; boundary=\"quotedboundary\"", "quotedboundary")]
    [InlineData("multipart/form-data; boundary=\"has spaces inside\"", "has spaces inside")]
    [InlineData("MULTIPART/FORM-DATA; BOUNDARY=caseinsensitive", "caseinsensitive")]
    [InlineData("multipart/form-data; charset=utf-8; boundary=afterotherparams", "afterotherparams")]
    [InlineData("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW", "----WebKitFormBoundary7MA4YWxkTrZu0gW")]
    [InlineData("multipart/form-data; boundary=b", "b")]

    // The literal string "boundary" as the boundary value, which is what keeps
    // HasAmbiguousBoundaryParameter honest. Requiring a "=" after the token is what makes this
    // second occurrence a value rather than a second declaration: PHP's
    // strstr(content_type, "boundary") plus strchr(..., '=') pair reads the same delimiter
    // WPShield does, so there is no differential, and refusing it would be a false positive on a
    // client that is unusual but not hostile.
    [InlineData("multipart/form-data; boundary=boundary", "boundary")]
    [InlineData("multipart/form-data; boundary=\"boundary\"", "boundary")]
    public void TryGetBoundary_AcceptsWellFormedDeclarations(string contentType, string expected)
    {
        Assert.True(MultipartInspectionReader.TryGetBoundary(
            Request(contentType), new MultipartInspectionOptions(), out var boundary));
        Assert.Equal(expected, boundary);
    }

    /// <summary>
    /// A boundary of exactly 70 characters is legal under RFC 2046 §5.1.1 and must be accepted; 71
    /// is where the fail-closed rule starts. Getting this edge wrong in the accepting direction
    /// widens the parser-differential surface, and in the rejecting direction turns a legal request
    /// into a 415.
    /// </summary>
    [Fact]
    public void TryGetBoundary_AcceptsExactlyTheMaximumLength()
    {
        var boundary70 = new string('b', MultipartInspectionReader.MaximumBoundaryLength);

        Assert.True(MultipartInspectionReader.TryGetBoundary(
            Request($"multipart/form-data; boundary={boundary70}"),
            new MultipartInspectionOptions(),
            out var boundary));
        Assert.Equal(boundary70, boundary);
    }

    /// <summary>
    /// Every declaration the gateway refuses to extract a boundary from, and — the half that was
    /// missing — whether each one still counts as declaring <c>multipart/form-data</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>UploadInspectionService</c> reads the two answers as a pair: no usable boundary
    /// <i>and</i> not multipart means "ordinary traffic, stream it through untouched", while no
    /// usable boundary <i>and</i> multipart means "fail closed" — a 415 in Block, a warning in
    /// Monitor. Asserting only the first half is what let F3 ship. Four of the rows below returned
    /// <see langword="false"/> from <i>both</i> halves, so a body PHP parses happily was classified
    /// as ordinary traffic and forwarded with no buffer, no rule and no log line. The string
    /// <c>multipart/form-data; boundary=aaa, application/json</c> was already in this data before
    /// the fix — only the boundary half of it was ever asserted.
    /// </para>
    /// <para>
    /// The third column is therefore a security decision per row, and belongs where it is written.
    /// <see langword="true"/> costs a refusal in Block mode for a request no mainstream client
    /// sends. <see langword="false"/> means the request is never inspected at all, and is defensible
    /// only where the backend cannot turn it into an upload either.
    /// </para>
    /// </remarks>
    [Theory]
    [MemberData(nameof(RejectedBoundaryDeclarations))]
    public void TryGetBoundary_RejectsUnusableDeclarations(
        string caseName, string contentType, bool declaresMultipart)
    {
        var request = Request(contentType);

        Assert.False(MultipartInspectionReader.TryGetBoundary(
            request, new MultipartInspectionOptions(), out var boundary));
        Assert.Equal(string.Empty, boundary);

        // The pairing. Without this assertion the suite cannot tell "refused, and therefore
        // inspected as malformed" apart from "refused, and therefore forwarded uninspected" — and
        // those two differ by an entire rule set.
        Assert.Equal(declaresMultipart, MultipartInspectionReader.DeclaresMultipartFormData(request));
        Assert.NotNull(caseName);
    }

    public static TheoryData<string, string, bool> RejectedBoundaryDeclarations()
    {
        return new TheoryData<string, string, bool>
        {
            { "no boundary parameter", "multipart/form-data", true },
            { "empty boundary", "multipart/form-data; boundary=\"\"", true },
            {
                "one character over the RFC 2046 cap",
                "multipart/form-data; boundary=" +
                new string('b', MultipartInspectionReader.MaximumBoundaryLength + 1),
                true
            },
            {
                "Kestrel would accept this one — the entire known false-positive band",
                "multipart/form-data; boundary=" + new string('b', 128),
                true
            },

            // A trailing space is legal inside a quoted boundary but is invisible in a log and is
            // stripped by some parsers, so the two ends can disagree about where the delimiter ends.
            { "trailing space", "multipart/form-data; boundary=\"trailing \"", true },

            // The characters that would let a boundary carry header structure into the parser.
            { "semicolon", "multipart/form-data; boundary=\"a;b\"", true },
            { "backslash", "multipart/form-data; boundary=\"a\\\\b\"", true },
            { "carriage return", "multipart/form-data; boundary=\"a\rb\"", true },
            { "line feed", "multipart/form-data; boundary=\"a\nb\"", true },
            { "tab", "multipart/form-data; boundary=\"a\tb\"", true },
            { "non-ASCII", "multipart/form-data; boundary=\"boundaría\"", true },

            // F3, every measured row. Kestrel neither rejects nor splits a comma-joined value, so
            // each of these arrives as one header line that no strict whole-value parser accepts —
            // and that PHP reduces to "aaa" with boundary_end = strpbrk(boundary, ",;"). All four
            // were measured as forwarded uninspected: Declares=False, Boundary=False, no buffer, no
            // rule, no log line. They are the reason the declaration check is textual.
            { "trailing comma", "multipart/form-data; boundary=aaa,", true },
            { "comma-joined second boundary", "multipart/form-data; boundary=aaa,bbb", true },
            {
                "comma-joined second media type",
                "multipart/form-data; boundary=aaa, application/json",
                true
            },
            {
                "trailing comma on a browser-shaped boundary",
                "multipart/form-data;boundary=----WebKitFormBoundaryABC,",
                true
            },

            // F3b. Two things in one value that PHP will read as a boundary declaration. WPShield
            // takes aaa in both rows; PHP takes bbb in both, the first because nothing says the
            // parsers agree on which duplicate wins, the second because strstr(ct, "boundary")
            // matches inside xboundary.
            { "boundary declared twice", "multipart/form-data; boundary=aaa; boundary=bbb", true },
            {
                "boundary shadowed by an earlier xboundary",
                "multipart/form-data; xboundary=bbb; boundary=aaa",
                true
            },

            // The honest false positive, written down rather than hidden. PHP's strstr finds the
            // real parameter first here, so it agrees with us and there is no differential behind
            // this refusal. Telling the two orders apart means re-implementing PHP's scan, which is
            // the arms race the design refuses to enter — so it costs a 415 in Block mode for a
            // request no real client sends.
            {
                "decoy boundary parameter after the real one",
                "multipart/form-data; boundary=aaa; xboundary=bbb",
                true
            },

            // Out of scope by subtype. PHP populates $_FILES only for form-data, so these cannot
            // become an upload through the path WPShield defends — which is what makes "never
            // inspected" the right answer rather than a gap.
            { "multipart/mixed", "multipart/mixed; boundary=synthetic", false },
            { "multipart/related", "multipart/related; boundary=synthetic", false },
            { "not multipart at all", "application/x-www-form-urlencoded", false },
            { "json", "application/json", false },
            { "unparseable header", "this is not a media type", false },
            { "empty header", "", false }
        };
    }

    /// <summary>
    /// Two <c>Content-Type</c> lines is a parser-differential probe: Kestrel does not reject them
    /// and <c>HttpRequest.ContentType</c> joins them with <c>", "</c>, so if WPShield parses one
    /// while IIS, ARR or PHP parses the other, WPShield inspected a different request than the one
    /// that executes.
    /// </summary>
    [Theory]
    [InlineData("multipart/form-data; boundary=one", "multipart/form-data; boundary=two")]
    [InlineData("multipart/form-data; boundary=one", "multipart/form-data; boundary=one")]
    [InlineData("application/json", "multipart/form-data; boundary=one")]
    public void TryGetBoundary_RejectsDuplicateContentTypeHeaders(string first, string second)
    {
        Assert.False(MultipartInspectionReader.TryGetBoundary(
            Request(first, second), new MultipartInspectionOptions(), out _));
    }

    /// <summary>
    /// The pairing that makes duplicate headers a finding rather than a skip. "Declared multipart"
    /// and "has a usable boundary" are separate questions, and collapsing them either blocks every
    /// GET or hands an attacker a bypass, depending on which way they collapse.
    /// </summary>
    [Fact]
    public void DuplicateContentTypeHeaders_StillCountAsDeclaringMultipart()
    {
        var request = Request("multipart/form-data; boundary=one", "multipart/form-data; boundary=two");

        Assert.True(MultipartInspectionReader.DeclaresMultipartFormData(request));
        Assert.False(MultipartInspectionReader.TryGetBoundary(
            request, new MultipartInspectionOptions(), out _));
    }

    [Theory]
    [InlineData("multipart/form-data; boundary=synthetic", true)]
    [InlineData("multipart/form-data", true)]
    [InlineData("MultiPart/Form-Data; boundary=synthetic", true)]
    [InlineData("multipart/mixed; boundary=synthetic", false)]
    [InlineData("application/json", false)]
    [InlineData("", false)]
    public void DeclaresMultipartFormData_TracksTheDeclarationNotTheBoundary(
        string contentType, bool expected)
    {
        Assert.Equal(expected, MultipartInspectionReader.DeclaresMultipartFormData(Request(contentType)));
    }

    [Fact]
    public void DeclaresMultipartFormData_IsFalseWhenNoContentTypeIsSent()
    {
        Assert.False(MultipartInspectionReader.DeclaresMultipartFormData(new DefaultHttpContext().Request));
    }

    /// <summary>
    /// The boundary is handed to <c>MultipartReader</c> without a leading <c>--</c>, which prepends
    /// the delimiter itself. Passing <c>--boundary</c> produces a reader that matches nothing and a
    /// clean-looking empty parse — a silent false negative that is very hard to spot in review, so
    /// it is pinned end to end here rather than left to the extraction unit test alone.
    /// </summary>
    [Fact]
    public async Task BoundaryFromTryGetBoundary_ParsesABodyBuiltWithThatBoundary()
    {
        const string contentType = "multipart/form-data; boundary=\"----WPShieldSyntheticBoundary\"";
        Assert.True(MultipartInspectionReader.TryGetBoundary(
            Request(contentType), new MultipartInspectionOptions(), out var boundary));

        var body = new MultipartBodyBuilder(boundary)
            .File("async-upload", "photo.jpg", "image/jpeg", Filled(0x99, 24))
            .Build();

        var outcome = await ReadAsync(body, boundary: boundary);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal("photo.jpg", Assert.Single(outcome.Files).FileName);
    }

    // =================================================================================================
    // 6. File names: Unicode, evasions, and what the reader must not "helpfully" clean up
    // =================================================================================================

    /// <summary>
    /// Non-ASCII names are ordinary WordPress traffic on most of the planet. If the header parser
    /// refused them the reader would report <see cref="MultipartReadStatus.Malformed"/>, and in
    /// Block mode that is a 415 for every photo with a Cyrillic or CJK name.
    /// </summary>
    [Theory]
    [InlineData("фото.jpg")]
    [InlineData("写真.jpg")]
    [InlineData("imagen-año-2026.jpg")]
    [InlineData("emoji-🐛.png")]
    [InlineData("naïve café.jpg")]
    public async Task UnicodeFileNames_SurviveTheReadVerbatim(string fileName)
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", fileName, "image/jpeg", Filled(0x21, 16))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(fileName, Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// The right-to-left override trick: <c>photo‮gpj.php</c> renders in a file listing as
    /// something ending in <c>.jpg</c> while the bytes on disk end in <c>.php</c>. The reader must
    /// carry the raw name through untouched — stripping the control character here would hide the
    /// evasion from <c>UnsafeFileNameRule</c>, which is the rule whose job it is to notice.
    /// </summary>
    [Theory]
    [InlineData("photo‮gpj.php")]
    [InlineData("‮photo.php")]
    [InlineData("photo​.php")]
    public async Task BidirectionalOverrideNames_ArePassedThroughUnaltered(string fileName)
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", fileName, "image/jpeg", Filled(0x21, 16))
            .Build();

        Assert.Equal(fileName, Assert.Single((await ReadAsync(body)).Files).FileName);
    }

    /// <summary>
    /// Names that normalize away to nothing. The reader does not normalize — that is
    /// <c>NormalizedFileName</c>'s job and it happens later — so what must be asserted here is that
    /// the raw name reaches the rules intact rather than being turned into <see langword="null"/>
    /// or trimmed into something harmless-looking.
    /// </summary>
    [Theory]
    [InlineData("   ")]
    [InlineData("...")]
    [InlineData(".")]
    [InlineData("..")]
    public async Task NamesThatNormalizeToEmpty_StillReachTheRulesRaw(string fileName)
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", fileName, "application/octet-stream", Filled(0x21, 16))
            .Build();

        var file = Assert.Single((await ReadAsync(body)).Files);

        Assert.Equal(fileName, file.FileName);
        Assert.True(NormalizedFileName.Create(file.FileName).IsEmpty);
    }

    /// <summary>
    /// The Windows evasion forms, driven end to end: through the reader, into an
    /// <c>InspectionContext</c>, and into the rule that is supposed to catch them. A reader that
    /// trimmed a trailing space, dropped a trailing dot, resolved a directory prefix or stripped an
    /// alternate-data-stream suffix would leave the rule looking at a name IIS never sees, and each
    /// of these reaches disk as <c>shell.php</c>.
    /// </summary>
    [Theory]
    [InlineData("shell.php.")]
    [InlineData("shell.php ")]
    [InlineData("shell.php::$DATA")]
    [InlineData("../../shell.php")]
    [InlineData(@"..\..\shell.php")]
    [InlineData("shell.pHp5.")]
    [InlineData("shell.p hp")]
    public async Task WindowsEvasionNames_SurviveTheReaderAndStillTripTheRule(string fileName)
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", fileName, "image/jpeg", Filled(0x21, 16))
            .Build();

        var file = Assert.Single((await ReadAsync(body)).Files);
        Assert.Equal(fileName, file.FileName);

        var finding = await new ExecutableUploadExtensionRule().EvaluateAsync(
            new InspectionContext(
                "site-one",
                "wordpress-one.example",
                "POST",
                "/wp-admin/async-upload.php",
                file.FileName,
                file.DeclaredContentType,
                file.Sample));

        Assert.NotNull(finding);
        Assert.Equal("WP-UPLOAD-001", finding.RuleId);
    }

    /// <summary>
    /// The double-extension case is not an evasion of this reader but of a naive extension check,
    /// so what matters here is only that the name arrives whole for <c>WP-UPLOAD-002</c> to reason
    /// about.
    /// </summary>
    [Fact]
    public async Task EmbeddedExecutableExtension_ArrivesWhole()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", "photo.php.jpg", "image/jpeg", Filled(0x21, 16))
            .Build();

        var file = Assert.Single((await ReadAsync(body)).Files);

        Assert.Equal("photo.php.jpg", file.FileName);
        Assert.NotNull(await new DisguisedExtensionRule().EvaluateAsync(
            new InspectionContext(
                "site-one",
                "wordpress-one.example",
                "POST",
                "/wp-admin/async-upload.php",
                file.FileName,
                file.DeclaredContentType,
                file.Sample)));
    }

    // =================================================================================================
    // 7. Cancellation and the read deadline
    // =================================================================================================

    /// <summary>
    /// A client that closed the tab must stop the work at once, and the exception must reach the
    /// caller: only the caller knows there is no longer a connection to answer, and converting this
    /// into a status would have the gateway compose a response for nobody.
    /// </summary>
    [Fact]
    public async Task AlreadyCancelledToken_PropagatesOperationCanceled()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", "photo.jpg", "image/jpeg", Filled(0x21, 4096))
            .Build();
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await ReadAsync(body, cancellationToken: cancellation.Token));
    }

    /// <summary>
    /// The same distinction mid-read: the caller's token firing is a disconnect and propagates,
    /// even though the reader's own deadline is running at the same time and would have produced
    /// <see cref="MultipartReadStatus.TimedOut"/>. This is the branch a <c>catch</c> without the
    /// <c>when</c> filter would get wrong.
    /// </summary>
    [Fact]
    public async Task ClientDisconnectMidRead_PropagatesRatherThanReportingTimedOut()
    {
        var stalling = new StallingStream(PrefixUpToFileContent());
        using var cancellation = new CancellationTokenSource();
        var reader = new MultipartInspectionReader();

        var read = reader.ReadAsync(
            stalling,
            Boundary,
            Options(readTimeoutSeconds: MultipartInspectionOptions.AbsoluteMaximumReadTimeoutSeconds),
            cancellation.Token).AsTask();

        await stalling.StalledAsync;
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await read);
    }

    /// <summary>
    /// The reader's own deadline is the only thing bounding how long a slow client can pin a pooled
    /// buffer, and it must become a status rather than an exception: the connection is still there,
    /// so the caller has a response to write.
    /// </summary>
    [Fact]
    public async Task ReadDeadline_ProducesTimedOutRatherThanThrowing()
    {
        var stalling = new StallingStream(PrefixUpToFileContent());
        var reader = new MultipartInspectionReader();

        var outcome = await reader.ReadAsync(
            stalling, Boundary, Options(readTimeoutSeconds: 1), CancellationToken.None);

        Assert.Equal(MultipartReadStatus.TimedOut, outcome.Status);
    }

    /// <summary>
    /// A deadline that elapses before a single part header has been read is the same status. The
    /// caller, not the reader, knows whether the body behind it is complete.
    /// </summary>
    [Fact]
    public async Task ReadDeadlineBeforeAnyPart_AlsoProducesTimedOut()
    {
        var stalling = new StallingStream([]);
        var reader = new MultipartInspectionReader();

        var outcome = await reader.ReadAsync(
            stalling, Boundary, Options(readTimeoutSeconds: 1), CancellationToken.None);

        Assert.Equal(MultipartReadStatus.TimedOut, outcome.Status);
        Assert.Empty(outcome.Files);
    }

    // =================================================================================================
    // 8. Disk-freedom, asserted rather than assumed
    // =================================================================================================

    /// <summary>
    /// AGENTS.md says a suspicious upload is never stored on disk, without qualification, and this
    /// is the test that makes that falsifiable rather than aspirational. Every temporary-directory
    /// environment variable the framework consults — including <c>ASPNETCORE_TEMP</c>, which is
    /// what <c>FileBufferingReadStream</c> reads — is redirected into an empty directory for the
    /// duration, a representative battery of reads is run through it, and the directory has to
    /// still be empty afterwards.
    /// </summary>
    [Fact]
    public async Task ReadingBodiesOfEveryShape_CreatesNoFileOnDisk()
    {
        var probe = Directory.CreateTempSubdirectory("wpshield-disk-probe-");
        var restore = RedirectTemporaryDirectory(probe.FullName);

        try
        {
            var large = new MultipartBodyBuilder()
                .File("async-upload", "large.bin", "application/octet-stream", Sequential(2 * 1024 * 1024))
                .Build();
            await ReadAsync(large);

            var many = new MultipartBodyBuilder();
            for (var index = 0; index < 30; index++)
            {
                many.File($"file-{index}", $"file-{index}.bin", "application/octet-stream", Sequential(64 * 1024));
            }

            await ReadAsync(many.Build());
            await ReadAsync(Truncate(large, 1024 * 1024));
            await ReadAsync([]);
            await ReadAsync(new MultipartBodyBuilder().Part(string.Empty, "synthetic"u8.ToArray()).Build());

            Assert.Empty(Directory.EnumerateFileSystemEntries(
                probe.FullName, "*", SearchOption.AllDirectories));
        }
        finally
        {
            restore();
            probe.Delete(recursive: true);
        }
    }

    /// <summary>
    /// The structural half of the same guarantee, and the more durable one. The buffering decision
    /// was made specifically so that disk-freedom is a property of the code rather than of a
    /// configured threshold, so the assembly is checked for any reference to a type that could
    /// write one — <c>FileBufferingReadStream</c> above all, whose spill to disk is switched off by
    /// a number a future contributor can edit. A guarantee that can be undone by changing a
    /// constant is not the guarantee AGENTS.md asks for.
    /// </summary>
    [Fact]
    public void GatewayAssembly_ReferencesNoTypeThatCanWriteToDisk()
    {
        string[] forbidden =
        [
            "Microsoft.AspNetCore.WebUtilities.FileBufferingReadStream",
            "Microsoft.AspNetCore.WebUtilities.FileBufferingWriteStream",
            "System.IO.File",
            "System.IO.FileInfo",
            "System.IO.FileStream",
            "System.IO.Directory",
            "System.IO.DirectoryInfo",
            "System.IO.StreamWriter",
            "System.IO.MemoryMappedFiles.MemoryMappedFile"
        ];

        var referenced = ReferencedTypeNames(typeof(MultipartInspectionReader).Assembly.Location);

        // Positive control. A scan that silently read nothing would pass the assertion below while
        // proving nothing at all, so first prove the scan sees a type the gateway certainly uses.
        Assert.Contains("Microsoft.AspNetCore.WebUtilities.MultipartReader", referenced);

        foreach (var name in forbidden)
        {
            Assert.DoesNotContain(name, referenced);
        }
    }

    // =================================================================================================
    // 9. Sample ownership — the use-after-return the pooled scratch array invites
    // =================================================================================================

    /// <summary>
    /// The bug this exists to catch: if the sample were handed out as a window onto the pooled
    /// scratch array instead of a copy, the array's next tenant would be a different request, and
    /// one site's upload would surface in another site's evidence. Reading eight further bodies
    /// full of a different byte churns the pool; the first sample has to be unchanged afterwards.
    /// </summary>
    [Fact]
    public async Task SampleSurvivesLaterReadsThatReuseThePool()
    {
        var options = Options(sampleBytes: 4096);
        var kept = Assert.Single((await ReadAsync(
            new MultipartBodyBuilder()
                .File("async-upload", "kept.bin", "application/octet-stream", Filled(0xAA, 4096))
                .Build(),
            options)).Files);

        for (var index = 0; index < 8; index++)
        {
            await ReadAsync(
                new MultipartBodyBuilder()
                    .File("async-upload", "churn.bin", "application/octet-stream", Filled(0xBB, 4096))
                    .Build(),
                options);
        }

        Assert.Equal(4096, kept.Sample.Length);
        Assert.True(kept.Sample.Span.IndexOfAnyExcept((byte)0xAA) < 0);
    }

    /// <summary>
    /// The same hazard under the condition that actually produces it in production. The reader is
    /// documented as safe to share as a singleton, so one instance serves every concurrent request
    /// here; each read uses a distinct fill byte, and any bleed between pooled rentals shows up as
    /// a sample that is not uniform.
    /// </summary>
    [Fact]
    public async Task ConcurrentReadsThroughOneReader_DoNotShareSampleBuffers()
    {
        var reader = new MultipartInspectionReader();
        var options = Options(sampleBytes: 4096);

        var reads = Enumerable.Range(0, 24).Select(async index =>
        {
            var fill = (byte)(index + 1);
            var body = new MultipartBodyBuilder()
                .File("async-upload", $"file-{index}.bin", "application/octet-stream", Filled(fill, 8192))
                .Build();

            using var stream = new MemoryStream(body, writable: false);
            var outcome = await reader.ReadAsync(stream, Boundary, options, CancellationToken.None);

            Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
            var file = Assert.Single(outcome.Files);
            Assert.Equal(8192, file.ByteCount);
            Assert.Equal(4096, file.Sample.Length);
            Assert.True(
                file.Sample.Span.IndexOfAnyExcept(fill) < 0,
                $"sample for file-{index}.bin was contaminated by another read");
        });

        await Task.WhenAll(reads);
    }

    // =================================================================================================
    // 10. Stream contract
    // =================================================================================================

    /// <summary>
    /// The reader never seeks, which is what lets the same code path serve a forward-only stream,
    /// and it never rewinds, which is what keeps "rewind before forwarding" visible at the one call
    /// site where forgetting it would send WordPress a truncated upload.
    /// </summary>
    [Fact]
    public async Task ReadAsync_NeitherSeeksNorRewinds()
    {
        var body = new MultipartBodyBuilder()
            .File("async-upload", "photo.jpg", "image/jpeg", Filled(0x21, 4096))
            .Build();
        using var stream = new SeekRecordingStream(body);

        var outcome = await new MultipartInspectionReader().ReadAsync(
            stream, Boundary, new MultipartInspectionOptions(), CancellationToken.None);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal(0, stream.SeekCalls);
        Assert.True(stream.Position > 0, "the reader must leave the rewind to its caller");
    }

    // =================================================================================================
    // 11. Parser differentials — the bypasses an adversarial review measured against M2
    // =================================================================================================
    //
    // Every test below is one request that this reader and PHP's main/rfc1867.c read as two
    // different requests, and every one of them was measured as a working bypass against the
    // assemblies M2 shipped: WPShield inspected one thing, WordPress would have written another,
    // and the request was forwarded.
    //
    // The fix is the same shape in all four cases, and it is worth saying out loud because the
    // obvious alternative is worse. WPShield does not imitate PHP's parser — its quirks are
    // undocumented, version-dependent and occasionally deliberate, and matching them is an arms
    // race a gateway loses. Instead the reader fails closed the moment it cannot be sure it is
    // seeing what the backend will see. So the assertions here are deliberately not "WPShield now
    // finds shell.php": they are "WPShield now refuses to call this Complete", which is what turns
    // each of these into a 415 in Block mode and a warning in Monitor.

    /// <summary>
    /// <b>F1.</b> One closing delimiter in front of the body made the entire body invisible.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured against the shipped M2 assembly, this body reported <c>Complete</c> with zero files
    /// and zero fields, scored 0, and was forwarded in Block mode with nothing above Information in
    /// the log. <c>MultipartReaderStream</c> matches <c>--X</c> at offset 0, sees the trailing
    /// <c>--</c>, sets <c>FinalBoundaryFound</c> and returns <see langword="null"/> from the very
    /// first <c>ReadNextSectionAsync</c>; the loop broke on "section is null" and nothing checked
    /// whether the parse had consumed the buffer. PHP has no concept of a terminating boundary at
    /// all — <c>find_boundary</c> reads lines until one matches <c>--X</c>, and
    /// <c>multipart_buffer_headers</c> drops lines with no colon — so PHP parses the part behind the
    /// decoy and writes <c>$_FILES['f']</c>.
    /// </para>
    /// <para>
    /// The assertion that the reader still sees nothing is the deliberate half. The smuggled part
    /// remains invisible to this parser and that is fine; what changed is that a parse which did not
    /// reach the end of the body may no longer call itself
    /// <see cref="MultipartReadStatus.Complete"/>, so the caller fails closed on a body it did not
    /// actually see rather than vouching for it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ClosingDelimiterBeforeTheBody_IsMalformedRatherThanAnEmptyComplete()
    {
        var body = Concat(
            Encoding.ASCII.GetBytes($"--{Boundary}--\r\n"),
            new MultipartBodyBuilder()
                .File("f", "shell.php", null, Encoding.ASCII.GetBytes(SyntheticPhpMarker))
                .Build());

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);
        Assert.Empty(outcome.Files);
        Assert.Equal(0, outcome.FieldCount);
    }

    /// <summary>
    /// <b>F1.</b> The same trick with the decoy at the end instead of the start: a complete, benign
    /// upload, and a second complete part smuggled into the epilogue.
    /// </summary>
    /// <remarks>
    /// This variant shows what the differential costs, because here the reader does produce a file —
    /// the wrong one. WPShield inspects and passes <c>photo.jpg</c> while PHP, which keeps reading
    /// lines after a closing delimiter it does not treat as terminal, writes <c>shell.php</c>. The
    /// status is the only thing standing between that request and the media library, so the file
    /// list is asserted next to it: <c>photo.jpg</c> is what was inspected, and <c>Malformed</c> is
    /// the admission that it was not all there was.
    /// </remarks>
    [Fact]
    public async Task PartSmuggledIntoTheEpilogue_IsMalformedEvenThoughTheFirstPartParsedCleanly()
    {
        var body = Concat(
            new MultipartBodyBuilder()
                .File("async-upload", "photo.jpg", "image/jpeg", "GIF89a"u8.ToArray())
                .Build(),
            new MultipartBodyBuilder()
                .File("f", "shell.php", null, Encoding.ASCII.GetBytes(SyntheticPhpMarker))
                .Build());

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);
        Assert.Equal("photo.jpg", Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// <b>F1.</b> A bare delimiter in the epilogue, with no part behind it at all.
    /// </summary>
    /// <remarks>
    /// Nothing is smuggled here, and it is still refused. That is the point: the check is "did a
    /// delimiter appear after the close?", not "did a part appear after the close?" — because
    /// deciding whether the bytes behind the delimiter would have parsed for PHP means implementing
    /// PHP's parser, and a differential the gateway has to resolve correctly on every input is a
    /// differential the gateway has already lost.
    /// </remarks>
    [Fact]
    public async Task DelimiterInsideTheEpilogue_IsMalformedWithNoPartBehindIt()
    {
        var body = Concat(
            new MultipartBodyBuilder()
                .File("async-upload", "photo.jpg", "image/jpeg", "GIF89a"u8.ToArray())
                .Build(),
            Encoding.ASCII.GetBytes($"Thank you for uploading.\r\n--{Boundary}\r\nnothing follows\r\n"));

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);
        Assert.Equal("photo.jpg", Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// <b>F1.</b> The closing delimiter in the middle of an otherwise ordinary body, which hides
    /// every part after a benign first one.
    /// </summary>
    /// <remarks>
    /// The shape a real attacker would reach for, because the request looks entirely normal to
    /// anyone reading a log: one photograph, forwarded, nothing found. Everything after the stray
    /// close was never parsed by WPShield, and all of it is parsed by PHP. Two parts are hidden
    /// rather than one on purpose — with a single part on each side of the stray delimiter this
    /// body would be byte-for-byte the one
    /// <c>PartSmuggledIntoTheEpilogue_IsMalformedEvenThoughTheFirstPartParsedCleanly</c> sends, and
    /// a second test asserting the same bytes under a different name proves nothing twice.
    /// </remarks>
    [Fact]
    public async Task ClosingDelimiterInTheMiddle_IsMalformedAndHidesEverythingAfterIt()
    {
        var body = Concat(
            new MultipartBodyBuilder()
                .File("async-upload", "photo.jpg", "image/jpeg", "GIF89a"u8.ToArray())
                .BuildWithoutFinalDelimiter(),
            Encoding.ASCII.GetBytes($"--{Boundary}--\r\n"),
            new MultipartBodyBuilder()
                .File("f", "shell.php", null, Encoding.ASCII.GetBytes(SyntheticPhpMarker))
                .File("g", "web.config", null, "<configuration/>"u8.ToArray())
                .Build());

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);
        Assert.Equal("photo.jpg", Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// The false-positive fence for F1: a file whose own bytes contain the client's delimiter, but
    /// never at the start of a line.
    /// </summary>
    /// <remarks>
    /// A delimiter counts only at a line start — the first byte of the body, or a byte after CR or
    /// LF — which is a superset of what <c>MultipartReaderStream</c> requires (a leading CRLF) and
    /// of what PHP's line-oriented <c>find_boundary</c> requires (a leading LF), so nothing either
    /// parser would act on can be missed. Without the line-start requirement, any file that happened
    /// to quote the boundary — a saved HTTP trace, a bug report, a test fixture like this one —
    /// would become a 415 in Block mode. That is a false positive on precisely the upload a site
    /// owner uses to report a WPShield problem.
    /// </remarks>
    [Fact]
    public async Task DelimiterInsideFileContentButNotAtALineStart_IsStillComplete()
    {
        var content = Encoding.ASCII.GetBytes($"GIF89a a support ticket quoting --{Boundary} mid-line");
        var body = new MultipartBodyBuilder()
            .File("async-upload", "trace.txt", "text/plain", content)
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal("trace.txt", Assert.Single(outcome.Files).FileName);
        Assert.Equal(content.Length, outcome.Files[0].ByteCount);
    }

    /// <summary>
    /// <b>F2.</b> A folded continuation line in a part's headers smuggles a file name past the
    /// disposition parser.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both parsers are doing something defensible, which is what let this survive review. A
    /// part-header line beginning with SP or HTAB is a folded continuation under RFC 5322, and PHP's
    /// <c>multipart_buffer_headers</c> implements exactly that — <c>space in the beginning means
    /// same header</c>, as its own comment puts it — appending the line to the previous header and
    /// then keeping the <b>last</b> <c>filename</c> it finds.
    /// <c>MultipartReader.ReadHeadersAsync</c> has no concept of folding and splits every line at
    /// the first colon, so the folded line becomes a junk header whose <i>name</i> is
    /// <c>&#32;; filename="shell.php"&#32;</c> while <c>Content-Disposition</c> keeps its first-line
    /// value. The smuggled parameter never enters <c>disposition.Parameters</c>, which is why
    /// <c>HasRepeatedFileNameParameter</c> could not see it.
    /// </para>
    /// <para>
    /// Measured on the shipped assembly: the first row reported <c>Complete</c> with
    /// <c>Fields=1</c> and no files — a form field, which is counted and never sampled and never
    /// inspected — while PHP wrote <c>$_FILES['f']</c> with <c>shell.php</c>. The second row is
    /// worse, because it reported <c>Files=[photo.jpg]</c>: WPShield inspected a benign file, found
    /// nothing, and forwarded a request that writes a different file entirely. The trailing
    /// <c>&#32;: x</c> exists only to give ASP.NET Core a colon to split on; the last row drops it
    /// and is here so the two shapes cannot drift apart — that one already failed closed, and it has
    /// to keep doing so for a reason the code states rather than by accident.
    /// </para>
    /// </remarks>
    [Theory]
    [MemberData(nameof(ObsFoldedPartHeaders))]
    public async Task ObsFoldedPartHeader_IsMalformed(string caseName, string headerBlock)
    {
        var body = new MultipartBodyBuilder()
            .Part(headerBlock, Encoding.ASCII.GetBytes(SyntheticPhpMarker))
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Malformed, outcome.Status);

        // Neither a file nor a field. The part is refused before its disposition is parsed, because
        // once GetContentDispositionHeader() has answered there is nothing left to notice.
        Assert.Empty(outcome.Files);
        Assert.Equal(0, outcome.FieldCount);
        Assert.NotNull(caseName);
    }

    public static TheoryData<string, string> ObsFoldedPartHeaders()
    {
        return new TheoryData<string, string>
        {
            // Measured: Complete, Fields=1, Files=[]. WPShield saw a form field; PHP saw shell.php.
            {
                "space fold smuggling a file name onto a field",
                "Content-Disposition: form-data; name=\"f\"\r\n ; filename=\"shell.php\" : x"
            },

            // Measured: Complete, Files=[photo.jpg]. WPShield inspected and passed the wrong file.
            {
                "space fold overriding a benign file name",
                "Content-Disposition: form-data; name=\"f\"; filename=\"photo.jpg\"\r\n" +
                " ; filename=\"shell.php\" : x"
            },

            // A tab folds identically, under RFC 5322 and under PHP's isspace() test alike.
            {
                "tab fold",
                "Content-Disposition: form-data; name=\"f\"\r\n\t; filename=\"shell.php\" : x"
            },

            // No colon on the folded line: ASP.NET Core has nothing to split on and this one already
            // failed closed. Pinned so the two shapes stay together.
            {
                "space fold with no colon on the folded line",
                "Content-Disposition: form-data; name=\"f\"\r\n ; filename=\"shell.php\""
            }
        };
    }

    /// <summary>
    /// The false-positive fence for F2: whitespace <i>after</i> the colon is ordinary and must not
    /// be read as a fold.
    /// </summary>
    /// <remarks>
    /// The test is on the header name the framework produced, not on the raw line, and such a name
    /// can begin with SP or HTAB only if the line was a continuation. Header values are routinely
    /// padded — a double space after the colon is legal and some clients emit a tab — so a check
    /// written against the raw line instead would refuse real uploads.
    /// </remarks>
    [Fact]
    public async Task PartHeaderWithPaddedValues_IsNotMistakenForAFold()
    {
        var body = new MultipartBodyBuilder()
            .Part(
                "Content-Disposition:  form-data; name=\"async-upload\"; filename=\"photo.jpg\"\r\n" +
                "Content-Type:\timage/jpeg",
                "GIF89a"u8.ToArray())
            .Build();

        var outcome = await ReadAsync(body);

        Assert.Equal(MultipartReadStatus.Complete, outcome.Status);
        Assert.Equal("photo.jpg", Assert.Single(outcome.Files).FileName);
    }

    /// <summary>
    /// <b>F3.</b> A comma in <c>Content-Type</c> used to mean WPShield never noticed the request was
    /// multipart at all.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are the five values the review measured against the shipped assembly. Only the first
    /// was inspected; the other four answered <see langword="false"/> to <i>both</i> halves of the
    /// fail-closed pairing in <c>UploadInspectionService</c> — no usable boundary <i>and</i> not
    /// multipart — so the request streamed through with no buffer, no rule and no log line, while
    /// PHP took <c>boundary_end = strpbrk(boundary, ",;")</c>, got <c>aaa</c>, and populated
    /// <c>$_FILES</c>. One trailing comma was a complete bypass of every rule WPShield ships.
    /// </para>
    /// <para>
    /// The cause was that <c>DeclaresMultipartFormData</c> asked
    /// <c>MediaTypeHeaderValue.TryParse</c>, a strict whole-value parser that treats a comma as a
    /// value separator. A strict parser may decide whether a value is <i>usable</i>; it must never
    /// decide whether a request is <i>in scope</i>. So the first assertion is the one that matters
    /// in every row: the declaration is now matched textually and is <see langword="true"/>
    /// throughout, which is what turns rows two to five into <c>Malformed</c> and a 415 instead of
    /// into silence.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("multipart/form-data; boundary=aaa", true)]
    [InlineData("multipart/form-data; boundary=aaa,", false)]
    [InlineData("multipart/form-data; boundary=aaa,bbb", false)]
    [InlineData("multipart/form-data; boundary=aaa, application/json", false)]
    [InlineData("multipart/form-data;boundary=----WebKitFormBoundaryABC,", false)]
    public void ContentTypeWithAComma_IsStillInScopeEvenWhenItsBoundaryIsUnusable(
        string contentType, bool boundaryUsable)
    {
        var request = Request(contentType);

        Assert.True(MultipartInspectionReader.DeclaresMultipartFormData(request));
        Assert.Equal(
            boundaryUsable,
            MultipartInspectionReader.TryGetBoundary(request, new MultipartInspectionOptions(), out _));
    }

    /// <summary>
    /// The false-positive fence for F3: a textual match must be a match on the <i>media type</i>,
    /// not a substring search of the header.
    /// </summary>
    /// <remarks>
    /// Widening <c>DeclaresMultipartFormData</c> is only safe while it stays exact. A substring
    /// search would put every <c>application/json</c> request carrying the string in a parameter
    /// onto the buffered path, and <c>StartsWith</c> would do the same for
    /// <c>multipart/form-data-x</c>. Neither reaches <c>rfc1867_post_handler</c> — PHP's lookup is
    /// an exact hash match on the type — so inspecting them would cost memory and, in Block mode,
    /// refuse traffic PHP treats as an ordinary body.
    /// </remarks>
    [Theory]
    [InlineData("application/json; x=multipart/form-data")]
    [InlineData("multipart/form-data-x; boundary=aaa")]
    [InlineData("multipart/form-datax; boundary=aaa")]
    [InlineData("\"multipart/form-data\"; boundary=aaa")]
    [InlineData("application/x-www-form-urlencoded")]
    public void ContentTypeThatMerelyMentionsMultipart_IsNotInScope(string contentType)
    {
        Assert.False(MultipartInspectionReader.DeclaresMultipartFormData(Request(contentType)));
    }

    /// <summary>
    /// The other half of F3's fence: the spacing and casing variants that <i>are</i> in scope,
    /// because each one can still become an upload on the backend.
    /// </summary>
    /// <remarks>
    /// The HTAB row is the interesting one. PHP does <i>not</i> terminate its media-type lookup on a
    /// tab, so <c>multipart/form-data\t;boundary=x</c> reaches PHP as an unknown type and never
    /// populates <c>$_FILES</c> — WPShield still treats it as in scope, because the direction to err
    /// in is inspecting a request the backend will ignore, never ignoring one the backend will act
    /// on.
    /// </remarks>
    [Theory]
    [InlineData("multipart/form-data;boundary=aaa")]
    [InlineData("multipart/form-data ; boundary=aaa")]
    [InlineData("multipart/form-data\t; boundary=aaa")]
    [InlineData("  multipart/form-data; boundary=aaa")]
    [InlineData("MULTIPART/FORM-DATA; boundary=aaa")]
    public void ContentTypeWithUnusualSpacingOrCasing_IsStillInScope(string contentType)
    {
        Assert.True(MultipartInspectionReader.DeclaresMultipartFormData(Request(contentType)));
    }

    /// <summary>
    /// <b>F3b.</b> The doubled-<c>filename</c> differential one level up: a doubled — or merely
    /// PHP-visible — <c>boundary</c>, which makes the two ends disagree about where every part of
    /// the body begins.
    /// </summary>
    /// <remarks>
    /// <c>boundary=aaa; boundary=bbb</c> hands <c>MediaTypeHeaderValue.Boundary</c> the first match,
    /// and nothing says IIS, ARR and PHP agree with it. <c>xboundary=bbb; boundary=aaa</c> parses as
    /// two distinct parameters, so WPShield gets <c>aaa</c>, while PHP's
    /// <c>strstr(content_type, "boundary")</c> matches inside <c>xboundary</c> and gets <c>bbb</c>.
    /// The review confirmed with a probe that one body can be valid multipart under both boundaries
    /// at once, presenting <c>photo.jpg</c> to the reading WPShield takes and <c>shell.php</c> to the
    /// reading PHP takes; <c>BlockMode_ShadowedBoundaryParameter_Returns415AndReachesNoBackend</c>
    /// in the integration suite sends exactly that body.
    /// </remarks>
    [Theory]
    [InlineData("multipart/form-data; boundary=aaa; boundary=bbb")]
    [InlineData("multipart/form-data; xboundary=bbb; boundary=aaa")]
    [InlineData("multipart/form-data; BOUNDARY=aaa; boundary=bbb")]
    public void AmbiguousBoundaryParameter_IsRefusedRatherThanResolved(string contentType)
    {
        var request = Request(contentType);

        Assert.True(MultipartInspectionReader.DeclaresMultipartFormData(request));
        Assert.False(MultipartInspectionReader.TryGetBoundary(
            request, new MultipartInspectionOptions(), out var boundary));
        Assert.Equal(string.Empty, boundary);
    }

    // =================================================================================================
    // Helpers
    // =================================================================================================

    private static async Task<MultipartInspectionOutcome> ReadAsync(
        byte[] body,
        MultipartInspectionOptions? options = null,
        string boundary = Boundary,
        CancellationToken cancellationToken = default)
    {
        using var stream = new MemoryStream(body, writable: false);
        return await new MultipartInspectionReader().ReadAsync(
            stream, boundary, options ?? new MultipartInspectionOptions(), cancellationToken);
    }

    private static MultipartInspectionOptions Options(
        int? sampleBytes = null,
        int? maximumFileCount = null,
        int? maximumFieldCount = null,
        int? maximumPartHeaderBytes = null,
        int? readTimeoutSeconds = null)
    {
        var defaults = new MultipartInspectionOptions();
        return new MultipartInspectionOptions
        {
            SampleBytes = sampleBytes ?? defaults.SampleBytes,
            MaximumFileCount = maximumFileCount ?? defaults.MaximumFileCount,
            MaximumFieldCount = maximumFieldCount ?? defaults.MaximumFieldCount,
            MaximumPartHeaderBytes = maximumPartHeaderBytes ?? defaults.MaximumPartHeaderBytes,
            ReadTimeoutSeconds = readTimeoutSeconds ?? defaults.ReadTimeoutSeconds
        };
    }

    private static HttpRequest Request(params string[] contentTypes)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.ContentType = new StringValues(contentTypes);
        return context.Request;
    }

    private static byte[] Filled(byte value, int count)
    {
        var buffer = new byte[count];
        Array.Fill(buffer, value);
        return buffer;
    }

    private static byte[] Sequential(int count)
    {
        var buffer = new byte[count];
        for (var index = 0; index < count; index++)
        {
            buffer[index] = (byte)(index % 251);
        }

        return buffer;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var combined = new byte[parts.Sum(part => part.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(combined, offset);
            offset += part.Length;
        }

        return combined;
    }

    private static byte[] Truncate(byte[] body, int keepBytes)
    {
        return body.AsSpan(0, Math.Min(keepBytes, body.Length)).ToArray();
    }

    /// <summary>
    /// The bytes of a multipart body up to and including the first part's headers, so a stalling
    /// stream can hand out a well-formed prefix and then stop inside the file content.
    /// </summary>
    private static byte[] PrefixUpToFileContent()
    {
        return Encoding.ASCII.GetBytes(
            $"--{Boundary}\r\n" +
            "Content-Disposition: form-data; name=\"async-upload\"; filename=\"photo.jpg\"\r\n" +
            "Content-Type: image/jpeg\r\n\r\n" +
            "GIF89a");
    }

    private static Action RedirectTemporaryDirectory(string path)
    {
        string[] names = ["ASPNETCORE_TEMP", "TMP", "TEMP", "TMPDIR"];
        var previous = names.ToDictionary(
            name => name, Environment.GetEnvironmentVariable, StringComparer.Ordinal);

        foreach (var name in names)
        {
            Environment.SetEnvironmentVariable(name, path);
        }

        return () =>
        {
            foreach (var (name, value) in previous)
            {
                Environment.SetEnvironmentVariable(name, value);
            }
        };
    }

    private static HashSet<string> ReferencedTypeNames(string assemblyPath)
    {
        using var stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream);
        var metadata = peReader.GetMetadataReader();
        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var handle in metadata.TypeReferences)
        {
            var reference = metadata.GetTypeReference(handle);
            var typeNamespace = metadata.GetString(reference.Namespace);
            var name = metadata.GetString(reference.Name);
            names.Add(typeNamespace.Length == 0 ? name : $"{typeNamespace}.{name}");
        }

        return names;
    }

    /// <summary>
    /// Assembles multipart bodies as raw bytes, including the shapes a well-behaved HTTP client
    /// would refuse to produce.
    /// </summary>
    private sealed class MultipartBodyBuilder(string boundary = Boundary)
    {
        private readonly MemoryStream _buffer = new();

        public MultipartBodyBuilder Field(string name, string value)
        {
            return Part(
                $"Content-Disposition: form-data; name=\"{name}\"", Encoding.UTF8.GetBytes(value));
        }

        public MultipartBodyBuilder File(
            string fieldName, string fileName, string? contentType, byte[] content)
        {
            var headers = $"Content-Disposition: form-data; name=\"{fieldName}\"; filename=\"{fileName}\"";
            if (contentType is not null)
            {
                headers += $"\r\nContent-Type: {contentType}";
            }

            return Part(headers, content);
        }

        /// <summary>
        /// Writes one part with a verbatim header block. An empty block produces a part with no
        /// headers at all, which is not a shape any client library will build for you.
        /// </summary>
        public MultipartBodyBuilder Part(string headerBlock, byte[] content)
        {
            Write($"--{boundary}\r\n");
            if (headerBlock.Length > 0)
            {
                Write(headerBlock);
                Write("\r\n");
            }

            Write("\r\n");
            _buffer.Write(content);
            Write("\r\n");
            return this;
        }

        public byte[] Build()
        {
            var complete = new MemoryStream();
            _buffer.Position = 0;
            _buffer.CopyTo(complete);
            complete.Write(Encoding.ASCII.GetBytes($"--{boundary}--\r\n"));
            return complete.ToArray();
        }

        public byte[] BuildWithoutFinalDelimiter()
        {
            return _buffer.ToArray();
        }

        private void Write(string value)
        {
            _buffer.Write(Encoding.UTF8.GetBytes(value));
        }
    }

    /// <summary>
    /// Hands out a prefix and then stops responding, honouring cancellation. It stands in for the
    /// slow client that the read deadline exists to bound — the only case in which one request can
    /// pin a pooled buffer for as long as it likes.
    /// </summary>
    private sealed class StallingStream(byte[] prefix) : Stream
    {
        private readonly TaskCompletionSource _stalled =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private int _position;

        /// <summary>
        /// Completes the first time the stream runs out of prefix, so a test can cancel at a
        /// deterministic point instead of racing a timer.
        /// </summary>
        public Task StalledAsync => _stalled.Task;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position < prefix.Length)
            {
                var count = Math.Min(buffer.Length, prefix.Length - _position);
                prefix.AsSpan(_position, count).CopyTo(buffer.Span);
                _position += count;
                return count;
            }

            _stalled.TrySetResult();
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        // Synchronous reads would block the deadline out of existence. Throwing makes an accidental
        // synchronous path a loud test failure rather than a hung test run.
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("The stalling stream is asynchronous only.");

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    /// <summary>
    /// A seekable stream that records whether the reader ever seeks. The reader's contract is that
    /// it reads forward only and leaves the position for the caller to reset.
    /// </summary>
    private sealed class SeekRecordingStream(byte[] content) : Stream
    {
        private readonly MemoryStream _inner = new(content, writable: false);

        public int SeekCalls { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set
            {
                SeekCalls++;
                _inner.Position = value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            _inner.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _inner.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _inner.ReadAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
        {
            SeekCalls++;
            return _inner.Seek(offset, origin);
        }

        public override void Flush() => _inner.Flush();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
