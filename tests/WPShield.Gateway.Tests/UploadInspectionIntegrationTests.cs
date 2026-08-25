using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace WPShield.Gateway.Tests;

/// <summary>
/// End-to-end proof that the inspection engine actually runs on live traffic.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this suite exists.</b> Before M2 the gateway resolved a site, checked
/// <c>Content-Length</c>, and forwarded — the rules ran only from the <c>WPShield.Service</c>
/// console demonstration, and <c>WPShield.Gateway.csproj</c> did not even reference the rules
/// project. Every rule test in the repository passed while not one of those rules could fire on a
/// real request. Unit tests cannot detect that class of failure, because the thing that was broken
/// was the wiring between components that each worked. So every test here drives a real Kestrel
/// gateway, on a dynamically allocated loopback port, against real synthetic backends, and asks the
/// only question that matters: what did WordPress actually receive?
/// </para>
/// <para>
/// <b>The backends record raw bytes, not parsed forms.</b> A synthetic backend that parsed the
/// multipart body would hide exactly the defect worth catching — a gateway that re-encodes a
/// buffered body, drops the final CRLF, or forwards from a non-zero stream position produces a body
/// that still parses but is not the one the client sent. Comparing the byte array the test built
/// against the byte array the backend read is what makes "forwarded intact" a fact rather than an
/// assumption, and it is the single assertion that makes Monitor mode safe to deploy.
/// </para>
/// <para>
/// <b>No weaponized samples.</b> The dangerous fixtures are named to trip the name and content
/// rules and their bodies are harmless synthetic markers. A file called <c>shell.php</c> containing
/// <c>&lt;?php echo 'synthetic marker';</c> scores exactly as a real webshell does, because the
/// rules match structure, not behaviour.
/// </para>
/// </remarks>
public sealed class UploadInspectionIntegrationTests
{
    // Placeholder hosts only. These are the two names the repository is allowed to commit; a real
    // hostname in a test fixture is a real hostname in the git history forever.
    private const string SiteOneHost = "wordpress-one.example";
    private const string SiteTwoHost = "wordpress-two.example";

    // WordPress posts every media-library upload here, which is also why MapFallback had to stop
    // using the "{*path:nonfile}" default: a pattern that rejects dotted last segments would have
    // 404'd this route and no upload would ever have reached the inspection stage.
    private const string UploadPath = "/wp-admin/async-upload.php";

    private const string SyntheticPhpMarker = "<?php echo 'synthetic marker';";

    #region Monitor mode — the default, and the mode that must never refuse a request

    /// <summary>
    /// The load-bearing Monitor assertion: a request that scores past the block threshold is still
    /// delivered to WordPress unchanged, and the finding is recorded.
    /// </summary>
    /// <remarks>
    /// Monitor's entire value is that an operator can enable WPShield in front of a live site and
    /// learn what it would have blocked without risking a single refused upload. If buffering
    /// changed one byte of the body, or dropped the boundary parameter from the forwarded
    /// <c>Content-Type</c>, Monitor would silently corrupt uploads while reporting success — the
    /// worst possible failure, because it would be attributed to WordPress rather than to WPShield.
    /// </remarks>
    [Fact]
    public async Task MonitorMode_DangerousUpload_IsForwardedByteForByteAndRecorded()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var body = new MultipartBuilder()
            .AddField("action", "upload-attachment")
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var received = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal("POST", received.Method);
        Assert.Equal(UploadPath, received.PathAndQuery);

        // The boundary must survive verbatim. A re-serialized Content-Type would still parse, so a
        // laxer assertion here would pass against a gateway that rewrote the header.
        Assert.Equal(body.ContentType, received.ContentType);
        AssertBodyForwardedIntact(body, received);

        // ...and the inspection genuinely ran. WP-UPLOAD-001 scores 90 for a final .php extension
        // and PHP-CONTENT-001 adds 75, saturating at 100.
        Assert.Contains("Upload finding.", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("WP-UPLOAD-001", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("PHP-CONTENT-001", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Score=100", harness.LogText, StringComparison.Ordinal);

        // Observe, not Block: the engine owns the Monitor downgrade and the gateway reads its
        // decision rather than re-deriving one from the thresholds.
        Assert.Contains("Action=Observe", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Disposition=forwarded", harness.LogText, StringComparison.Ordinal);

        // The one field that answers "what happens if I turn Block on here?" from logs an operator
        // already has. Running Monitor first is pointless without it.
        Assert.Contains("WouldBlock=True", harness.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MonitorMode_BenignUpload_IsForwardedUnchangedWithNoFinding()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var body = new MultipartBuilder()
            .AddField("action", "upload-attachment")
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var received = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal(body.ContentType, received.ContentType);
        AssertBodyForwardedIntact(body, received);

        // Silence is the assertion. A media library uploading ordinary photographs is the traffic
        // this gateway spends most of its life in front of, and a rule set that scores it above
        // zero is a rule set that gets switched off.
        Assert.DoesNotContain("Upload finding.", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Score=0", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Action=Allow", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("WouldBlock=False", harness.LogText, StringComparison.Ordinal);
    }

    /// <summary>
    /// Score is the maximum across files, never the sum, and this is where that shows.
    /// </summary>
    /// <remarks>
    /// Two benign files accompany one dangerous one. Summing across parts would let a bulk upload
    /// of harmless files reach the block threshold on its own — <c>FILE-NAME-001</c> alone scores 60
    /// and fires on the full-local-path names some legacy clients still send, so three such files
    /// would block a request in which nothing is wrong.
    /// </remarks>
    [Fact]
    public async Task MonitorMode_MultiFileUploadWithOneDangerousFile_ReportsOnlyThatFile()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var body = new MultipartBuilder()
            .AddFile("file0", "notes.txt", "text/plain", BenignText())
            .AddFile("file1", "photo.jpg", "image/jpeg", BenignJpeg())
            .AddFile("file2", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .AddFile("file3", "diagram.jpg", "image/jpeg", BenignJpeg())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var received = Assert.Single(harness.SiteOne.Requests);
        AssertBodyForwardedIntact(body, received);

        // One finding event, for part index 2 only. One event per file rather than per finding is
        // what bounds log volume at the file count the operator configured.
        var findings = harness.Records
            .Where(record => record.Text.Contains("Upload finding.", StringComparison.Ordinal))
            .ToArray();
        var finding = Assert.Single(findings);
        Assert.Contains("PartIndex=2", finding.Text, StringComparison.Ordinal);
        Assert.Contains("NormalizedName=shell.php", finding.Text, StringComparison.Ordinal);
        Assert.Contains("Files=4", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Score=100", harness.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DisabledSiteMode_ForwardsDangerousUploadWithoutBufferingOrInspecting()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Disabled");
        var body = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertBodyForwardedIntact(body, Assert.Single(harness.SiteOne.Requests));

        // Disabled must cost nothing: no buffer, no sample, no rule evaluation. The absence of the
        // summary line is the observable proof that the stage returned before reading a byte.
        Assert.DoesNotContain("Upload inspection complete.", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Site protection disabled", harness.LogText, StringComparison.Ordinal);
    }

    /// <summary>
    /// The operator escape hatch, and the state nobody should reach without noticing.
    /// </summary>
    [Fact]
    public async Task MultipartInspectionDisabled_ForwardsDangerousUploadAndSaysSoAtStartup()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(multipartEnabled: false);
        var body = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertBodyForwardedIntact(body, Assert.Single(harness.SiteOne.Requests));
        Assert.DoesNotContain("Upload inspection complete.", harness.LogText, StringComparison.Ordinal);

        // A gateway with inspection off is a reverse proxy with a size limit. That is a legitimate
        // incident decision and an illegitimate accident, so it is announced at Warning.
        Assert.Contains(
            harness.Records,
            record => record.Level == LogLevel.Warning &&
                      record.Text.Contains("Multipart upload inspection is DISABLED", StringComparison.Ordinal));
    }

    #endregion

    #region Block mode — the request must not reach WordPress at all

    /// <summary>
    /// Blocking means the backend never sees the request. Not a truncated body, not a body with an
    /// error status returned afterwards — nothing.
    /// </summary>
    /// <remarks>
    /// This is why the pipeline buffers. A streaming gateway that decides mid-body has already
    /// delivered a prefix to WordPress by the time it refuses, and for an upload a prefix is enough
    /// to create a partial file on disk. Asserting the backend's request list is empty is the only
    /// assertion that distinguishes "refused" from "refused after leaking".
    /// </remarks>
    [Fact]
    public async Task BlockMode_DangerousUpload_ReachesNoBackendAtAll()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var body = new MultipartBuilder()
            .AddField("action", "upload-attachment")
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Empty(harness.SiteTwo.Requests);

        Assert.Contains("Action=Block", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("Disposition=blocked", harness.LogText, StringComparison.Ordinal);

        // Warning, not Error. A blocked upload is WPShield working; an operator alerting on Error
        // must not be paged because somebody tried to upload web.config.
        Assert.DoesNotContain(harness.Records, record => record.Level >= LogLevel.Error);
    }

    /// <summary>
    /// What the refusal body may say, and — the harder half — what it may not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rule identifiers are disclosed because the complete catalogue, with identifiers, scores and
    /// matching logic, is already published in this repository. Withholding them protects nothing an
    /// attacker cannot read, while the cost falls entirely on a site owner staring at an opaque 403.
    /// </para>
    /// <para>
    /// The score is withheld for the exact opposite reason, and that is the assertion worth having:
    /// a binary allow/deny forces an attacker to search blind, whereas a numeric score turns evasion
    /// into hill-climbing because every mutation reports how much closer it got. So this test
    /// asserts on the absence of a number, which is the kind of thing that gets added back by a
    /// well-meaning "make the error more helpful" change unless a test refuses it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task BlockMode_RefusalBody_CarriesRequestIdAndRuleIdsAndNothingDerived()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var body = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        Assert.Equal("upload_blocked", root.GetProperty("error").GetString());

        // The correlation identifier in the body must be the one in the header, or an operator
        // cannot join a user's screenshot to a log line — which is the whole point of returning it.
        var headerRequestId = response.Headers.GetValues("X-WPShield-Request-ID").Single();
        Assert.Equal(headerRequestId, root.GetProperty("requestId").GetString());

        var ruleIds = root.GetProperty("ruleIds").EnumerateArray().Select(element => element.GetString()).ToArray();
        Assert.Contains("WP-UPLOAD-001", ruleIds);

        // A content decision is not an inspectability failure, so no narrower reason is offered.
        Assert.False(root.TryGetProperty("reason", out _));

        // Nothing derived, nothing attacker-supplied, nothing about the deployment.
        Assert.DoesNotContain("score", payload, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("threshold", payload, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shell.php", payload, StringComparison.Ordinal);
        Assert.DoesNotContain("async-upload", payload, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic marker", payload, StringComparison.Ordinal);
        Assert.DoesNotContain("<?php", payload, StringComparison.Ordinal);
        Assert.DoesNotContain("wordpress-one", payload, StringComparison.Ordinal);

        // Documented on every generated response, and previously true of only some of them:
        // HttpResponse.Clear() wipes headers, so the 413 and 502 writers used to erase both of these.
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task BlockMode_BenignUpload_IsStillForwarded()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var body = new MultipartBuilder()
            .AddField("action", "upload-attachment")
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        // Block mode is not a kill switch for uploads. If enabling it stopped ordinary media from
        // reaching WordPress, no operator would leave it on for a week.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var received = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal(body.ContentType, received.ContentType);
        AssertBodyForwardedIntact(body, received);
    }

    [Fact]
    public async Task BlockMode_MultiFileUploadWithOneDangerousFile_IsRefusedWhole()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var body = new MultipartBuilder()
            .AddFile("file0", "notes.txt", "text/plain", BenignText())
            .AddFile("file1", "photo.jpg", "image/jpeg", BenignJpeg())
            .AddFile("file2", "web.config", "application/octet-stream", BenignText())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);
        var payload = await response.Content.ReadAsStringAsync();

        // The request is one unit. There is no partial forward that drops the offending part,
        // because reassembling a body the client did not send is how a gateway starts producing
        // uploads WordPress cannot correlate with anything the user did.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Contains("IIS-CONFIG-001", payload, StringComparison.Ordinal);
    }

    #endregion

    #region Uninspectable bodies — the direction the design chose is "fail closed"

    /// <summary>
    /// A body that declares multipart but cannot be parsed is refused in Block mode, not forwarded.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the bypass the two-axis policy exists to close. If "the reader gave up" meant
    /// "forward it", an attacker would need one unusual <c>Content-Type</c> header to skip every
    /// rule WPShield ships — a one-line, zero-knowledge bypass, with IIS and PHP parsing the body
    /// happily on the other side.
    /// </para>
    /// <para>
    /// <b>The named false positive.</b> The 71–128 character band is real: Kestrel's own
    /// <c>FormOptions.MultipartBoundaryLengthLimit</c> defaults to 128 and PHP is at least as
    /// tolerant, so a bespoke API client with an unusual boundary generator gets a 415 once Block is
    /// on. That is the documented cost of failing closed, which is why Monitor is the default and
    /// why the condition logs at Warning first.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("multipart/form-data")]
    [InlineData("multipart/form-data; boundary=")]
    [InlineData("multipart/form-data; boundary=\"has spaces and ; separators\"")]
    public async Task BlockMode_UnusableBoundary_Returns415AndReachesNoBackend(string contentType)
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var parseable = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();
        var body = parseable with { ContentType = contentType };

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);

        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        Assert.Equal("multipart_not_inspectable", root.GetProperty("error").GetString());

        // 415 rather than 403 on purpose: 403 says "we understood this and refuse it", 415 says
        // "we cannot accept this media type as presented". Collapsing them destroys the single most
        // useful signal an operator has for telling a detection apart from a parser giving up.
        Assert.Equal("malformed", root.GetProperty("reason").GetString());
        Assert.Contains(
            "GATEWAY-MULTIPART-001",
            root.GetProperty("ruleIds").EnumerateArray().Select(element => element.GetString()));
        Assert.Contains("Multipart body could not be fully inspected.", harness.LogText, StringComparison.Ordinal);
    }

    /// <summary>
    /// A boundary longer than 70 characters. Named separately because it is the rule's entire
    /// false-positive surface and deserves to fail loudly if the length check is ever relaxed.
    /// </summary>
    [Fact]
    public async Task BlockMode_OverLongBoundary_Returns415EvenThoughKestrelWouldAcceptIt()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var overLongBoundary = new string('a', 71);
        var body = new MultipartBuilder(overLongBoundary)
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg())
            .Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Contains("\"reason\":\"malformed\"", payload, StringComparison.Ordinal);
    }

    /// <summary>
    /// Two <c>Content-Type</c> header lines. Kestrel does not reject them and
    /// <c>HttpRequest.ContentType</c> joins them with <c>", "</c>, so a gateway that parsed one value
    /// while the backend parsed the other would have inspected a different request than the one that
    /// executes. Sent over a raw socket because <c>HttpClient</c> will not emit a duplicate.
    /// </summary>
    [Fact]
    public async Task BlockMode_DuplicateContentTypeHeaders_Returns415AndReachesNoBackend()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var body = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        var response = await SendRawAsync(
            harness.Address,
            [
                $"POST {UploadPath} HTTP/1.1",
                $"Host: {SiteOneHost}",
                $"Content-Type: {body.ContentType}",
                "Content-Type: multipart/form-data; boundary=second-value",
                $"Content-Length: {body.Bytes.Length}",
                "Connection: close"
            ],
            body.Bytes);

        Assert.Equal(415, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Contains("\"error\":\"multipart_not_inspectable\"", response.Body, StringComparison.Ordinal);
        Assert.Contains("\"reason\":\"malformed\"", response.Body, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same unparseable body in Monitor mode is forwarded — intact.
    /// </summary>
    /// <remarks>
    /// This is the payoff of draining the whole bounded body before parsing any of it. Because the
    /// body is already complete in memory when the parse fails, Monitor can keep its promise to
    /// forward the request whole while still recording that it could not be inspected. An
    /// interleaved parse would have made every parse failure a partial-body failure too, and Monitor
    /// would have had to choose between corrupting the upload and blocking it.
    /// </remarks>
    [Fact]
    public async Task MonitorMode_UnusableBoundary_IsForwardedIntactAndWarned()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var parseable = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();
        var body = parseable with { ContentType = "multipart/form-data" };

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var received = Assert.Single(harness.SiteOne.Requests);
        AssertBodyForwardedIntact(body, received);
        Assert.Equal("multipart/form-data", received.ContentType);

        Assert.Contains(
            harness.Records,
            record => record.Level == LogLevel.Warning &&
                      record.Text.Contains("Multipart body could not be fully inspected.", StringComparison.Ordinal) &&
                      record.Text.Contains("Reason=malformed", StringComparison.Ordinal) &&
                      record.Text.Contains("Forwarded=True", StringComparison.Ordinal));
    }

    /// <summary>
    /// Exceeding a reader limit is itself a finding, so Block refuses rather than forwarding.
    /// </summary>
    /// <remarks>
    /// The attack is concrete: prefix the payload with more dummy parts than the reader will look
    /// at, and if "gave up" meant "forward" the twenty-first file is uninspected. Every file here is
    /// benign precisely so the 415 cannot be mistaken for a 403 — the refusal is about the limit,
    /// not about the contents.
    /// </remarks>
    [Fact]
    public async Task BlockMode_FileCountLimitExceeded_Returns415LimitExceeded()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block", maximumFileCount: 2);
        var builder = new MultipartBuilder();
        for (var index = 0; index < 5; index++)
        {
            builder.AddFile($"file{index}", $"photo{index}.jpg", "image/jpeg", BenignJpeg());
        }

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, builder.Build());
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);

        using var document = JsonDocument.Parse(payload);
        Assert.Equal("multipart_not_inspectable", document.RootElement.GetProperty("error").GetString());
        Assert.Equal("limit_exceeded", document.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task MonitorMode_FileCountLimitExceeded_IsForwardedIntactAndWarned()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(maximumFileCount: 2);
        var builder = new MultipartBuilder();
        for (var index = 0; index < 5; index++)
        {
            builder.AddFile($"file{index}", $"photo{index}.jpg", "image/jpeg", BenignJpeg());
        }

        var body = builder.Build();
        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertBodyForwardedIntact(body, Assert.Single(harness.SiteOne.Requests));
        Assert.Contains(
            harness.Records,
            record => record.Level == LogLevel.Warning &&
                      record.Text.Contains("Reason=limit_exceeded", StringComparison.Ordinal) &&
                      record.Text.Contains("Forwarded=True", StringComparison.Ordinal));
    }

    /// <summary>
    /// The limit most likely to be met by legitimate traffic: a page builder or form plugin that
    /// posts a large form with a file attached. Monitor surfaces the observed count so an operator
    /// can raise the setting before Block turns it into a refusal.
    /// </summary>
    [Fact]
    public async Task MonitorMode_FieldCountLimitExceeded_IsForwardedIntactAndReportsTheObservedCount()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(maximumFieldCount: 3);
        var builder = new MultipartBuilder();
        for (var index = 0; index < 10; index++)
        {
            builder.AddField($"field{index}", $"value{index}");
        }

        builder.AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg());
        var body = builder.Build();

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertBodyForwardedIntact(body, Assert.Single(harness.SiteOne.Requests));
        Assert.Contains("Reason=limit_exceeded", harness.LogText, StringComparison.Ordinal);
    }

    #endregion

    #region Boundary conditions the buffered path must not have regressed

    /// <summary>
    /// The pre-existing 413, with a declared length. Rejected before a byte is buffered.
    /// </summary>
    [Fact]
    public async Task DeclaredOversizedMultipartBody_Returns413WithoutReachingBackend()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(maximumRequestBytes: 4096);
        var body = new MultipartBuilder()
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg(8192))
            .Build();

        Assert.True(body.Bytes.Length > 4096, "Fixture must exceed the configured limit to be meaningful.");

        using var response = await harness.PostAsync(SiteOneHost, UploadPath, body);
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Contains("\"error\":\"request_too_large\"", payload, StringComparison.Ordinal);
        Assert.Empty(harness.SiteOne.Requests);
    }

    /// <summary>
    /// The same limit with no declared length — the case buffering could plausibly have broken.
    /// </summary>
    /// <remarks>
    /// A chunked body is the attacker-controlled case: there is no <c>Content-Length</c> to check up
    /// front, so the limit can only be enforced while reading. <c>RequestBodyLimitStream</c> is
    /// therefore installed <i>before</i> the inspection stage rather than immediately before the
    /// forward, which is what stops the drain into the pooled buffer from being unbounded. Getting
    /// that order wrong would turn the 6 MiB ceiling into a suggestion.
    /// </remarks>
    [Fact]
    public async Task ChunkedOversizedMultipartBody_Returns413WithoutReachingBackend()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(maximumRequestBytes: 4096);
        var body = new MultipartBuilder()
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg(16384))
            .Build();

        using var request = new HttpRequestMessage(HttpMethod.Post, UploadPath)
        {
            Content = new UnknownLengthContent(body.Bytes)
        };
        request.Headers.Host = SiteOneHost;
        request.Content.Headers.TryAddWithoutValidation("Content-Type", body.ContentType);

        using var response = await harness.Client.SendAsync(request);
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Contains("\"error\":\"request_too_large\"", payload, StringComparison.Ordinal);

        // Strictly better than the streamed path, where a bounded prefix has already reached the
        // backend by the time the overflow is detected. On the buffered path nothing is forwarded.
        Assert.Empty(harness.SiteOne.Requests);
    }

    /// <summary>
    /// Ordinary WordPress traffic must keep streaming through with no buffer and no added cost.
    /// </summary>
    /// <remarks>
    /// Page views, admin-ajax posts and REST calls are the overwhelming majority of what a WordPress
    /// gateway carries. If they began paying for the upload path, M2 would have traded a real
    /// detection capability for a latency and memory regression on traffic that contains no uploads
    /// at all — so the absence of the inspection summary is the assertion, not an afterthought.
    /// </remarks>
    [Theory]
    [InlineData("GET", null, null)]
    [InlineData("POST", "application/x-www-form-urlencoded", "action=heartbeat&interval=15")]
    [InlineData("POST", "application/json", "{\"title\":\"synthetic post\"}")]
    [InlineData("POST", "text/xml", "<?xml version=\"1.0\"?><methodCall/>")]
    public async Task NonMultipartTraffic_IsForwardedOnTheUnbufferedPath(
        string method,
        string? contentType,
        string? payload)
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        using var request = new HttpRequestMessage(new HttpMethod(method), "/wp-admin/admin-ajax.php");
        request.Headers.Host = SiteOneHost;

        if (payload is not null)
        {
            request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(payload));
            request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        }

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var received = Assert.Single(harness.SiteOne.Requests);
        Assert.Equal(method, received.Method);
        Assert.Equal(payload ?? string.Empty, Encoding.UTF8.GetString(received.Body));
        Assert.DoesNotContain("Upload inspection complete.", harness.LogText, StringComparison.Ordinal);

        // Note the XML-RPC row. It is forwarded uninspected by design, and that is a real coverage
        // gap rather than an oversight: no non-multipart body is inspected in M2. The test records
        // the gap so the documentation cannot quietly overstate what is covered.
    }

    /// <summary>
    /// A client that vanishes mid-upload must cost the gateway a pooled buffer and nothing else.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Someone closing a browser tab during a large upload is entirely ordinary, and it is also the
    /// one moment when the gateway is holding the most attacker-influenced memory. The three things
    /// that must not happen are a hang, a leaked buffer, and an <c>Error</c> line — the last because
    /// a component whose <c>Error</c> level fires on routine user behaviour has an <c>Error</c>
    /// level that means nothing.
    /// </para>
    /// <para>
    /// The socket is reset rather than closed politely, because a FIN would let Kestrel finish the
    /// body cleanly and the interesting path would never run. The settle delay before the reset is
    /// not padding: without it the close can land before Kestrel has parked on the body read, and
    /// the test then exercises a different, easier moment than the one it is named for.
    /// </para>
    /// <para>
    /// <b>What this test deliberately does not assert, and why.</b> The documented behaviour is that
    /// a mid-upload abort is caught by the narrow
    /// <c>catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)</c>
    /// filter in <c>GatewayApplication.ForwardRequestAsync</c> and logged at Information as "Client
    /// disconnected before the request could be forwarded." Measured on this build, that line does
    /// <i>not</i> appear once the gateway is genuinely parked in the drain: a client reset surfaces
    /// as a Kestrel connection-reset <c>IOException</c> rather than an
    /// <c>OperationCanceledException</c>, so the filter does not match and the exception leaves the
    /// handler unobserved. Asserting the log line here would produce a test that passes only when
    /// verbose logging happens to shift the race — which is exactly how a flaky test gets muted.
    /// The invariants below are the ones that hold unconditionally, and the missing line is reported
    /// as a defect against the gateway rather than encoded as a passing assertion here.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ClientDisconnectMidUpload_DoesNotHangLeakOrProduceAnError()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var body = new MultipartBuilder()
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg(65536))
            .Build();

        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, harness.Address.Port);
            var stream = client.GetStream();
            var head =
                $"POST {UploadPath} HTTP/1.1\r\n" +
                $"Host: {SiteOneHost}\r\n" +
                $"Content-Type: {body.ContentType}\r\n" +
                "Transfer-Encoding: chunked\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(head));

            // One partial chunk, then silence. The declared chunk never completes.
            var prefix = body.Bytes.AsSpan(0, 1024).ToArray();
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"{prefix.Length:x}\r\n"));
            await stream.WriteAsync(prefix);
            await stream.FlushAsync();

            // Wait until the gateway has entered the drain, then give it a moment to park on the
            // body read. Only then is the reset landing at the moment this test is about.
            await WaitForAsync(
                () => harness.LogText.Contains(UploadPath, StringComparison.Ordinal),
                TimeSpan.FromSeconds(10));
            await Task.Delay(500);

            // RST rather than FIN.
            client.Client.LingerState = new LingerOption(true, 0);
        }

        // Bounded settle. The abort is either observed or it is not; nothing here waits on a log
        // line, so this cannot become a ten-second stall when the gateway behaves differently.
        await Task.Delay(1000);

        // Nothing reached WordPress. An abort must never deliver a prefix of an upload, because a
        // prefix is enough for a partial file to appear in the media library.
        Assert.Empty(harness.SiteOne.Requests);

        // No Error line. A visitor closing a tab is routine, and a component whose Error level
        // fires on routine behaviour has an Error level that means nothing to whoever is alerting
        // on it.
        Assert.DoesNotContain(harness.Records, record => record.Level >= LogLevel.Error);

        // The gateway still works, and works correctly — a full inspect-and-forward on a fresh
        // connection. This is what "did not hang" means operationally: the abort did not wedge the
        // pipeline, exhaust the pool, or leave inspection in a state that mis-handles the next
        // upload. Asserting the body byte-for-byte, rather than just the status, is what makes it a
        // statement about the buffer having been returned cleanly rather than about liveness alone.
        var body2 = new MultipartBuilder()
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg())
            .Build();
        using var followUp = await harness.PostAsync(SiteOneHost, UploadPath, body2);
        Assert.Equal(HttpStatusCode.OK, followUp.StatusCode);
        AssertBodyForwardedIntact(body2, Assert.Single(harness.SiteOne.Requests));
    }

    /// <summary>
    /// A client that stalls mid-body gets a 408 — in Monitor mode, which is the point.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the one refusal Monitor is allowed to make, and it is not an exception to Monitor's
    /// promise but a consequence of it. Monitor promises never to block on a <i>finding</i>; a body
    /// that half arrived is not a finding, it is a request the client failed to deliver. Forwarding
    /// what arrived would hand WordPress a body shorter than its declared length, producing a
    /// corrupt upload and a backend error no operator could trace back to WPShield. The 413 sets the
    /// same precedent: absolute resource controls apply in all three modes.
    /// </para>
    /// <para>
    /// <b>The named false positive.</b> The default 30-second deadline against a 6 MiB body implies a
    /// sustained floor of roughly 205 KiB/s, so a genuinely slow mobile or satellite client
    /// uploading a full-size image can trip this and receive a 408. Raising
    /// <c>ReadTimeoutSeconds</c> toward 120 drops the floor to about 51 KiB/s. The test uses 2
    /// seconds only to keep itself fast.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task SlowClientThatStopsSending_Receives408WhileStillInMonitorMode()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(readTimeoutSeconds: 2);
        var body = new MultipartBuilder()
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg(65536))
            .Build();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, harness.Address.Port);
        var stream = client.GetStream();
        var head =
            $"POST {UploadPath} HTTP/1.1\r\n" +
            $"Host: {SiteOneHost}\r\n" +
            $"Content-Type: {body.ContentType}\r\n" +
            "Transfer-Encoding: chunked\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head));

        var prefix = body.Bytes.AsSpan(0, 1024).ToArray();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"{prefix.Length:x}\r\n"));
        await stream.WriteAsync(prefix);
        await stream.FlushAsync();

        // The socket stays open and the client simply stops sending — a stalled upload rather than
        // an abandoned one. This is the case the deadline exists for, and the case that distinguishes
        // it from client disconnect: here there is still someone to answer.
        using var readDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var received = new MemoryStream();
        try
        {
            await stream.CopyToAsync(received, readDeadline.Token);
        }
        catch (Exception exception) when (exception is IOException or OperationCanceledException)
        {
            // Expected, and not a defect. Kestrel answers the 408 and then resets, because the
            // request body was never fully consumed and there is nothing to drain it into. Bytes
            // read before the reset are already in the buffer, so the assertions below still see the
            // response — and falling through reports what arrived, which is a far better failure
            // message than "the connection was closed".
        }

        var text = Encoding.UTF8.GetString(received.ToArray());
        Assert.Contains("408", text, StringComparison.Ordinal);
        Assert.Contains("\"error\":\"request_timeout\"", text, StringComparison.Ordinal);

        // A partial body is never forwarded. This is the assertion that separates "timed out" from
        // "timed out after sending WordPress half an upload".
        Assert.Empty(harness.SiteOne.Requests);
        Assert.Contains(
            harness.Records,
            record => record.Level == LogLevel.Warning &&
                      record.Text.Contains(
                          "Multipart body did not arrive within the read deadline.",
                          StringComparison.Ordinal));
    }

    #endregion

    #region Multi-site isolation

    /// <summary>
    /// An upload addressed to one site never reaches the other site's backend.
    /// </summary>
    /// <remarks>
    /// Buffering introduced a new place where a request could be attributed to the wrong site: the
    /// inspection stage. It runs inline in the forwarding handler, after the site is resolved once,
    /// precisely so there is no second resolution to disagree with the first — two places that each
    /// decide which site a request belongs to is how a multi-tenant gateway applies site A's policy
    /// to site B's traffic.
    /// </remarks>
    [Fact]
    public async Task UploadToOneSite_NeverReachesTheOtherSitesBackend()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var body = new MultipartBuilder()
            .AddFile("async-upload", "photo.jpg", "image/jpeg", BenignJpeg())
            .Build();

        using var first = await harness.PostAsync(SiteOneHost, UploadPath, body);
        using var second = await harness.PostAsync(SiteTwoHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);

        var toSiteOne = Assert.Single(harness.SiteOne.Requests);
        var toSiteTwo = Assert.Single(harness.SiteTwo.Requests);
        Assert.Equal("wordpress-one", toSiteOne.Backend);
        Assert.Equal("wordpress-two", toSiteTwo.Backend);
        AssertBodyForwardedIntact(body, toSiteOne);
        AssertBodyForwardedIntact(body, toSiteTwo);
    }

    /// <summary>
    /// One gateway, two sites, two modes, one identical dangerous upload — and two different
    /// answers.
    /// </summary>
    /// <remarks>
    /// Per-site mode is what makes a staged rollout possible: turn Block on for one site, watch it
    /// for a week, then move the next. A gateway that read the mode from anywhere but the resolved
    /// site would pass this test's first half and fail its second, or worse, pass both by accident
    /// when the sites happen to be configured alike — which is why both halves run against the same
    /// bytes in the same process.
    /// </remarks>
    [Fact]
    public async Task PerSiteMode_IsHonouredIndependentlyWithinOneGateway()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(
            siteOneMode: "Monitor",
            siteTwoMode: "Block");
        var body = new MultipartBuilder()
            .AddFile("async-upload", "shell.php", "application/octet-stream", SyntheticPhpFile())
            .Build();

        using var monitored = await harness.PostAsync(SiteOneHost, UploadPath, body);
        using var blocked = await harness.PostAsync(SiteTwoHost, UploadPath, body);

        Assert.Equal(HttpStatusCode.OK, monitored.StatusCode);
        AssertBodyForwardedIntact(body, Assert.Single(harness.SiteOne.Requests));

        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Empty(harness.SiteTwo.Requests);

        Assert.Contains("SiteId=wordpress-one", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("SiteId=wordpress-two", harness.LogText, StringComparison.Ordinal);
    }

    #endregion

    #region Privacy — a threat-model requirement, so it is tested rather than trusted

    /// <summary>
    /// Every marker in this fixture is a string the gateway is forbidden to log, and each one is a
    /// different clause of the invariant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The raw file name is the sharpest of them. It is fully attacker-controlled and can carry
    /// control characters, ANSI escape sequences and newlines straight into a log file, a terminal
    /// or a future dashboard — which is why <c>NormalizedFileName</c> exists and why evidence
    /// records the normalized name instead. The fixture proves the distinction rather than asserting
    /// it: the raw name is <c>…\rawpath-marker\shell.php</c>, so <c>rawpath-marker</c> appearing
    /// anywhere in the logs means the raw name reached them, while <c>shell.php</c> appearing is
    /// correct and expected.
    /// </para>
    /// <para>
    /// The nonce is included because "never log nonces" is easy to satisfy by accident today and
    /// easy to break tomorrow: field parts are counted and never sampled, but the day someone
    /// decides field contents would be useful evidence, this assertion is what stops it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task MonitorMode_LogsCarryNoRawNameSampleQueryStringOrHeaderValue()
    {
        await using var harness = await UploadGatewayHarness.StartAsync();
        var body = new MultipartBuilder()
            .AddField("_wpnonce", "nonce-marker")
            .AddFile(
                "fieldname-marker",
                @"C:\Users\victim\rawpath-marker\shell.php",
                "application/x-declared-marker",
                Encoding.ASCII.GetBytes("<?php echo 'sample-content-marker';"))
            .AddFile(
                // A text body under a .jpg name is what makes FILE-TYPE-001 fire, and FILE-TYPE-001
                // is the one rule that looks at the part's declared Content-Type. Putting the marker
                // here rather than on the .php part is deliberate: it means the four-state reduction
                // (agrees / disagrees / opaque / absent) is actually exercised, so the assertion
                // that "x-declared-marker" never appears is a claim about running code rather than
                // about a code path the fixture never reached.
                "second-field-marker",
                "renamed-marker.jpg",
                "application/x-declared-marker",
                Encoding.ASCII.GetBytes(
                    "plain text pretending to be an image, sample-text-marker, padded to classify "
                    + new string('x', 512)))
            .Build();

        using var request = new HttpRequestMessage(HttpMethod.Post, UploadPath + "?secret=query-marker")
        {
            Content = new ByteArrayContent(body.Bytes)
        };
        request.Headers.Host = SiteOneHost;
        request.Content.Headers.TryAddWithoutValidation("Content-Type", body.ContentType);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer authorization-marker");
        request.Headers.TryAddWithoutValidation("Cookie", "wordpress_logged_in=cookie-marker");
        request.Headers.TryAddWithoutValidation("X-Synthetic-Header", "header-value-marker");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The inspection genuinely ran, so the assertions below are about a populated log rather
        // than an empty one — a privacy test that passes because nothing was logged proves nothing.
        Assert.Contains("Upload finding.", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("NormalizedName=shell.php", harness.LogText, StringComparison.Ordinal);

        // Proof that the bytes and the declared type were genuinely read, so the assertions below
        // are about data the gateway held and chose not to log. PHP-CONTENT-001 only fires if the
        // sample containing "sample-content-marker" was taken; FILE-TYPE-001 only fires if the
        // second part's body and declared type were both examined.
        Assert.Contains("PHP-CONTENT-001", harness.LogText, StringComparison.Ordinal);
        Assert.Contains("FILE-TYPE-001", harness.LogText, StringComparison.Ordinal);

        AssertNoForbiddenMarkers(harness.LogText);

        // The path is logged; the query string never is. Satisfying that at the source — Path.Value
        // rather than Path + QueryString — is more durable than remembering to redact one later.
        Assert.Contains("Path=" + UploadPath, harness.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BlockMode_RefusalBodyAndLogsCarryNoRawNameSampleQueryStringOrHeaderValue()
    {
        await using var harness = await UploadGatewayHarness.StartAsync(siteOneMode: "Block");
        var body = new MultipartBuilder()
            .AddField("_wpnonce", "nonce-marker")
            .AddFile(
                "fieldname-marker",
                @"C:\Users\victim\rawpath-marker\shell.php",
                "application/x-declared-marker",
                Encoding.ASCII.GetBytes("<?php echo 'sample-content-marker';"))
            .Build();

        using var request = new HttpRequestMessage(HttpMethod.Post, UploadPath + "?secret=query-marker")
        {
            Content = new ByteArrayContent(body.Bytes)
        };
        request.Headers.Host = SiteOneHost;
        request.Content.Headers.TryAddWithoutValidation("Content-Type", body.ContentType);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer authorization-marker");
        request.Headers.TryAddWithoutValidation("Cookie", "wordpress_logged_in=cookie-marker");
        request.Headers.TryAddWithoutValidation("X-Synthetic-Header", "header-value-marker");

        using var response = await harness.Client.SendAsync(request);
        var payload = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.SiteOne.Requests);

        // A refusal is the response most likely to be screenshotted, pasted into a support ticket or
        // rendered by a browser dev tool, so it is the response least able to afford reflecting
        // attacker bytes back out. Even the normalized name is withheld: safer, but worth nothing to
        // whoever sent the request.
        AssertNoForbiddenMarkers(payload);
        Assert.DoesNotContain("shell.php", payload, StringComparison.Ordinal);
        AssertNoForbiddenMarkers(harness.LogText);
    }

    private static void AssertNoForbiddenMarkers(string text)
    {
        string[] markers =
        [
            "rawpath-marker",        // the raw, attacker-controlled file name
            "fieldname-marker",      // the part's form field name
            "second-field-marker",
            "sample-content-marker", // bytes from inside the uploaded file
            "sample-text-marker",
            "x-declared-marker",     // the part's own declared Content-Type
            "nonce-marker",          // a WordPress nonce carried in a form field
            "query-marker",          // the query string
            "authorization-marker",  // the Authorization header
            "cookie-marker",         // the Cookie header
            "header-value-marker"    // an arbitrary request header value
        ];

        foreach (var marker in markers)
        {
            Assert.DoesNotContain(marker, text, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain(@"C:\Users\victim", text, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region Fixtures

    /// <summary>
    /// A file that scores exactly as a webshell does and does exactly nothing.
    /// </summary>
    /// <remarks>
    /// The rules match a final <c>.php</c> extension and the literal <c>&lt;?php</c> marker, so a
    /// harmless echo reproduces the full detection path. Committing a working webshell to obtain the
    /// same score would put an executable payload in the git history of a security tool forever.
    /// </remarks>
    private static byte[] SyntheticPhpFile()
    {
        return Encoding.ASCII.GetBytes(SyntheticPhpMarker + "\n// harmless synthetic upload fixture\n");
    }

    /// <summary>
    /// A JPEG that every rule must be silent about: a real signature at offset zero, a name that
    /// agrees with it, no script marker, and no structural anomaly.
    /// </summary>
    private static byte[] BenignJpeg(int length = 1024)
    {
        var bytes = new byte[length];
        bytes[0] = 0xFF;
        bytes[1] = 0xD8;
        bytes[2] = 0xFF;
        bytes[3] = 0xE0;
        bytes[4] = 0x00;
        bytes[5] = 0x10;
        "JFIF\0"u8.CopyTo(bytes.AsSpan(6));

        // A deterministic filler rather than zeros, so the sample looks like compressed data instead
        // of a degenerate run. Consecutive values differ by one, so the pair 0x3C 0x3F ("<?") cannot
        // occur and the fixture cannot accidentally trip a script-marker search.
        for (var index = 11; index < length; index++)
        {
            bytes[index] = (byte)(index % 251);
        }

        return bytes;
    }

    private static byte[] BenignText()
    {
        return Encoding.ASCII.GetBytes(
            "Release notes for the synthetic upload fixture.\nNothing here resembles a script.\n");
    }

    private static void AssertBodyForwardedIntact(MultipartBody sent, ReceivedRequest received)
    {
        Assert.Equal(sent.Bytes.Length, received.Body.Length);
        Assert.True(
            sent.Bytes.AsSpan().SequenceEqual(received.Body),
            "The forwarded body differed from the bytes the client sent.");
    }

    private static async Task WaitForAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && !condition())
        {
            await Task.Delay(25);
        }
    }

    #endregion

    #region Harness

    private sealed record MultipartBody(byte[] Bytes, string ContentType);

    /// <summary>
    /// Builds a multipart body as exact bytes.
    /// </summary>
    /// <remarks>
    /// <c>MultipartFormDataContent</c> was deliberately not used. It chooses its own boundary and
    /// serializes on demand, so a test could not compare what it sent against what arrived — and
    /// "the backend received a body that parses" is a much weaker claim than "the backend received
    /// these bytes". Writing the framing by hand is also what makes the malformed-boundary cases
    /// expressible at all.
    /// </remarks>
    private sealed class MultipartBuilder
    {
        private readonly string _boundary;
        private readonly MemoryStream _buffer = new();

        public MultipartBuilder(string? boundary = null)
        {
            _boundary = boundary ?? "----WPShieldSyntheticBoundary7d91f2a4";
        }

        public MultipartBuilder AddField(string name, string value)
        {
            WriteAscii($"--{_boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n");
            return this;
        }

        public MultipartBuilder AddFile(string fieldName, string fileName, string contentType, byte[] content)
        {
            WriteAscii(
                $"--{_boundary}\r\n" +
                $"Content-Disposition: form-data; name=\"{fieldName}\"; filename=\"{fileName}\"\r\n" +
                $"Content-Type: {contentType}\r\n\r\n");
            _buffer.Write(content);
            WriteAscii("\r\n");
            return this;
        }

        public MultipartBody Build()
        {
            WriteAscii($"--{_boundary}--\r\n");
            return new MultipartBody(_buffer.ToArray(), $"multipart/form-data; boundary={_boundary}");
        }

        private void WriteAscii(string text)
        {
            _buffer.Write(Encoding.ASCII.GetBytes(text));
        }
    }

    private sealed record RawResponse(int StatusCode, string Head, string Body);

    /// <summary>
    /// Sends a request over a raw socket, for the cases <c>HttpClient</c> refuses to express — a
    /// duplicate <c>Content-Type</c> being the one that matters, because that duplicate is exactly
    /// the parser differential the boundary check exists to close.
    /// </summary>
    private static async Task<RawResponse> SendRawAsync(
        Uri gateway,
        IReadOnlyList<string> requestLines,
        byte[] body)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, gateway.Port);
        var stream = client.GetStream();

        var head = new StringBuilder();
        foreach (var line in requestLines)
        {
            head.Append(line).Append("\r\n");
        }

        head.Append("\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()));
        await stream.WriteAsync(body);
        await stream.FlushAsync();

        using var received = new MemoryStream();
        await stream.CopyToAsync(received);
        var text = Encoding.UTF8.GetString(received.ToArray());

        var separator = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headText = separator < 0 ? text : text[..separator];
        var bodyText = separator < 0 ? string.Empty : text[(separator + 4)..];

        // The response is chunked, so the payload carries chunk framing. Only the JSON object is of
        // interest and it is always a single chunk at these sizes.
        var open = bodyText.IndexOf('{');
        var close = bodyText.LastIndexOf('}');
        if (open >= 0 && close > open)
        {
            bodyText = bodyText[open..(close + 1)];
        }

        var statusToken = headText.Split("\r\n")[0].Split(' ')[1];
        return new RawResponse(int.Parse(statusToken, CultureInfo.InvariantCulture), headText, bodyText);
    }

    private sealed class UnknownLengthContent(byte[] content) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            return stream.WriteAsync(content).AsTask();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class UploadGatewayHarness : IAsyncDisposable
    {
        private readonly WebApplication _gateway;
        private readonly RecordingLoggerProvider _logs;

        private UploadGatewayHarness(
            WebApplication gateway,
            HttpClient client,
            Uri address,
            SyntheticBackend siteOne,
            SyntheticBackend siteTwo,
            RecordingLoggerProvider logs)
        {
            _gateway = gateway;
            _logs = logs;
            Client = client;
            Address = address;
            SiteOne = siteOne;
            SiteTwo = siteTwo;
        }

        public HttpClient Client { get; }
        public Uri Address { get; }
        public SyntheticBackend SiteOne { get; }
        public SyntheticBackend SiteTwo { get; }
        public IReadOnlyCollection<LogRecord> Records => _logs.Records;
        public string LogText => string.Join(Environment.NewLine, _logs.Records.Select(record => record.Text));

        public static async Task<UploadGatewayHarness> StartAsync(
            string siteOneMode = "Monitor",
            string siteTwoMode = "Monitor",
            long maximumRequestBytes = 6L * 1024 * 1024,
            bool multipartEnabled = true,
            int maximumFileCount = 20,
            int maximumFieldCount = 200,
            int sampleBytes = 4096,
            int readTimeoutSeconds = 30)
        {
            var siteOne = await SyntheticBackend.StartAsync("wordpress-one");
            SyntheticBackend? siteTwo = null;
            WebApplication? gateway = null;

            try
            {
                siteTwo = await SyntheticBackend.StartAsync("wordpress-two");
                var builder = WebApplication.CreateBuilder(new WebApplicationOptions
                {
                    EnvironmentName = "Testing"
                });
                builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
                builder.Configuration.Sources.Clear();
                builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Gateway:Urls:0"] = "http://127.0.0.1:0",
                    ["Gateway:AllowRemoteHealthChecks"] = "false",
                    ["Gateway:ActivityTimeoutSeconds"] = "10",
                    ["Gateway:MaximumRequestBytes"] = maximumRequestBytes.ToString(CultureInfo.InvariantCulture),
                    ["Gateway:Multipart:Enabled"] = multipartEnabled ? "true" : "false",
                    ["Gateway:Multipart:MaximumFileCount"] =
                        maximumFileCount.ToString(CultureInfo.InvariantCulture),
                    ["Gateway:Multipart:MaximumFieldCount"] =
                        maximumFieldCount.ToString(CultureInfo.InvariantCulture),
                    ["Gateway:Multipart:MaximumPartHeaderBytes"] = "16384",
                    ["Gateway:Multipart:SampleBytes"] = sampleBytes.ToString(CultureInfo.InvariantCulture),
                    ["Gateway:Multipart:ReadTimeoutSeconds"] =
                        readTimeoutSeconds.ToString(CultureInfo.InvariantCulture),
                    ["Sites:0:Id"] = "wordpress-one",
                    ["Sites:0:Hosts:0"] = SiteOneHost,
                    ["Sites:0:Destination"] = siteOne.Address.ToString(),
                    ["Sites:0:Mode"] = siteOneMode,
                    ["Sites:0:ObserveThreshold"] = "30",
                    ["Sites:0:BlockThreshold"] = "80",
                    ["Sites:1:Id"] = "wordpress-two",
                    ["Sites:1:Hosts:0"] = SiteTwoHost,
                    ["Sites:1:Destination"] = siteTwo.Address.ToString(),
                    ["Sites:1:Mode"] = siteTwoMode,
                    ["Sites:1:ObserveThreshold"] = "30",
                    ["Sites:1:BlockThreshold"] = "80"
                });

                var logs = new RecordingLoggerProvider();
                builder.Logging.AddProvider(logs);

                gateway = GatewayApplication.Build(builder);
                await gateway.StartAsync();
                var address = GetBoundAddress(gateway);
                var client = new HttpClient { BaseAddress = address, Timeout = TimeSpan.FromSeconds(60) };
                return new UploadGatewayHarness(gateway, client, address, siteOne, siteTwo, logs);
            }
            catch
            {
                if (gateway is not null)
                {
                    await gateway.DisposeAsync();
                }

                if (siteTwo is not null)
                {
                    await siteTwo.DisposeAsync();
                }

                await siteOne.DisposeAsync();
                throw;
            }
        }

        public Task<HttpResponseMessage> PostAsync(string host, string pathAndQuery, MultipartBody body)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, pathAndQuery)
            {
                Content = new ByteArrayContent(body.Bytes)
            };
            request.Headers.Host = host;

            // TryAddWithoutValidation rather than the typed setter: the typed setter re-serializes
            // the media type, and this suite asserts the header arrives at the backend verbatim.
            request.Content.Headers.TryAddWithoutValidation("Content-Type", body.ContentType);
            return Client.SendAsync(request);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _gateway.DisposeAsync();
            await SiteTwo.DisposeAsync();
            await SiteOne.DisposeAsync();
        }
    }

    /// <summary>
    /// A backend that records raw bytes. It never parses the multipart body, because a parser would
    /// accept a re-encoded body and hide the defect this suite exists to catch.
    /// </summary>
    private sealed class SyntheticBackend : IAsyncDisposable
    {
        private readonly WebApplication _application;
        private readonly ConcurrentQueue<ReceivedRequest> _requests = new();

        private SyntheticBackend(WebApplication application, Uri address)
        {
            _application = application;
            Address = address;
        }

        public Uri Address { get; }
        public IReadOnlyCollection<ReceivedRequest> Requests => _requests;

        public static async Task<SyntheticBackend> StartAsync(string name)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
            var application = builder.Build();
            SyntheticBackend? backend = null;

            // "{*path}" explicitly, never the MapFallback default of "{*path:nonfile}". The nonfile
            // constraint rejects any path whose last segment contains a dot, so a backend using the
            // default answers 404 to /wp-admin/async-upload.php — every upload route there is. The
            // gateway carries the same fix for the same reason; a synthetic backend that kept the
            // default would fail every test here and look like a gateway bug.
            application.MapFallback("{*path}", async context =>
            {
                using var received = new MemoryStream();
                await context.Request.Body.CopyToAsync(received, context.RequestAborted);

                backend!._requests.Enqueue(new ReceivedRequest(
                    name,
                    context.Request.Method,
                    context.Request.Path + context.Request.QueryString,
                    context.Request.Headers.ContentType.ToString(),
                    received.ToArray()));

                await context.Response.WriteAsJsonAsync(new { backend = name }, context.RequestAborted);
            });

            await application.StartAsync();
            backend = new SyntheticBackend(application, GetBoundAddress(application));
            return backend;
        }

        public ValueTask DisposeAsync()
        {
            return _application.DisposeAsync();
        }
    }

    private sealed record ReceivedRequest(
        string Backend,
        string Method,
        string PathAndQuery,
        string ContentType,
        byte[] Body);

    /// <summary>
    /// One emitted log event, flattened to text.
    /// </summary>
    /// <remarks>
    /// Both the rendered message and the structured state values are captured. Checking only the
    /// rendered message would miss a leak through a structured property that a JSON or OpenTelemetry
    /// sink would happily write out, and structured logging is precisely how this gateway is meant
    /// to be consumed.
    /// </remarks>
    private sealed record LogRecord(LogLevel Level, string Category, string Text);

    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<LogRecord> _records = new();

        public IReadOnlyCollection<LogRecord> Records => _records;

        public ILogger CreateLogger(string categoryName)
        {
            return new RecordingLogger(categoryName, _records);
        }

        public void Dispose()
        {
        }

        private sealed class RecordingLogger(string category, ConcurrentQueue<LogRecord> records) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var text = new StringBuilder(formatter(state, exception));

                if (state is IReadOnlyList<KeyValuePair<string, object?>> values)
                {
                    foreach (var value in values)
                    {
                        text.Append(' ').Append(value.Key).Append('=').Append(value.Value);
                    }
                }

                if (exception is not null)
                {
                    text.Append(' ').Append(exception);
                }

                records.Enqueue(new LogRecord(logLevel, category, text.ToString()));
            }
        }
    }

    private static Uri GetBoundAddress(WebApplication application)
    {
        var addresses = application.Services
            .GetRequiredService<IServer>()
            .Features
            .Get<IServerAddressesFeature>()?
            .Addresses;
        var address = Assert.Single(addresses ?? []);
        var uri = new Uri(address);

        // Never a well-known port. A test that binds 8081 fails on the developer machine that is
        // already running the thing 8081 belongs to, and the failure looks like a product bug.
        Assert.DoesNotContain(uri.Port, new[] { 80, 443, 8081, 8082, 10000 });
        Assert.True(IPAddress.TryParse(uri.Host, out var ipAddress));
        Assert.True(IPAddress.IsLoopback(ipAddress));
        return uri;
    }

    #endregion
}
