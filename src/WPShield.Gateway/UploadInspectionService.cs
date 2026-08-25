using System.Buffers;
using System.Globalization;
using WPShield.Abstractions;
using WPShield.Core;

namespace WPShield.Gateway;

/// <summary>
/// Turns one inbound <c>multipart/form-data</c> request into a decision: forward it, or answer it.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the component the M2 milestone exists for.</b> Until it was wired in, the inspection
/// engine never ran on real traffic — the rules executed only from the <c>WPShield.Service</c>
/// console demonstration, so a gateway that documents eight upload rules was in practice a reverse
/// proxy with a size limit and an unknown-host rejection.
/// </para>
/// <para>
/// <b>Two phases, and the order is the design.</b> The whole bounded body is drained into a
/// <see cref="PooledRequestBuffer"/> first, and only then parsed and inspected. Interleaving the
/// two would be cheaper, but it would make every parse failure also a partial-body failure, and
/// Monitor mode could no longer keep its promise to forward the request intact. Draining first is
/// what lets a limit hit or a malformed body be a <i>finding</i> in Monitor rather than a refusal:
/// the body is already whole in memory, so forwarding it costs nothing.
/// </para>
/// <para>
/// <b>Why buffering at all.</b> To block, the gateway must decide before forwarding; to forward, it
/// must re-read the body; a network stream cannot be re-read. Buffering is the only way to have
/// both, and it is confined to the one case that needs it — see
/// <see cref="EvaluateAsync"/> for the three conditions, every one of which must hold before a
/// single byte is buffered.
/// </para>
/// <para>
/// <b>Statelessness.</b> Every piece of state lives in a local or in the returned decision, so a
/// single instance is safe to register as a singleton and share across concurrent requests. The
/// same is true of the <see cref="InspectionEngine"/> and every shipped rule, which is what makes
/// the singleton registrations in <c>GatewayApplication.Build</c> correct rather than merely
/// convenient.
/// </para>
/// <para>
/// This is <c>§2.1</c> of <c>docs/en/m2-inspection-pipeline-design.md</c>, which calls the type
/// <c>UploadInspectionStage</c>; the milestone assigned it this file name and the type follows the
/// file.
/// </para>
/// </remarks>
internal sealed class UploadInspectionService(InspectionEngine engine, MultipartInspectionReader reader)
{
    /// <summary>
    /// The pseudo-rule identifier the gateway emits when inspection itself could not complete.
    /// </summary>
    /// <remarks>
    /// It is emitted by the gateway, not by a rule in <c>WPShield.Rules.WordPress</c>, and it does
    /// not participate in scoring: a body the reader could not finish is a policy outcome, not a
    /// score contribution. It exists so that "WPShield could not inspect this" is as explainable
    /// from a log line or a 415 body as "WPShield found this", instead of being the one refusal an
    /// operator cannot trace. M4 should promote it to a first-class inspection event.
    /// </remarks>
    public const string MultipartPseudoRuleId = "GATEWAY-MULTIPART-001";

    /// <summary>
    /// Most rule identifiers a single response body may name.
    /// </summary>
    /// <remarks>
    /// A request at the file-count ceiling could otherwise produce a response listing dozens of
    /// identifiers, which is response amplification driven by attacker-chosen input. Sixteen is far
    /// more than any real diagnosis needs.
    /// </remarks>
    public const int MaximumReportedRuleIds = 16;

    private static readonly IReadOnlyList<string> MultipartPseudoRuleIds = [MultipartPseudoRuleId];

    /// <summary>
    /// Inspects the request when it qualifies, and reports what the gateway should do next.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The three conditions, checked cheapest first.</b> Buffering happens only when multipart
    /// inspection is enabled, the site is not <see cref="ProtectionMode.Disabled"/>, and the request
    /// actually declares <c>multipart/form-data</c>. Anything else returns
    /// <see cref="UploadInspectionDecision.NotInspected"/> before a byte is read, so ordinary
    /// WordPress page traffic — the overwhelming majority — keeps streaming exactly as it did
    /// before M2, with no buffer rented, no chunk allocated and no extra byte copied. That is not a
    /// performance nicety: a gateway that starts holding memory for every GET is a gateway an
    /// operator turns off.
    /// </para>
    /// <para>
    /// <b>Inspection is deliberately not restricted by HTTP method.</b> Limiting it to POST is
    /// tempting, since that is what PHP's multipart handler runs for, but a method allowlist is a
    /// method-shaped bypass and it buys nothing the empty-body guard does not already give.
    /// </para>
    /// <para>
    /// <b>Ownership of the buffer transfers with the return value.</b> On every path that does not
    /// hand <see cref="UploadInspectionDecision.Body"/> back to the caller — a rejection, an
    /// exception, cancellation, a body that turned out to be empty — the buffer is disposed here
    /// and its pooled chunks are returned. The caller disposes only what it receives.
    /// </para>
    /// </remarks>
    /// <param name="context">The inbound request. Its <c>Body</c> must already be wrapped in a
    /// <see cref="RequestBodyLimitStream"/> so that the drain is bounded even for a chunked body
    /// that declares no length.</param>
    /// <param name="site">The resolved site, whose mode and thresholds are the policy.</param>
    /// <param name="gatewayOptions">Gateway-wide bounds; <c>MaximumRequestBytes</c> caps the buffer.</param>
    /// <param name="multipartOptions">The multipart bounds.</param>
    /// <param name="logger">The request logger. One event per file with findings, plus a summary.</param>
    /// <param name="cancellationToken">
    /// <c>HttpContext.RequestAborted</c>. A client disconnect propagates as
    /// <see cref="OperationCanceledException"/> for the caller to classify; the read deadline is
    /// linked to it rather than replacing it.
    /// </param>
    public async ValueTask<UploadInspectionDecision> EvaluateAsync(
        HttpContext context,
        SiteOptions site,
        GatewayOptions gatewayOptions,
        MultipartInspectionOptions multipartOptions,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(site);
        ArgumentNullException.ThrowIfNull(gatewayOptions);
        ArgumentNullException.ThrowIfNull(multipartOptions);
        ArgumentNullException.ThrowIfNull(logger);

        if (!multipartOptions.Enabled)
        {
            return UploadInspectionDecision.NotInspected;
        }

        // The engine short-circuits on Disabled as well, and both guards stay. The engine's is the
        // contract; this one is what avoids the memory cost of buffering a body nobody will look at.
        if (site.Mode == ProtectionMode.Disabled)
        {
            return UploadInspectionDecision.NotInspected;
        }

        // A body of declared length zero has nothing to inspect, and buffering it would hand the
        // reader an empty stream that it correctly calls malformed — a 415 in Block mode for a
        // request that is merely odd. A chunked request declares no length, so its emptiness is not
        // knowable until it has been drained; that case is handled after the drain.
        if (context.Request.ContentLength == 0)
        {
            return UploadInspectionDecision.NotInspected;
        }

        var hasBoundary = MultipartInspectionReader.TryGetBoundary(
            context.Request, multipartOptions, out var boundary);

        // "Multipart but the boundary is unusable" and "not multipart at all" must not be confused.
        // The first fails closed as a finding; the second is ordinary traffic that keeps streaming
        // through untouched. Collapsing them either blocks every GET or hands an attacker a
        // one-line bypass, depending on which way they collapse.
        //
        // The pairing is only as good as its second half, and that half used to answer with a
        // strict media-type parser. A single trailing comma — "multipart/form-data; boundary=aaa,"
        // — made both halves say no, so an upload PHP parses happily reached this line and left it
        // as ordinary traffic: no buffer, no rule, no log. DeclaresMultipartFormData now matches the
        // media type textually for exactly this reason; it is the question "is this in scope?", and
        // a parser that rejects a value it dislikes must never be allowed to answer that one.
        if (!hasBoundary && !MultipartInspectionReader.DeclaresMultipartFormData(context.Request))
        {
            return UploadInspectionDecision.NotInspected;
        }

        // Linked to the request's own token, never replacing it: the deadline bounds how long a
        // slow client may pin a pooled buffer, and the request token is how a closed browser tab
        // stops the work immediately instead of waiting the deadline out. It is enforceable
        // independently of ForwarderRequestConfig.ActivityTimeout, which governs only the
        // forwarding leg and does not yet exist at the point the body is being drained — nothing
        // else is watching this read.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(
            multipartOptions.ReadTimeoutSeconds,
            1,
            MultipartInspectionOptions.AbsoluteMaximumReadTimeoutSeconds)));

        PooledRequestBuffer? buffer = null;
        try
        {
            buffer = new PooledRequestBuffer(gatewayOptions.MaximumRequestBytes);

            // Phase one: drain. This is the only phase that can leave a partial body, and therefore
            // the only one whose timeout cannot end in a forward.
            try
            {
                await buffer.FillFromAsync(context.Request.Body, deadline.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                logger.LogWarning(
                    "Multipart body did not arrive within the read deadline. RequestId={RequestId} SiteId={SiteId} BufferedBytes={BufferedBytes} TimeoutSeconds={TimeoutSeconds}",
                    context.TraceIdentifier,
                    site.Id,
                    buffer.Length,
                    multipartOptions.ReadTimeoutSeconds);

                // 408 in every mode, Monitor included. Monitor's promise is that WPShield never
                // blocks on a finding, and a half-arrived body is not a finding — it is a request
                // the client failed to deliver. Forwarding what arrived would send WordPress a body
                // shorter than its declared Content-Length, producing a corrupt upload and a
                // backend error the operator cannot attribute to WPShield. The 413 sets the same
                // precedent: absolute resource controls apply in all three modes.
                return UploadInspectionDecision.Rejected(
                    new GatewayRejection(StatusCodes.Status408RequestTimeout, "request_timeout", null, []));
            }

            // A chunked request that turned out to carry nothing. Nothing to inspect; let it stream
            // on as the empty body it is.
            if (buffer.Length == 0)
            {
                return UploadInspectionDecision.NotInspected;
            }

            // Phase two: parse the buffer. From here the body is complete no matter what happens,
            // because parsing never touches the network.
            MultipartInspectionOutcome outcome;
            if (hasBoundary)
            {
                try
                {
                    buffer.Position = 0;
                    outcome = await reader.ReadAsync(buffer, boundary, multipartOptions, deadline.Token);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    // A deadline reached while parsing an already-buffered body. The body is
                    // intact, so this is treated exactly like a limit being hit: Monitor forwards
                    // and warns, Block refuses. The reader converts its own deadline to TimedOut;
                    // this catch covers the shared deadline that started at the drain.
                    outcome = new MultipartInspectionOutcome([], 0, MultipartReadStatus.TimedOut);
                }
            }
            else
            {
                // Declared multipart/form-data, but with a boundary the gateway refuses to parse:
                // absent, over 70 characters, carrying bytes that could smuggle header structure
                // into the parser, spread over two Content-Type lines, comma-joined with a second
                // media type, declared twice, or shadowed by a parameter such as xboundary= that
                // PHP's strstr finds before the real one. Fail closed. Forwarding what we cannot
                // parse is a one-line bypass — an unusual boundary and the request sails through
                // uninspected while IIS and PHP parse it happily.
                //
                // Everything in that list resolves to one 415 with Reason=malformed, which is the
                // line an operator will meet first. The narrower reason is deliberately not
                // reported: it would tell whoever is probing which of the boundary rules they
                // tripped, and turn a blind search into a guided one.
                outcome = new MultipartInspectionOutcome([], 0, MultipartReadStatus.Malformed);
            }

            var assessment = await InspectFilesAsync(context, site, outcome, logger, cancellationToken);
            var decision = Decide(context, site, outcome, assessment, buffer, logger);

            if (decision.Body is not null)
            {
                // Ownership handed to the caller, which disposes it in the same finally that
                // restores HttpRequest.Body. Clearing the local is what stops this method's own
                // finally from returning chunks the forwarder is about to read from.
                buffer = null;
            }

            return decision;
        }
        finally
        {
            buffer?.Dispose();
        }
    }

    /// <summary>
    /// Runs every registered rule against every inspectable file and aggregates the results.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Max across files, never sum.</b> The engine already sums findings <i>within</i> one file
    /// and caps that at 100. Summing again <i>across</i> files would let twenty benign files at 30
    /// each reach 600 and block a request in which nothing is wrong — and <c>FILE-NAME-001</c>
    /// scores 60 and fires on the full-local-path names some legacy clients still send, so three
    /// such files would cross the block threshold on their own. Score is a property of a file, not
    /// of a request. Max also gives "one file at 90 blocks regardless of what accompanies it" for
    /// free, and it denies an attacker the dilution attack in the other direction.
    /// </para>
    /// <para>
    /// <b>Take the action, do not re-derive it.</b> <see cref="InspectionEngine.InspectAsync"/>
    /// already applies the thresholds <i>and</i> the Monitor downgrade from Block to Observe.
    /// Reading <see cref="InspectionResult.RecommendedAction"/> keeps that policy in one place; a
    /// second implementation in the gateway is exactly where a future edit forgets the downgrade
    /// and Monitor silently starts blocking.
    /// </para>
    /// </remarks>
    private async ValueTask<FileAssessment> InspectFilesAsync(
        HttpContext context,
        SiteOptions site,
        MultipartInspectionOutcome outcome,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var host = context.Request.Host.Host;
        var method = context.Request.Method;

        // Path only, never Path + QueryString. Satisfying "never log a full query string" at the
        // source is more durable than remembering to redact one later.
        var path = context.Request.Path.Value ?? "/";

        var maximumScore = 0;
        var action = InspectionAction.Allow;
        var ruleIds = new SortedSet<string>(StringComparer.Ordinal);

        for (var partIndex = 0; partIndex < outcome.Files.Count; partIndex++)
        {
            var upload = outcome.Files[partIndex];
            var inspectionContext = new InspectionContext(
                site.Id,
                host,
                method,
                path,
                upload.FileName,
                upload.DeclaredContentType,
                upload.Sample);

            var result = await engine.InspectAsync(inspectionContext, site, cancellationToken);

            if (result.Score > maximumScore)
            {
                maximumScore = result.Score;
            }

            if (result.RecommendedAction > action)
            {
                action = result.RecommendedAction;
            }

            if (result.Findings.Count == 0)
            {
                continue;
            }

            var normalizedName = inspectionContext.NormalizedFile.BaseName;
            foreach (var finding in result.Findings)
            {
                ruleIds.Add(finding.RuleId);
            }

            // One event per file, not one per finding: a request at the absolute ceilings could
            // otherwise emit 100 files x 8 rules = 800 lines. This bounds log volume at a number
            // the operator configured.
            //
            // Everything on this line is either gateway-assigned or normalized. The raw file name,
            // the field name, the sample and every header value are absent by construction — the
            // raw name in particular can carry control characters, ANSI escapes and newlines
            // straight into a log file or a terminal, which is why NormalizedFileName exists.
            logger.LogWarning(
                "Upload finding. RequestId={RequestId} SiteId={SiteId} Method={Method} Path={Path} PartIndex={PartIndex} NormalizedName={NormalizedName} Score={Score} Action={Action} RuleIds={RuleIds} Evidence={Evidence}",
                context.TraceIdentifier,
                site.Id,
                method,
                path,
                partIndex,
                normalizedName,
                result.Score,
                result.RecommendedAction,
                string.Join(',', result.Findings.Select(finding => finding.RuleId)),
                DescribeEvidence(result.Findings, partIndex, normalizedName));
        }

        return new FileAssessment(maximumScore, action, ruleIds);
    }

    /// <summary>
    /// Renders the findings' evidence, tagged with the file each came from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two keys are merged in. <c>partIndex</c> is the answer to "which file was this about" and is
    /// safe by construction: it is an integer the gateway assigned, so it cannot carry attacker
    /// bytes the way a field name could. <c>normalizedName</c> is added only when the rule did not
    /// already supply it — most rules do, but <c>PhpContentInUploadRule</c> supplies no evidence at
    /// all, so a PHP-content finding would otherwise be untraceable to a file.
    /// </para>
    /// <para>
    /// The merge builds a <b>new</b> dictionary every time. A rule's evidence belongs to the rule,
    /// some rules pass <see langword="null"/>, and mutating a dictionary a rule might have cached
    /// would be a cross-request hazard rather than merely rude.
    /// </para>
    /// <para>
    /// Rendering evidence into a log line is safe only because of an invariant the rules keep:
    /// evidence carries normalized names and members of closed token sets, never raw
    /// attacker-supplied bytes. If that ever stops being true, this method is the place it will
    /// leak from.
    /// </para>
    /// </remarks>
    private static string DescribeEvidence(
        IReadOnlyList<RuleFinding> findings,
        int partIndex,
        string normalizedName)
    {
        var parts = new List<string>();

        foreach (var finding in findings)
        {
            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["partIndex"] = partIndex.ToString(CultureInfo.InvariantCulture)
            };

            if (finding.Evidence is { } supplied)
            {
                foreach (var pair in supplied)
                {
                    evidence[pair.Key] = pair.Value;
                }
            }

            if (!evidence.ContainsKey("normalizedName"))
            {
                evidence["normalizedName"] = normalizedName;
            }

            parts.Add($"{finding.RuleId}[{string.Join(' ', evidence.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{pair.Key}={pair.Value}"))}]");
        }

        return string.Join(' ', parts);
    }

    /// <summary>
    /// Applies the two policy axes and produces the request's outcome.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The axes are independent and the more restrictive one wins. Axis one is what the rules
    /// found; axis two is whether inspection completed at all. A limit hit or a malformed body is a
    /// finding in its own right, because if "the reader gave up" meant "forward it", an attacker
    /// would prefix a payload with ten thousand dummy parts and buy a one-request, zero-knowledge
    /// bypass of every rule WPShield ships.
    /// </para>
    /// <para>
    /// 403 is checked before 415 when both apply. Both refuse the request, but 403 names the rules
    /// that fired, and a refusal an operator can trace to a rule is worth more than one that says
    /// only "could not inspect".
    /// </para>
    /// <para>
    /// <b>Monitor combined with <see cref="InspectionAction.Block"/> is unreachable by
    /// construction</b> — the engine emits Block only when the site mode is Block. There is
    /// deliberately no defensive branch for it here: a second implementation of the downgrade is
    /// worse than none, because the next person to edit one will not know which is authoritative.
    /// </para>
    /// </remarks>
    private static UploadInspectionDecision Decide(
        HttpContext context,
        SiteOptions site,
        MultipartInspectionOutcome outcome,
        FileAssessment assessment,
        PooledRequestBuffer buffer,
        ILogger logger)
    {
        var ruleIds = Cap(assessment.RuleIds);
        var blocking = site.Mode == ProtectionMode.Block;

        // Warning, not Error, for a refusal. A blocked upload is WPShield working correctly; Error
        // is reserved for the gateway failing, which is what the proxy-failure line uses. An
        // operator alerting on Error should not be paged because someone tried to upload web.config.
        if (assessment.Action == InspectionAction.Block)
        {
            LogSummary(context, site, outcome, assessment, buffer, logger, LogLevel.Warning, "blocked");
            return UploadInspectionDecision.Rejected(
                new GatewayRejection(StatusCodes.Status403Forbidden, "upload_blocked", null, ruleIds));
        }

        if (outcome.Status != MultipartReadStatus.Complete)
        {
            var reason = outcome.Status switch
            {
                MultipartReadStatus.Malformed => "malformed",
                _ => "limit_exceeded"
            };

            logger.LogWarning(
                "Multipart body could not be fully inspected. RequestId={RequestId} SiteId={SiteId} Reason={Reason} Files={FileCount} Fields={FieldCount} BufferedBytes={BufferedBytes} RuleId={RuleId} Forwarded={Forwarded}",
                context.TraceIdentifier,
                site.Id,
                reason,
                outcome.Files.Count,
                outcome.FieldCount,
                buffer.Length,
                MultipartPseudoRuleId,
                !blocking);

            if (blocking)
            {
                // 415 rather than 403 because the two mean different things to whoever reads the
                // log: 403 says "we understood this and refuse it", 415 says "we cannot accept this
                // media type as presented". Collapsing them destroys the distinction between a
                // detection and a parser giving up, which is the single most useful signal an
                // operator has for tuning the limits.
                return UploadInspectionDecision.Rejected(new GatewayRejection(
                    StatusCodes.Status415UnsupportedMediaType,
                    "multipart_not_inspectable",
                    reason,
                    MultipartPseudoRuleIds));
            }
        }

        LogSummary(
            context,
            site,
            outcome,
            assessment,
            buffer,
            logger,
            assessment.Action == InspectionAction.Allow ? LogLevel.Information : LogLevel.Warning,
            "forwarded");

        return UploadInspectionDecision.Inspected(buffer, assessment.Action, assessment.Score, ruleIds);
    }

    private static void LogSummary(
        HttpContext context,
        SiteOptions site,
        MultipartInspectionOutcome outcome,
        FileAssessment assessment,
        PooledRequestBuffer buffer,
        ILogger logger,
        LogLevel level,
        string disposition)
    {
        // WouldBlock is the field that lets an operator answer "what happens if I turn Block on for
        // this site?" from the logs they already have, which is the entire point of running Monitor
        // first. It reads site.BlockThreshold — and that is the one permitted use of a threshold
        // here. The gateway may read the thresholds for reporting and must never read them for
        // control; the line between the two is exactly one careless refactor wide.
        logger.Log(
            level,
            "Upload inspection complete. RequestId={RequestId} SiteId={SiteId} Method={Method} Path={Path} Files={FileCount} Fields={FieldCount} Status={Status} Score={Score} Action={Action} WouldBlock={WouldBlock} RuleIds={RuleIds} BufferedBytes={BufferedBytes} Disposition={Disposition}",
            context.TraceIdentifier,
            site.Id,
            context.Request.Method,
            context.Request.Path.Value ?? "/",
            outcome.Files.Count,
            outcome.FieldCount,
            outcome.Status,
            assessment.Score,
            assessment.Action,
            assessment.Score >= site.BlockThreshold,
            string.Join(',', assessment.RuleIds),
            buffer.Length,
            disposition);
    }

    private static IReadOnlyList<string> Cap(SortedSet<string> ruleIds)
    {
        if (ruleIds.Count == 0)
        {
            return [];
        }

        return ruleIds.Count <= MaximumReportedRuleIds
            ? [.. ruleIds]
            : [.. ruleIds.Take(MaximumReportedRuleIds)];
    }

    /// <summary>
    /// What every inspected file in one request added up to: the worst score, the most severe
    /// recommended action, and the distinct rules that fired.
    /// </summary>
    private sealed record FileAssessment(int Score, InspectionAction Action, SortedSet<string> RuleIds);
}

/// <summary>
/// A response the gateway must produce instead of forwarding.
/// </summary>
/// <param name="StatusCode">The HTTP status to answer with.</param>
/// <param name="Error">The stable machine-readable token for the response body's <c>error</c> field.</param>
/// <param name="Reason">
/// A narrower classification where one exists — <c>malformed</c> or <c>limit_exceeded</c> for a 415.
/// It comes from a closed set the gateway chose, never from the request.
/// </param>
/// <param name="RuleIds">
/// The rule identifiers to disclose, sorted and capped. Disclosing them is a deliberate decision:
/// WPShield is open source and the complete catalogue — every identifier, score and matching rule —
/// is already published, so withholding the identifiers protects nothing an attacker cannot read
/// while the entire cost falls on the site owner staring at an opaque refusal. The score and the
/// thresholds are the opposite case and are never disclosed: a binary allow/deny forces a blind
/// search, but a number turns evasion into hill-climbing because every mutation reports how much
/// closer it got.
/// </param>
internal sealed record GatewayRejection(
    int StatusCode,
    string Error,
    string? Reason,
    IReadOnlyList<string> RuleIds);

/// <summary>
/// What the inspection step concluded, and — when the body was buffered — the body itself.
/// </summary>
/// <param name="Body">
/// The buffered request body, rewound to 0 and ready to forward, or <see langword="null"/> when the
/// request was never buffered. When it is non-null the caller owns it and must dispose it on every
/// exit path.
/// </param>
/// <param name="Rejection">
/// The response the gateway must write instead of forwarding, or <see langword="null"/> to forward.
/// The stage never writes a response itself: response writing stays in one place in
/// <c>GatewayApplication</c>, so every status the gateway generates can be reviewed as a set.
/// </param>
/// <param name="Action">The most severe action across the inspected files.</param>
/// <param name="Score">The highest score across the inspected files. For logging only — never a control input.</param>
/// <param name="RuleIds">Distinct rule identifiers that fired, sorted ordinal and capped.</param>
internal sealed record UploadInspectionDecision(
    PooledRequestBuffer? Body,
    GatewayRejection? Rejection,
    InspectionAction Action,
    int Score,
    IReadOnlyList<string> RuleIds)
{
    /// <summary>
    /// The request was not a candidate for inspection, or carried nothing to inspect. Nothing was
    /// buffered and the request streams through exactly as it did before M2.
    /// </summary>
    public static UploadInspectionDecision NotInspected { get; } =
        new(null, null, InspectionAction.Allow, 0, []);

    public static UploadInspectionDecision Rejected(GatewayRejection rejection) =>
        new(null, rejection, InspectionAction.Block, 0, rejection.RuleIds);

    public static UploadInspectionDecision Inspected(
        PooledRequestBuffer body,
        InspectionAction action,
        int score,
        IReadOnlyList<string> ruleIds) =>
        new(body, null, action, score, ruleIds);
}

/// <summary>
/// A seekable, read-only, in-memory request body assembled from fixed-size arrays rented from
/// <see cref="ArrayPool{T}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Disk-freedom is structural here, not configurational.</b> This type references
/// <see cref="ArrayPool{T}"/> and nothing else. It contains no <c>FileStream</c>, no <c>File</c>,
/// no <c>Path</c>, no <c>Directory</c> and no memory-mapped file — there is no code path to disk to
/// prove unreachable, because there is no code path to disk. That is the whole reason
/// <c>Microsoft.AspNetCore.WebUtilities.FileBufferingReadStream</c> was rejected: it is the obvious
/// choice and it would work, since setting its threshold above the absolute request ceiling makes
/// the spill unreachable — but that safety survives only as long as nobody edits the threshold and
/// nobody adds a second construction site with a different one. "Never store a suspicious upload on
/// disk" is written without qualification, and a guarantee a future contributor can undo by
/// changing one number is not that guarantee.
/// </para>
/// <para>
/// <b>Implementers must not add a disk fallback for large bodies.</b> If a body does not fit, the
/// answer is 413, not a temporary file.
/// </para>
/// <para>
/// <b>Why 64 KiB chunks and not one right-sized array.</b> Two measurements on the .NET 10 runtime
/// this repository builds against decided it. <c>ArrayPool&lt;byte&gt;.Shared.Rent(6 MiB)</c>
/// returns an <b>8,388,608</b>-byte array, because the pool rounds to power-of-two buckets: the
/// obvious "rent MaximumRequestBytes" design wastes a third of what it takes and parks an 8 MiB
/// array on the large object heap for every concurrent multipart request, whether the upload was
/// 8 MiB or 8 KiB. <c>Rent(65536)</c> returns exactly 65,536 — a bucket size, so no rounding waste,
/// and below the 85,000-byte large-object threshold, so this pipeline never allocates on the LOH at
/// all. Chunks also grow without copying, which is what a chunked body with no declared length
/// needs: the alternative is renting the maximum up front or copying on every doubling.
/// </para>
/// <para>
/// Memory is therefore <c>ceil(bytes / 65536) * 65536</c>. A typical 180 KiB WordPress media upload
/// costs 192 KiB; only an actual 6 MiB upload costs 6 MiB.
/// </para>
/// </remarks>
internal sealed class PooledRequestBuffer : Stream
{
    /// <summary>
    /// The rented chunk size. See the type remarks — this specific number is load-bearing.
    /// </summary>
    public const int ChunkBytes = 64 * 1024;

    private readonly List<byte[]> _chunks = [];
    private readonly long _maximumBytes;
    private long _length;
    private long _position;
    private bool _disposed;

    /// <param name="maximumRequestBytes">
    /// The gateway's configured request limit. The buffer's own ceiling is one byte above it,
    /// because <see cref="RequestBodyLimitStream"/> deliberately permits reading one byte past the
    /// limit so that an overflow is <i>detectable</i> rather than merely truncated.
    /// </param>
    public PooledRequestBuffer(long maximumRequestBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumRequestBytes);

        _maximumBytes = maximumRequestBytes + 1;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => Seek(value, SeekOrigin.Begin);
    }

    /// <summary>
    /// Drains <paramref name="source"/> to its end into pooled chunks.
    /// </summary>
    /// <remarks>
    /// The independent ceiling below is redundant today, because the caller has already wrapped the
    /// request body in <see cref="RequestBodyLimitStream"/>. It is kept so that this type is
    /// bounded as a standalone stream: a future caller who forgets the wrapper cannot make it
    /// unbounded, and an unbounded in-memory buffer fed by an attacker-controlled chunked body is
    /// the single worst failure this file could have.
    /// </remarks>
    public async ValueTask FillFromAsync(Stream source, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (true)
        {
            var chunkIndex = (int)(_length / ChunkBytes);
            var offset = (int)(_length % ChunkBytes);

            if (chunkIndex == _chunks.Count)
            {
                _chunks.Add(ArrayPool<byte>.Shared.Rent(ChunkBytes));
            }

            var read = await source.ReadAsync(
                _chunks[chunkIndex].AsMemory(offset, ChunkBytes - offset), cancellationToken);
            if (read == 0)
            {
                break;
            }

            _length += read;
            if (_length > _maximumBytes)
            {
                throw new RequestBodyTooLargeException();
            }
        }

        _position = 0;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateBufferArguments(buffer, offset, count);
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var remaining = _length - _position;
        if (remaining <= 0 || buffer.Length == 0)
        {
            return 0;
        }

        // One chunk per call. A short read is legal for every Stream consumer, and the forwarder's
        // copy loop calls again; splicing across chunks here would buy a marginally larger read for
        // a second index calculation that could get the boundary wrong.
        var chunkIndex = (int)(_position / ChunkBytes);
        var chunkOffset = (int)(_position % ChunkBytes);
        var available = (int)Math.Min(
            Math.Min(buffer.Length, remaining),
            ChunkBytes - chunkOffset);

        _chunks[chunkIndex].AsSpan(chunkOffset, available).CopyTo(buffer);
        _position += available;
        return available;
    }

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        return cancellationToken.IsCancellationRequested
            ? ValueTask.FromCanceled<int>(cancellationToken)
            : new ValueTask<int>(Read(buffer.Span));
    }

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        ValidateBufferArguments(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };

        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(target, _length, nameof(offset));

        _position = target;
        return _position;
    }

    public override void Flush()
    {
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Returns every rented chunk to the pool. Idempotent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>_disposed</c> guard is not defensive tidiness. Returning one array to the pool twice
    /// hands the same buffer to two concurrent requests, which is a cross-request data leak rather
    /// than merely a bug — and the symptom would be one visitor's upload appearing in another
    /// visitor's evidence.
    /// </para>
    /// <para>
    /// No <c>clearArray: true</c>. Zeroing up to 6 MiB on every upload is real CPU for no
    /// confidentiality gain: <c>_length</c> bounds every read and only ever advances as bytes are
    /// written, so no consumer of a recycled chunk can reach a byte this request wrote. Stated
    /// explicitly because "pooled buffer, no clear" reads as an oversight to a reviewer who has not
    /// worked that through.
    /// </para>
    /// </remarks>
    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            foreach (var chunk in _chunks)
            {
                ArrayPool<byte>.Shared.Return(chunk);
            }

            _chunks.Clear();
            _length = 0;
            _position = 0;
        }

        base.Dispose(disposing);
    }
}
