using System.Text;
using System.Text.Json;
using WPShield.Abstractions;
using WPShield.Core;

namespace WPShield.Cli.Preview;

/// <summary>
/// Reads a bounded prefix of one JSONL source. No serving configuration, requests, rules, or
/// infrastructure are loaded. Retained state is bounded by the line and provenance ceilings.
/// </summary>
internal static class PolicyPreview
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    public static async Task<PreviewReport> ReadAsync(Stream input, string siteId, CandidatePolicy candidate,
        PreviewLimits limits, CancellationToken cancellationToken = default)
    {
        if (!limits.IsValid) throw new ArgumentOutOfRangeException(nameof(limits));
        if (candidate.Mode is not (ProtectionMode.Monitor or ProtectionMode.Block) ||
            candidate.ObserveThreshold is < 0 or > 100 || candidate.BlockThreshold is < 1 or > 100 ||
            candidate.ObserveThreshold > candidate.BlockThreshold)
            throw new ArgumentOutOfRangeException(nameof(candidate));
        var report = new PreviewReport(siteId, candidate, limits);
        var seen = new HashSet<(string Revision, string Request)>();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(limits.TimeoutSeconds));
        var chunk = new byte[4096];
        var line = new byte[PreviewLimits.MaximumLineBytes];
        var lineLength = 0;
        try
        {
            var originalLength = input.Length;
            report.SourceBytesAtOpen = originalLength;
            var remaining = Math.Min(originalLength, limits.MaximumBytes);
            while (remaining > 0)
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (report.LinesRead == limits.MaximumLines)
                {
                    report.StopReason = "line_limit";
                    break;
                }
                var read = await input.ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, remaining)), deadline.Token);
                if (read == 0)
                {
                    report.StopReason = "source_truncated";
                    break;
                }
                report.BytesRead += read;
                remaining -= read;
                for (var index = 0; index < read; index++)
                {
                    deadline.Token.ThrowIfCancellationRequested();
                    if (report.LinesRead == limits.MaximumLines)
                    {
                        report.StopReason = "line_limit";
                        return Finish(report);
                    }
                    if (chunk[index] == '\n')
                    {
                        report.LinesRead++;
                        ProcessLine(line.AsMemory(0, lineLength), report, seen);
                        lineLength = 0;
                    }
                    else if (lineLength == line.Length)
                    {
                        report.StopReason = "line_too_long";
                        return Finish(report);
                    }
                    else
                    {
                        line[lineLength++] = chunk[index];
                    }
                }
            }

            if (report.StopReason == "end_of_input")
            {
                report.StopReason = originalLength > limits.MaximumBytes ? "byte_limit"
                    : lineLength > 0 ? "unterminated_record"
                    : input.Length != originalLength ? "source_changed" : "end_of_input";
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            report.StopReason = "timeout";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            report.StopReason = "read_failed";
            if (report.EligibleRecords == 0) report.Status = "unavailable";
        }

        cancellationToken.ThrowIfCancellationRequested();
        return Finish(report);
    }

    private static PreviewReport Finish(PreviewReport report)
    {
        report.Finish();
        return report;
    }

    private static void ProcessLine(ReadOnlyMemory<byte> line, PreviewReport report,
        HashSet<(string Revision, string Request)> seen)
    {
        // UTF-8 BOM is legal only at the beginning of the source. CRLF is ordinary JSON whitespace.
        if (report.LinesRead == 1 && line.Span.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) line = line[3..];
        if (line.Span.IndexOfAnyExcept((byte)' ', (byte)'\r', (byte)'\t') < 0)
        {
            report.IgnoredLines++;
            return;
        }

        try
        {
            _ = StrictUtf8.GetCharCount(line.Span);
            using var document = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || HasDuplicates(root))
            {
                report.InvalidLines++;
                return;
            }
            var state = root.TryGetProperty("state", out var value) && value.ValueKind == JsonValueKind.Object ? value : default;
            if (state.ValueKind == JsonValueKind.Object && HasDuplicates(state))
            {
                report.InvalidLines++;
                return;
            }
            if (Text(root, "category") == "WPShield.Gateway.Logging" &&
                (Number(state, "DroppedEntries") > 0 || Text(root, "level") == "Error"))
            {
                report.EvidenceLossNotices++;
                return;
            }
            if (Text(state, "EventType") != "request_completed")
            {
                if (Text(root, "category") == "WPShield.Gateway.Evidence")
                    report.InvalidLines++;
                else
                    report.IgnoredLines++;
                return;
            }
            if (Text(root, "category") != "WPShield.Gateway.Evidence" || Text(state, "SiteId") is not { } site)
            {
                report.InvalidLines++;
                return;
            }
            if (!string.Equals(site, report.SiteId, StringComparison.Ordinal))
            {
                report.OtherSiteRecords++;
                return;
            }
            report.SelectedRecords++;
            if (Number(state, "SchemaVersion") != 1)
            {
                report.Exclude("unsupported_schema");
                return;
            }
            Compare(root, state, report, seen);
        }
        // JsonElement also rejects unpaired escaped UTF-16 surrogates when reading a string.
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException or InvalidOperationException)
        {
            report.InvalidLines++;
        }
    }

    private static void Compare(JsonElement root, JsonElement state, PreviewReport report,
        HashSet<(string Revision, string Request)> seen)
    {
        var revision = Text(state, "ConfigurationRevision");
        var requestId = Text(state, "RequestId");
        var gateway = Text(state, "GatewayVersion");
        var engine = Text(state, "EngineVersion");
        var windows = Text(state, "WindowsRulesVersion");
        var wordpress = Text(state, "WordPressRulesVersion");
        if (revision is null || !Guid.TryParseExact(revision, "N", out _) || !SafeToken(requestId) ||
            !SafeToken(gateway) || !SafeToken(engine) || !SafeToken(windows) || !SafeToken(wordpress) ||
            !root.TryGetProperty("timestamp", out var stamp) || stamp.ValueKind != JsonValueKind.String ||
            !stamp.TryGetDateTimeOffset(out var timestamp))
        {
            report.Exclude("missing_provenance");
            return;
        }
        if (!seen.Add((revision, requestId!)))
        {
            report.Exclude("duplicate_request");
            return;
        }

        var mode = Text(state, "Mode");
        if (mode is not ("Monitor" or "Block"))
        {
            report.Exclude("disabled_or_unknown_mode");
            return;
        }
        // A mode change also changes rate enforcement. Scores cannot replay a historical budget.
        if (!IsNull(state, "RateLimitRuleId"))
        {
            report.Exclude("rate_budget_or_missing_state");
            return;
        }
        var disposition = Text(state, "Disposition");
        if (disposition is not ("forwarded" or "rejected"))
        {
            report.Exclude("incomplete_exchange");
            return;
        }
        if (!TryStage(state, "Path", false, out var pathScore, out var pathAction) ||
            !TryStage(state, "Upload", true, out var uploadScore, out var uploadAction))
        {
            report.Exclude("incomplete_inspection");
            return;
        }
        if (uploadScore is not null &&
            (Number(state, "FilesRead") is not (>= 0 and <= 200) ||
             Number(state, "FilesRead") != Number(state, "FilesInspected") ||
             Number(state, "FilesRead") == 0 && (uploadScore != 0 || uploadAction != InspectionAction.Allow)))
        {
            report.Exclude("inconsistent_file_coverage");
            return;
        }
        var recorded = (InspectionAction)Math.Max((int)pathAction, (int)uploadAction);
        var reason = Text(state, "Reason");
        if ((mode == "Monitor" && recorded == InspectionAction.Block) ||
            (disposition == "forwarded" && (recorded == InspectionAction.Block || reason != "exchange_completed" || Boolean(state, "ForwardingAttempted") != true)) ||
            (disposition == "rejected" && (recorded != InspectionAction.Block || Boolean(state, "ForwardingAttempted") != false ||
                (pathAction == InspectionAction.Block ? reason != "request_blocked" : reason != "upload_blocked"))))
        {
            report.Exclude("inconsistent_outcome");
            return;
        }

        var source = new SourcePolicy(revision, gateway!, engine!, windows!, wordpress!, mode);
        var comparison = report.Comparisons.Find(item => item.Source == source);
        if (comparison is null)
        {
            if (report.Comparisons.Count == PreviewLimits.MaximumProvenanceGroups)
            {
                report.Exclude("provenance_limit");
                return;
            }
            comparison = new PolicyComparison(source);
            report.Comparisons.Add(comparison);
        }

        // Skipped non-multipart/empty upload stages have no score and remain outside the comparison.
        var candidatePath = Recommend(pathScore!.Value, report.Candidate);
        var candidateUpload = uploadScore is { } score ? Recommend(score, report.Candidate) : InspectionAction.Allow;
        var candidate = (InspectionAction)Math.Max((int)candidatePath, (int)candidateUpload);
        report.NewlyRefused ??= 0;
        report.NewlyPermitted ??= 0;
        report.ChangedRecommendations ??= 0;
        report.UnchangedRecommendations ??= 0;
        report.EligibleRecords++;
        comparison.EligibleRecords++;
        if (recorded != InspectionAction.Block && candidate == InspectionAction.Block)
        {
            report.NewlyRefused++;
            comparison.NewlyRefused++;
        }
        if (recorded == InspectionAction.Block && candidate != InspectionAction.Block)
        {
            report.NewlyPermitted++;
            comparison.NewlyPermitted++;
        }
        if (recorded == candidate)
        {
            report.UnchangedRecommendations++;
            comparison.UnchangedRecommendations++;
        }
        else
        {
            report.ChangedRecommendations++;
            comparison.ChangedRecommendations++;
        }
        report.WindowStart = Earlier(report.WindowStart, timestamp);
        report.WindowEnd = Later(report.WindowEnd, timestamp);
        comparison.WindowStart = Earlier(comparison.WindowStart, timestamp);
        comparison.WindowEnd = Later(comparison.WindowEnd, timestamp);
    }

    private static InspectionAction Recommend(int score, CandidatePolicy candidate) =>
        InspectionPolicy.Recommend(score, candidate.Mode, candidate.ObserveThreshold, candidate.BlockThreshold);

    private static bool TryStage(JsonElement state, string prefix, bool allowSkipped,
        out int? score, out InspectionAction action)
    {
        score = Number(state, prefix + "Score");
        action = InspectionAction.Allow;
        if (allowSkipped && Text(state, prefix + "Status") == "not_inspected" &&
            Text(state, prefix + "Reason") is "empty_body" or "non_multipart")
        {
            return IsNull(state, prefix + "Score") && IsNull(state, prefix + "Action") &&
                Text(state, prefix + "RuleIds") == "" && Boolean(state, prefix + "RuleIdsTruncated") == false;
        }
        if (Text(state, prefix + "Status") != "complete" || score is not (>= 0 and <= 100) ||
            Text(state, prefix + "Reason") != (allowSkipped ? "sampled_scope" : "rules_completed") ||
            Boolean(state, prefix + "RuleIdsTruncated") != false || Text(state, prefix + "RuleIds") is null)
        {
            return false;
        }
        var text = Text(state, prefix + "Action");
        return text is "Allow" or "Observe" or "Block" && Enum.TryParse(text, out action);
    }

    private static bool HasDuplicates(JsonElement element)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        return element.EnumerateObject().Any(property => !keys.Add(property.Name));
    }

    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;
    private static int? Number(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number : null;
    private static bool? Boolean(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean() : null;
    private static bool IsNull(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Null;
    private static bool SafeToken(string? value) => value is { Length: > 0 and <= 128 } && value != "unknown" &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '+' or '_' or ':');
    private static DateTimeOffset Earlier(DateTimeOffset? current, DateTimeOffset value) => current is null || value < current ? value : current.Value;
    private static DateTimeOffset Later(DateTimeOffset? current, DateTimeOffset value) => current is null || value > current ? value : current.Value;
}
