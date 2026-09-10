using System.Text.Json;

namespace WPShield.Cli.Watch;

/// <summary>
/// Turns one line of the gateway's JSON Lines log into an <see cref="EvidenceEvent"/>, or nothing.
/// </summary>
/// <remarks>
/// <para>
/// The console reads a file another process is appending to, and on a host under attack. So this is
/// written to survive everything a tail can hand it: a half-written final line, a blank line, a line
/// that is valid JSON but not an object, a line missing any field. Every one of those returns
/// <see langword="null"/> rather than throwing — a console that dies on a torn read is a console that
/// is never running at the moment it was wanted.
/// </para>
/// <para>
/// <b>The classification is by message prefix, matched exactly.</b> The gateway's log messages begin
/// with fixed literals — <c>"Upload finding."</c>, <c>"Request path inspected."</c> — and those
/// prefixes are the contract this reads against. Reading the shape from which fields happen to be
/// present would misread the upload verdict, which carries the same <c>RuleIds</c> field a finding
/// does. If the gateway ever changes a message, the matching test in this repository fails, which is
/// where that coupling is meant to break.
/// </para>
/// </remarks>
internal static class EvidenceParser
{
    // The stable message prefixes the gateway writes. Kept here as the one place the console's
    // reading of the log couples to the gateway's writing of it.
    private const string UploadFinding = "Upload finding.";
    private const string PathFinding = "Request path finding.";
    private const string UploadVerdict = "Upload inspection complete.";
    private const string PathVerdict = "Request path inspected.";
    private const string DroppedNotice = "Log entries were dropped";

    public static EvidenceEvent? Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(line);
        }
        catch (JsonException)
        {
            return null;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var message = GetString(root, "message");
            if (message is null)
            {
                return null;
            }

            if (!TryGetTimestamp(root, out var timestamp))
            {
                return null;
            }

            var level = GetString(root, "level") ?? "Information";
            var state = TryGetObject(root, "state");

            var kind = Classify(message);

            return new EvidenceEvent
            {
                Timestamp = timestamp,
                Level = level,
                Kind = kind,
                Message = message,
                Host = GetStateString(state, "SiteId"),
                Rules = ReadRules(state),
                Score = GetStateInt(state, "Score"),
                Action = ReadAction(state),
                Method = GetStateString(state, "Method"),
                Path = GetStateString(state, "Path"),
                Mode = GetStateString(state, "Mode")
            };
        }
    }

    private static EvidenceKind Classify(string message)
    {
        if (message.StartsWith(UploadFinding, StringComparison.Ordinal) ||
            message.StartsWith(PathFinding, StringComparison.Ordinal))
        {
            return EvidenceKind.Finding;
        }

        if (message.StartsWith(UploadVerdict, StringComparison.Ordinal) ||
            message.StartsWith(PathVerdict, StringComparison.Ordinal))
        {
            return EvidenceKind.Verdict;
        }

        if (message.StartsWith(DroppedNotice, StringComparison.Ordinal))
        {
            return EvidenceKind.DroppedNotice;
        }

        return EvidenceKind.Other;
    }

    /// <summary>
    /// The rule identifiers on the line. A path finding writes a single <c>RuleId</c>; an upload
    /// finding and an upload verdict write a comma-joined <c>RuleIds</c>. Either is returned as
    /// written, and null when neither is present or non-empty.
    /// </summary>
    private static string? ReadRules(JsonElement? state)
    {
        var many = GetStateString(state, "RuleIds");
        if (!string.IsNullOrEmpty(many))
        {
            return many;
        }

        var one = GetStateString(state, "RuleId");
        return string.IsNullOrEmpty(one) ? null : one;
    }

    private static EvidenceAction ReadAction(JsonElement? state)
    {
        return GetStateString(state, "Action") switch
        {
            "Allow" => EvidenceAction.Allow,
            "Observe" => EvidenceAction.Observe,
            "Block" => EvidenceAction.Block,
            _ => EvidenceAction.Unknown
        };
    }

    private static bool TryGetTimestamp(JsonElement root, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (!root.TryGetProperty("timestamp", out var element) || element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        return element.TryGetDateTimeOffset(out timestamp);
    }

    private static string? GetString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static JsonElement? TryGetObject(JsonElement root, string name)
    {
        return root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Object
            ? value
            : null;
    }

    private static string? GetStateString(JsonElement? state, string name)
    {
        if (state is not { } element || !element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    private static int? GetStateInt(JsonElement? state, string name)
    {
        if (state is not { } element || !element.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number
            : null;
    }
}
