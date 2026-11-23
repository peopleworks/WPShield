using System.Globalization;
using System.Text.Json;
using WPShield.SecurityMonitor;

namespace WPShield.Cli;

internal static class AuditReferenceCommand
{
    internal const string Help = """
        wpshield audit-reference --snapshot <report.json> --source rdp|sql --record-id <number>
        wpshield audit-reference --snapshot <report.json> --source iis --line <number>

        Read one saved UTF-8 JSON snapshot (up to 8 MiB). Print one minimal reference as JSON.
        Use the Windows event record ID or physical W3C line from the report.
        Exit 0: one reference. 1: invalid, ambiguous or unreadable input. 3: no matching record.
        """;
    internal const int MaxBytes = 8 * 1024 * 1024;
    private sealed class AmbiguousReferenceException : Exception;

    internal static async Task<int> RunAsync(CliOptions options, TextWriter output, TextWriter error, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        options.RejectRepeated();
        var source = options.Get("--source")?.ToLowerInvariant();
        var key = source == "iis" ? "--line" : "--record-id";
        options.RejectUnknown("--snapshot", "--source", key);
        var path = options.Get("--snapshot");
        if (string.IsNullOrWhiteSpace(path) || source is not ("iis" or "sql" or "rdp") ||
            !long.TryParse(options.Get(key), NumberStyles.None, CultureInfo.InvariantCulture, out var id) ||
            id <= 0 || source == "iis" && id > int.MaxValue)
            throw new CliArgumentException("Specify one --snapshot, --source and positive --record-id (RDP/SQL) or --line (IIS).");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        string? reference;
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var length = file.Length;
            if (length > MaxBytes)
            {
                error.WriteLine("The selected snapshot exceeds 8 MiB.");
                return 1;
            }
            var bytes = new byte[(int)length];
            await file.ReadExactlyAsync(bytes, timeout.Token);
            var preamble = System.Text.Encoding.UTF8.Preamble;
            var offset = bytes.AsSpan().StartsWith(preamble) ? preamble.Length : 0;
            using var doc = JsonDocument.Parse(bytes.AsMemory(offset), new JsonDocumentOptions { MaxDepth = 32, AllowDuplicateProperties = false });
            reference = Select(doc.RootElement, source, id, timeout.Token);
            timeout.Token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            error.WriteLine("The snapshot read exceeded the time budget.");
            return 1;
        }
        catch (AmbiguousReferenceException)
        {
            error.WriteLine("Multiple rows match the selected ID in this source.");
            return 1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error.WriteLine("Unable to read the selected snapshot.");
            return 1;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            error.WriteLine("Expected one valid WPShield JSON snapshot containing the selected source.");
            return 1;
        }
        if (reference is null)
        {
            error.WriteLine("No matching record in the selected snapshot and source.");
            return 3;
        }
        output.WriteLine(reference);
        return 0;
    }

    private static string? Select(JsonElement root, string source, long id, CancellationToken token)
    {
        if (source == "iis")
        {
            var rows = root.GetProperty("Report").GetProperty("Evidence").EnumerateArray();
            var row = Find(rows, "Line", id, token);
            if (row is null) return null;
            var hash = root.GetProperty("InputPrefixSha256").GetString();
            var bytes = root.GetProperty("InputPrefixBytes").GetInt32();
            if (hash is not { Length: 64 } || !hash.All(char.IsAsciiHexDigit) || bytes is < 1 or > IisLoginAudit.MaxBytes || id > bytes)
                throw new JsonException();
            var challenge = row.Value.GetProperty("ChallengeLine");
            int? line = challenge.ValueKind == JsonValueKind.Null ? null : challenge.GetInt32();
            if (line.HasValue && (line <= 0 || line >= id)) throw new JsonException();
            return JsonSerializer.Serialize(new { InputPrefixSha256 = hash, InputPrefixBytes = bytes, Line = id, ChallengeLine = line });
        }

        string channel, provider;
        IEnumerable<JsonElement> events;
        if (source == "rdp")
        {
            var audit = root.GetProperty("RdpAudit");
            channel = "Security";
            provider = RdpAuditReader.Provider;
            // Versions before source status used the same RDP reader and omitted Channel.
            if (audit.TryGetProperty("Channel", out var recorded) && recorded.GetString() != channel) throw new JsonException();
            if (audit.TryGetProperty("Provider", out var recordedProvider) && recordedProvider.GetString() != provider) throw new JsonException();
            events = audit.GetProperty("Flows").EnumerateArray().SelectMany(flow => flow.GetProperty("Events").EnumerateArray());
        }
        else
        {
            var audit = root.TryGetProperty("SqlAudit", out var sql) ? sql : root;
            channel = "Application";
            provider = audit.GetProperty("Provider").GetString() ?? throw new JsonException();
            if (audit.GetProperty("Channel").GetString() != channel || !(provider == "MSSQLSERVER" ||
                provider.StartsWith("MSSQL$", StringComparison.Ordinal) && SqlLoginAuditReader.IsValidInstance(provider[6..])))
                throw new JsonException();
            events = audit.GetProperty("Events").EnumerateArray();
        }
        var entry = Find(events, "RecordId", id, token);
        if (entry is null) return null;
        var time = entry.Value.GetProperty("Timestamp");
        var value = time.GetString();
        if (value is null || !(value.EndsWith('Z') || value.Length >= 6 && value[^6] is '+' or '-' && value[^3] == ':'))
            throw new JsonException();
        return JsonSerializer.Serialize(new { Channel = channel, Provider = provider, Timestamp = time.GetDateTimeOffset().ToUniversalTime(), RecordId = id });
    }

    private static JsonElement? Find(IEnumerable<JsonElement> rows, string key, long id, CancellationToken token)
    {
        JsonElement? match = null;
        foreach (var row in rows)
        {
            token.ThrowIfCancellationRequested();
            if (row.GetProperty(key).GetInt64() != id) continue;
            if (match.HasValue) throw new AmbiguousReferenceException();
            match = row;
        }
        return match;
    }
}
