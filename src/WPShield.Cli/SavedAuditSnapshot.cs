using System.Text;
using System.Text.Json;
using WPShield.SecurityMonitor;

namespace WPShield.Cli;

internal sealed class SnapshotSizeException : IOException;
internal sealed class ReferenceLimitException : Exception;
internal sealed class DuplicateAuditRowException : Exception;
internal sealed record AuditReferenceRow(string Source, long Id, DateTimeOffset? Timestamp, string Json);
internal sealed record AuditReferenceList(IReadOnlyList<AuditReferenceRow> Rows, IReadOnlyDictionary<string, string> Coverage);

internal static class SavedAuditSnapshot
{
    internal const int MaxReferences = 1024;
    internal const int MaxBytes = 8 * 1024 * 1024;
    internal sealed record Source(IEnumerable<JsonElement> Rows, string Key, Func<JsonElement, long, AuditReferenceRow> Project);

    internal static async Task<JsonDocument> ReadAsync(string path, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        var length = file.Length;
        if (length > MaxBytes) throw new SnapshotSizeException();
        var bytes = new byte[(int)length];
        await file.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        var offset = bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble) ? Encoding.UTF8.Preamble.Length : 0;
        return JsonDocument.Parse(bytes.AsMemory(offset), new JsonDocumentOptions { MaxDepth = 32, AllowDuplicateProperties = false });
    }

    internal static async Task<AuditReferenceList> BrowseAsync(string path, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        using var doc = await ReadAsync(path, timeout.Token).ConfigureAwait(false);
        var root = doc.RootElement;
        var rows = new List<AuditReferenceRow>();
        var coverage = new Dictionary<string, string>();
        if (root.TryGetProperty("RdpAudit", out var rdp)) Add("rdp", rdp);
        if (root.TryGetProperty("SqlAudit", out var sql)) Add("sql", sql);
        else if (root.TryGetProperty("Events", out _)) Add("sql", root);
        if (root.TryGetProperty("Report", out var iis)) Add("iis", iis);
        if (coverage.Count == 0) throw new JsonException();
        timeout.Token.ThrowIfCancellationRequested();
        return new(rows, coverage);

        void Add(string name, JsonElement report)
        {
            var section = GetSource(root, name);
            coverage.Add(name, Coverage(name, report));
            var ids = new HashSet<long>();
            foreach (var row in section.Rows)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (rows.Count == MaxReferences) throw new ReferenceLimitException();
                var id = row.GetProperty(section.Key).GetInt64();
                if (id <= 0) throw new JsonException();
                if (!ids.Add(id)) throw new DuplicateAuditRowException();
                rows.Add(section.Project(row, id));
            }
        }
    }

    private static string Coverage(string name, JsonElement report)
    {
        if (name != "iis")
        {
            var status = report.TryGetProperty("AuditStatus", out var field) ? field.GetString() : null;
            return status is "read" or "limited" or "unavailable" ? status : "unknown";
        }
        if (!report.TryGetProperty("StopReason", out var stop) || !report.TryGetProperty("MalformedRows", out var malformed) ||
            !report.TryGetProperty("UnattributedRows", out var unattributed)) return "unknown";
        return stop.GetString() == "end_of_file" && malformed.GetInt32() == 0 && unattributed.GetInt32() == 0 ? "read" : "limited";
    }

    internal static Source GetSource(JsonElement root, string source)
    {
        if (source == "iis")
        {
            var evidence = root.GetProperty("Report").GetProperty("Evidence").EnumerateArray();
            return new(evidence, "Line", (row, id) => IisReference(root, row, id));
        }
        string channel, provider;
        IEnumerable<JsonElement> events;
        if (source == "rdp")
        {
            var audit = root.GetProperty("RdpAudit");
            channel = "Security";
            provider = RdpAuditReader.Provider;
            // Earlier snapshots omitted the channel and provider of the same reader.
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
        return new(events, "RecordId", (row, id) =>
        {
            var time = row.GetProperty("Timestamp");
            var value = time.GetString();
            if (value is null || !(value.EndsWith('Z') || value.Length >= 6 && value[^6] is '+' or '-' && value[^3] == ':'))
                throw new JsonException();
            var timestamp = time.GetDateTimeOffset().ToUniversalTime();
            return new(source.ToUpperInvariant(), id, timestamp, JsonSerializer.Serialize(new { Channel = channel, Provider = provider, Timestamp = timestamp, RecordId = id }));
        });
    }

    private static AuditReferenceRow IisReference(JsonElement root, JsonElement row, long id)
    {
        var hash = root.GetProperty("InputPrefixSha256").GetString();
        var bytes = root.GetProperty("InputPrefixBytes").GetInt32();
        if (hash is not { Length: 64 } || !hash.All(char.IsAsciiHexDigit) || bytes is < 1 or > IisLoginAudit.MaxBytes || id > bytes)
            throw new JsonException();
        var challenge = row.GetProperty("ChallengeLine");
        int? line = challenge.ValueKind == JsonValueKind.Null ? null : challenge.GetInt32();
        if (line.HasValue && (line <= 0 || line >= id)) throw new JsonException();
        return new("IIS", id, null, JsonSerializer.Serialize(new { InputPrefixSha256 = hash, InputPrefixBytes = bytes, Line = id, ChallengeLine = line }));
    }
}
