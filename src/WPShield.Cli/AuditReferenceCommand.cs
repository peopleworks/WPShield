using System.Globalization;
using System.Text.Json;

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
            using var doc = await SavedAuditSnapshot.ReadAsync(path, timeout.Token);
            var section = SavedAuditSnapshot.GetSource(doc.RootElement, source);
            var row = Find(section.Rows, section.Key, id, timeout.Token);
            reference = row.HasValue ? section.Project(row.Value, id).Json : null;
            timeout.Token.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            error.WriteLine("The snapshot read exceeded the time budget.");
            return 1;
        }
        catch (SnapshotSizeException)
        {
            error.WriteLine("The selected snapshot exceeds 8 MiB.");
            return 1;
        }
        catch (DuplicateAuditRowException)
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

    private static JsonElement? Find(IEnumerable<JsonElement> rows, string key, long id, CancellationToken token)
    {
        JsonElement? match = null;
        foreach (var row in rows)
        {
            token.ThrowIfCancellationRequested();
            if (row.GetProperty(key).GetInt64() != id) continue;
            if (match.HasValue) throw new DuplicateAuditRowException();
            match = row;
        }
        return match;
    }
}
