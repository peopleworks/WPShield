using System.Globalization;
using System.Net;
using System.Text;

namespace WPShield.Cli;

internal sealed record IisLoginRow(int Line, DateTimeOffset Utc, int Status, int? Substatus,
    uint? Win32Status, string Observation, int? ChallengeLine);

internal sealed class IisLoginReport(string site)
{
    public string RequestedSite { get; } = site;
    public string SiteAttribution => SelectedRows > 0 ? "s-sitename" : "unknown";
    public string StopReason { get; internal set; } = "end_of_file";
    public int SelectedRows { get; internal set; }
    public int UnattributedRows { get; internal set; }
    public int MalformedRows { get; internal set; }
    public List<IisLoginRow> Evidence { get; } = [];
}

internal static class IisLoginAudit
{
    internal const int MaxBytes = 4 * 1024 * 1024;
    internal const int MaxLineBytes = 16 * 1024;
    internal const int MaxRows = 256;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private sealed record Exchange(IPAddress Client, ushort ClientPort, IPAddress Server, ushort ServerPort,
        string Method, string Stem);
    private sealed record Challenge(Exchange Connection, DateTimeOffset Utc, int Line);

    internal static IisLoginReport Scan(ReadOnlySpan<byte> bytes, bool moreBytes, string site, CancellationToken token)
    {
        var report = new IisLoginReport(site);
        Dictionary<string, int>? fields = null;
        Challenge? previous = null;
        var line = 0;
        if (bytes.StartsWith(Encoding.UTF8.Preamble)) bytes = bytes[Encoding.UTF8.Preamble.Length..];
        while (!bytes.IsEmpty)
        {
            token.ThrowIfCancellationRequested();
            line++;
            var end = bytes.IndexOf((byte)'\n');
            if (end < 0 || end > MaxLineBytes)
            {
                report.StopReason = (end < 0 ? bytes.Length : end) > MaxLineBytes ? "line_limit"
                    : moreBytes ? "byte_limit" : "unterminated_line";
                break;
            }
            var raw = bytes[..end];
            bytes = bytes[(end + 1)..];
            if (raw.EndsWith("\r"u8)) raw = raw[..^1];
            string row;
            try { row = Utf8.GetString(raw); }
            catch (DecoderFallbackException)
            {
                report.MalformedRows++;
                fields = null;
                previous = null;
                continue;
            }
            if (row.StartsWith("#Fields", StringComparison.OrdinalIgnoreCase))
            {
                fields = row.StartsWith("#Fields:", StringComparison.OrdinalIgnoreCase) ? ParseFields(row[8..]) : null;
                if (fields is null) report.MalformedRows++;
                previous = null;
                continue;
            }
            if (row.StartsWith('#') || row.Length == 0)
            {
                if (row.StartsWith("#Version:", StringComparison.OrdinalIgnoreCase) ||
                    row.StartsWith("#Software:", StringComparison.OrdinalIgnoreCase)) fields = null;
                previous = null;
                continue;
            }
            var prior = previous;
            previous = null;
            var values = row.Split(' ', 65, StringSplitOptions.RemoveEmptyEntries);
            if (fields is null || values.Length != fields.Count)
            {
                report.MalformedRows++;
                continue;
            }
            string? Get(string name) => fields.TryGetValue(name, out var index) ? values[index] : null;
            var rowSite = Get("s-sitename");
            if (rowSite is null or "-") { report.UnattributedRows++; continue; }
            if (!site.Equals(rowSite, StringComparison.OrdinalIgnoreCase)) continue;
            report.SelectedRows++;
            if (!DateTimeOffset.TryParseExact($"{Get("date")} {Get("time")}", "yyyy-MM-dd HH:mm:ss",
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var utc) ||
                !int.TryParse(Get("sc-status"), NumberStyles.None, CultureInfo.InvariantCulture, out var status) || status is < 100 or > 599)
            {
                report.MalformedRows++;
                continue;
            }
            int? sub = int.TryParse(Get("sc-substatus"), NumberStyles.None, CultureInfo.InvariantCulture, out var s) ? s : null;
            uint? win32 = uint.TryParse(Get("sc-win32-status"), NumberStyles.None, CultureInfo.InvariantCulture, out var w) ? w : null;
            var user = Get("cs-username");
            var authenticated = user is not (null or "-");
            var observation = (status, sub, win32) switch
            {
                (401, 1, 1326) => "login-rejected",
                (401, 2, 5) or (401, 1, 2148074254) when user == "-" => "challenge-compatible",
                (401, _, _) => "unknown",
                ( >= 200 and < 300, 0, 0) when authenticated => "authenticated-request",
                _ => null
            };
            if (observation is null) continue;
            if (report.Evidence.Count == MaxRows) { report.StopReason = "evidence_limit"; break; }
            int? challengeLine = null;
            if (observation is "challenge-compatible" or "authenticated-request" &&
                GetExchange(Get) is { } connection)
            {
                if (observation == "challenge-compatible") previous = new(connection, utc, line);
                else if (prior is not null && prior.Connection == connection && utc >= prior.Utc &&
                    utc - prior.Utc <= TimeSpan.FromSeconds(10))
                {
                    challengeLine = prior.Line;
                    observation = "challenge-followed-by-success";
                }
            }
            report.Evidence.Add(new(line, utc, status, sub, win32, observation, challengeLine));
        }
        if (moreBytes && report.StopReason == "end_of_file") report.StopReason = "byte_limit";
        return report;
    }

    private static Dictionary<string, int>? ParseFields(string header)
    {
        var names = header.Split(' ', 65, StringSplitOptions.RemoveEmptyEntries);
        if (names.Length is 0 or > 64) return null;
        var fields = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < names.Length; i++)
            if (!fields.TryAdd(names[i], i)) return null;
        return fields;
    }

    private static Exchange? GetExchange(Func<string, string?> get)
    {
        if (get("cs-version") != "HTTP/1.1" ||
            !IPAddress.TryParse(get("c-ip"), out var client) || !IPAddress.TryParse(get("s-ip"), out var server) ||
            !ushort.TryParse(get("c-port"), NumberStyles.None, CultureInfo.InvariantCulture, out var clientPort) || clientPort == 0 ||
            !ushort.TryParse(get("s-port"), NumberStyles.None, CultureInfo.InvariantCulture, out var serverPort) || serverPort == 0 ||
            get("cs-method") is not { Length: > 0 } method || method == "-" || get("cs-uri-stem") is not { Length: > 0 } stem || !stem.StartsWith('/'))
            return null;
        return new(client, clientPort, server, serverPort, method, stem);
    }
}
