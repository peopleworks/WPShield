using System.Security.Cryptography;
using System.Text.Json;

namespace WPShield.Cli;

internal static class IisLoginCommand
{
    internal const string Help = """
        wpshield iis-login --log-file <copied-w3c.log> --site <s-sitename> [--json]

        Read IIS Windows-authentication evidence from one W3C file. Select the site's exact
        logged s-sitename value. Missing attribution is unknown. Compare line numbers against
        the same input prefix. Reads up to 4 MiB, 16 KiB per line and 256 evidence rows.
        Exit 0: evidence read. 1: invalid or unreadable input. 2: partial. 3: no eligible evidence.
        """;

    internal static async Task<int> RunAsync(CliOptions options, TextWriter output, CancellationToken token = default)
    {
        options.RejectUnknown("--log-file", "--site", "--json");
        options.RejectRepeated();
        var path = options.Get("--log-file");
        var site = options.Get("--site");
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(site) || site == "-" ||
            site.Length > 128 || site.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) || options.Get("--json") is not null)
            throw new CliArgumentException("Specify --log-file and one logged --site value. --json takes no value.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
            var length = file.Length;
            var input = new byte[(int)Math.Min(length, IisLoginAudit.MaxBytes)];
            await file.ReadExactlyAsync(input, timeout.Token);
            var report = IisLoginAudit.Scan(input, length > input.Length, site, timeout.Token);
            var hash = Convert.ToHexString(SHA256.HashData(input));
            if (options.Has("--json"))
                output.WriteLine(JsonSerializer.Serialize(new { InputPrefixSha256 = hash, InputPrefixBytes = input.Length, Report = report }));
            else
            {
                output.WriteLine($"W3C  {input.Length} bytes  SHA-256 {hash}");
                output.WriteLine($"Site {site}  Attribution: {report.SiteAttribution}  Selected: {report.SelectedRows}  Unattributed: {report.UnattributedRows}  Malformed: {report.MalformedRows}  Stop: {report.StopReason}");
                foreach (var row in report.Evidence)
                {
                    var challenge = row.ChallengeLine.HasValue ? $"  Challenge line {row.ChallengeLine}" : "";
                    output.WriteLine($"Line {row.Line}  {row.Utc:u}  HTTP {row.Status}.{row.Substatus}  Win32 {row.Win32Status}  {row.Observation}{challenge}");
                }
            }
            if (report.StopReason != "end_of_file" || report.MalformedRows > 0 || report.UnattributedRows > 0) return 2;
            return report.Evidence.Count == 0 ? 3 : 0;
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            output.WriteLine(options.Has("--json") ? """{"StopReason":"timeout"}""" : "The W3C read exceeded its time budget.");
            return 2;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            output.WriteLine(options.Has("--json") ? """{"StopReason":"unavailable"}""" : "Unable to read the W3C input. Use a readable copy of a regular file.");
            return 1;
        }
    }
}
