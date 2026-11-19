using System.Text.Json;
using System.Text.Json.Serialization;
using WPShield.Cli.Preview;
using WPShield.Core;

namespace WPShield.Cli;

internal static class PreviewCommand
{
    public const string Help = """
        wpshield preview - compare recorded inspection decisions with a candidate policy. Offline, read-only.

        Usage: wpshield preview --log-file <file.jsonl> --site <site-id> [options]

          --mode <Monitor|Block>    Candidate mode. Default: Monitor. Disabled is not simulated.
          --observe-threshold <n>   Candidate observe threshold, 0..100. Default: 30.
          --block-threshold <n>     Candidate block threshold, 1..100, >= observe. Default: 80.
          --max-lines <n>           Scan at most this many input lines, 1..100000. Default: 10000.
          --max-bytes <n>           Scan at most this many bytes, 1..67108864. Default: 16777216.
          --timeout-seconds <n>     Time budget, 1..60 seconds. Default: 10.

        Prints a JSON report to stdout; writes no files and never loads or changes live configuration.
        Selects one exact SiteId from schema-1 request_completed events. Missing, partial, duplicate
        or inconsistent evidence is excluded explicitly. A complete report covers only eligible
        records in the input; it does not prove complete traffic coverage or replay content rules.
        Use a copied log for a stable source. No service, IIS, network or Reader-1 calls are made.

        Exit codes: 0 complete comparison; 2 partial comparison; 3 no eligible evidence;
                    1 invalid arguments or unavailable input. A preview never authorizes Block.
        """;

    private static readonly string[] KnownOptions =
    [
        "--log-file", "--site", "--mode", "--observe-threshold", "--block-threshold",
        "--max-lines", "--max-bytes", "--timeout-seconds"
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static int Run(CliOptions arguments, TextWriter output) => RunAsync(arguments, output).GetAwaiter().GetResult();

    internal static async Task<int> RunAsync(CliOptions arguments, TextWriter output, CancellationToken cancellationToken = default)
    {
        arguments.RejectUnknown(KnownOptions);
        arguments.RejectRepeated();
        foreach (var option in KnownOptions)
        {
            if (arguments.Has(option) && string.IsNullOrWhiteSpace(arguments.Get(option)))
                throw new CliArgumentException($"{option} requires a value.");
        }
        var path = arguments.Get("--log-file");
        var site = arguments.Get("--site");
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(site))
            throw new CliArgumentException("preview requires --log-file and --site.");
        if (site.Length > 128 || site.Any(char.IsControl))
            throw new CliArgumentException("--site must contain 1..128 characters and no control characters.");
        var modeText = arguments.Get("--mode", "Monitor");
        if (!string.Equals(modeText, "Monitor", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(modeText, "Block", StringComparison.OrdinalIgnoreCase))
            throw new CliArgumentException("--mode must be Monitor or Block.");
        var mode = Enum.Parse<ProtectionMode>(modeText, true);
        var observe = arguments.Integer("--observe-threshold", 30);
        var block = arguments.Integer("--block-threshold", 80);
        if (observe is < 0 or > 100 || block is < 1 or > 100 || observe > block)
            throw new CliArgumentException("Thresholds require 0 <= observe <= block <= 100 and block >= 1.");
        var limits = new PreviewLimits(arguments.Integer("--max-lines", 10_000),
            arguments.Integer("--max-bytes", 16 * 1024 * 1024), arguments.Integer("--timeout-seconds", 10));
        if (!limits.IsValid)
            throw new CliArgumentException("Preview limits require lines 1..100000, bytes 1..67108864 and timeout 1..60 seconds.");
        var candidate = new CandidatePolicy(mode, observe, block);
        PreviewReport report;
        try
        {
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            report = await PolicyPreview.ReadAsync(input, site, candidate, limits, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // Never print an exception carrying a sensitive path or line from the source log.
            report = new PreviewReport(site, candidate, limits) { Status = "unavailable", StopReason = "open_failed" };
        }
        await output.WriteLineAsync(JsonSerializer.Serialize(report, JsonOptions).AsMemory(), cancellationToken);
        return report.Status switch { "complete" => 0, "partial" => 2, "cannot_evaluate" => 3, _ => 1 };
    }
}
