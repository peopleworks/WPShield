using System.Net;
using WPShield.Evidence;

namespace WPShield.Cli.Tests;

/// <summary>
/// A real evidence store in a temporary directory, filled the way the service fills it: through
/// <see cref="EvidenceWriter"/> and <see cref="EvidenceSettings"/>. Synthetic RFC 5737 addresses only.
/// </summary>
internal sealed class EvidenceTestStore : IDisposable
{
    internal static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private long record;

    internal EvidenceTestStore()
    {
        Directory.CreateDirectory(DirectoryPath);
    }

    internal string DirectoryPath { get; } =
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "wpshield-cli-evidence-tests", Guid.NewGuid().ToString("N"));

    internal string Path => System.IO.Path.Combine(DirectoryPath, EvidenceStore.FileName);

    internal AuthFailure Failure(double minutesAgo, string? ip, string account = "admin", string reason = "bad-password", int type = 10) =>
        new(Now.AddMinutes(-minutesAgo), AttemptPairing.SecurityChannel, ip is null ? null : IPAddress.Parse(ip), 50000,
            account, reason, type, ++record);

    internal EvidenceTestStore Write(Action<EvidenceStore> fill)
    {
        using var store = EvidenceStore.OpenForWriting(Path);
        fill(store);
        return this;
    }

    internal EvidenceTestStore Append(params AuthFailure[] failures) => Write(store => new EvidenceWriter(store).Append(failures));

    internal EvidenceTestStore Covered(DateTimeOffset from, DateTimeOffset to, string status = "collected", string? reason = null) =>
        Write(store => new EvidenceWriter(store).BeginCoverage(EvidenceWriter.RawSource, from, to, status, reason));

    internal EvidenceTestStore Setting(string key, string json) =>
        Write(store => new EvidenceSettings(store).Set(key, json, "test", "test fixture", Now.AddDays(-1)));

    public void Dispose()
    {
        try { Directory.Delete(DirectoryPath, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
