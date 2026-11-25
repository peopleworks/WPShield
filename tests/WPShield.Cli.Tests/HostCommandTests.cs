using System.Text.Json;
using WPShield.Cli;
using WPShield.Evidence;
using WPShield.SecurityMonitor;

namespace WPShield.Cli.Tests;

/// <summary>
/// <c>wpshield host</c>: every fact with its age and status, "no snapshot yet" where nothing was read, stale
/// snapshots marked, verdicts labelled with their source, and a live read that writes nothing. Synthetic names only.
/// </summary>
public sealed class HostCommandTests : IDisposable
{
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly EvidenceTestStore store = new();

    public void Dispose() => store.Dispose();

    private (int Exit, string Output, string Error) Run(params string[] args) => Run(new Source(), args);

    private (int Exit, string Output, string Error) Run(IHostFactSource source, params string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var exit = HostCommand.Run(args, output, error, store.Path, () => true, () => Now, () => source);
        return (exit, output.ToString(), error.ToString());
    }

    private void Recorded() => store.Write(s =>
    {
        var writer = new HostFactsWriter(s);
        var source = new Source();
        writer.Write(source.ReadHealth(null, default) with { TakenAt = Now.AddMinutes(-3) });
        writer.Write(source.ReadPorts(default) with { TakenAt = Now.AddMinutes(-10) });
        // Six hours old for a fifteen-minute cadence: stale.
        writer.Write(source.ReadSessions(Now, default) with { TakenAt = Now.AddHours(-6) });
        writer.Write(HostFactReading.Failed(HostFacts.Sites, null, Now.AddMinutes(-10), HostFactStatus.NeedsElevation, "not-elevated",
            "Run the collector elevated: IIS is readable by administrators only."));
        writer.Write(source.ReadInventory(HostFacts.Accounts, default).WithFullNameIndicator(["synthetic person"]) with { TakenAt = Now.AddHours(-1) });
        writer.Write(source.ReadInventory(HostFacts.Services, default).Reading with { TakenAt = Now.AddHours(-1) });
        writer.RecordRestarts(HostRestarts.Group([new HostRestartRecord(Now.AddDays(-2), 70, 41, null),
            new HostRestartRecord(Now.AddDays(-2).AddMinutes(2), 71, 1001, 0x133)]));
    });

    [Fact]
    public void TheSummaryShowsEveryFactWithItsAgeAndSaysWhatWasNeverRead()
    {
        Recorded();

        var (exit, output, _) = Run();

        Assert.Equal(0, exit);
        Assert.Contains("Nothing on this server is changed.", output, StringComparison.Ordinal);
        Assert.Contains("unexpected restarts in 30 days: 1 (0x133 DPC_WATCHDOG_VIOLATION)", output, StringComparison.Ordinal);
        Assert.Contains("needs-elevation", output, StringComparison.Ordinal);
        Assert.Contains("Run the collector elevated: IIS is readable by administrators only.", output, StringComparison.Ordinal);
        Assert.Contains("iis_posture      no snapshot yet", output, StringComparison.Ordinal);
        Assert.Contains("tasks            no snapshot yet", output, StringComparison.Ordinal);
        Assert.Contains("STALE", Line(output, "rdp_sessions"), StringComparison.Ordinal);
        Assert.DoesNotContain("STALE", Line(output, "host_health"), StringComparison.Ordinal);
        Assert.Contains("attackers try a real account's full name: YES (1)", output, StringComparison.Ordinal);
        Assert.Contains("RED: 445", output, StringComparison.Ordinal);
    }

    [Fact]
    public void PortsSayTheirVerdictsAreByTheFirewallRulesNeverReachable()
    {
        Recorded();

        var (_, output, _) = Run("ports");

        Assert.Contains("Verdicts are by the Windows Firewall rules", output, StringComparison.Ordinal);
        Assert.Contains("never shown as \"reachable\"", output, StringComparison.Ordinal);
        Assert.Contains("RED  TCP   445", output, StringComparison.Ordinal);
        Assert.Contains("restrict the firewall rule", output, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInventoryNeverShowsArgumentsAndCleansNamesForTheConsole()
    {
        Recorded();

        var (_, output, _) = Run("inventory", "services");

        Assert.Contains("encoded-command", output, StringComparison.Ordinal);
        Assert.Contains("Arguments are never stored or shown", output, StringComparison.Ordinal);
        Assert.DoesNotContain("\u001b", output, StringComparison.Ordinal);
    }

    [Fact]
    public void HealthListsEveryRestartWithItsCode()
    {
        Recorded();

        var (_, output, _) = Run("health");

        Assert.Contains("Unexpected restarts in the last 30 days: 1", output, StringComparison.Ordinal);
        Assert.Contains("events 41/1001  0x133 DPC_WATCHDOG_VIOLATION", output, StringComparison.Ordinal);
        Assert.Contains("(IIS logs)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ThePatchLevelIsShownAsFactsWithTheDaysSinceTheLastCumulativeUpdate()
    {
        Recorded();

        var (_, summary, _) = Run();
        var (_, health, _) = Run("health");

        Assert.Contains("build 20348.2849; last cumulative update: 2026-11-02 12:00 UTC, 22 days ago; failed installs in 30 days: 1", summary, StringComparison.Ordinal);
        Assert.Contains("OS build          20348.2849 (21H2)", health, StringComparison.Ordinal);
        Assert.Contains("Kernel file       10.0.20348.2849", health, StringComparison.Ordinal);
        Assert.DoesNotContain("differs from the registry", health, StringComparison.Ordinal);
        Assert.Contains("22 days ago: 2026-11 Cumulative Update", health, StringComparison.Ordinal);
        Assert.Contains("never calls a host outdated", health, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnreadableUpdateLogIsUnknownNeverNone()
    {
        var (_, output, _) = Run(new Source { UpdateLogReadable = false }, "health", "--live");

        Assert.Contains("Last cumulative   unknown (the Windows Update log could not be read)", output, StringComparison.Ordinal);
        Assert.Contains("Failed installs   unknown", output, StringComparison.Ordinal);
        Assert.Contains("its revision differs from the registry's UBR", output, StringComparison.Ordinal);
        Assert.DoesNotContain("none", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void JsonCarriesTheSnapshotsTheirStatusAndTheRestarts()
    {
        Recorded();

        var (exit, output, _) = Run("--json");

        Assert.Equal(0, exit);
        using var document = JsonDocument.Parse(output);
        var snapshots = document.RootElement.GetProperty("snapshots");
        Assert.Contains(snapshots.EnumerateArray(), s => s.GetProperty("fact").GetString() == HostFacts.Sessions && s.GetProperty("stale").GetBoolean());
        Assert.Equal("by the Windows Firewall rules", document.RootElement.GetProperty("exposureVerdictsAre").GetString());
        Assert.Equal(0x133, document.RootElement.GetProperty("restarts")[0].GetProperty("bugCheckCode").GetInt32());
    }

    [Fact]
    public void ALiveReadWritesNothing()
    {
        Recorded();
        var before = File.ReadAllBytes(store.Path);

        var (exit, output, _) = Run(new Source(), "--live");

        Assert.Equal(0, exit);
        Assert.Contains("LIVE READ. Nothing was written", output, StringComparison.Ordinal);
        Assert.Contains("iis_sites", output, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllBytes(store.Path));
        using var reader = EvidenceStore.OpenReadOnly(store.Path);
        Assert.Null(new HostFactsQueries(reader).Latest(HostFacts.Posture));
    }

    [Fact]
    public void ALiveReaderThatFailsIsReportedAsUnreadableNotAsEmpty()
    {
        var (exit, output, _) = Run(new Source { Fail = true }, "sites", "--live");

        Assert.Equal(0, exit);
        Assert.Contains("unreadable", output, StringComparison.Ordinal);
        Assert.Contains("read-failed: InvalidOperationException", output, StringComparison.Ordinal);
    }

    [Fact]
    public void AStoreWithNoSnapshotSaysSoAndAMissingStoreIsNotAnEmptyHost()
    {
        store.Write(_ => { });
        var (exit, output, _) = Run();
        Assert.Equal(2, exit);
        Assert.Contains("no snapshot yet", output, StringComparison.Ordinal);

        using var missingOutput = new StringWriter();
        using var missingError = new StringWriter();
        var missing = HostCommand.Run([], missingOutput, missingError, Path.Combine(store.DirectoryPath, "none.db"), () => true, () => Now,
            () => new Source());
        Assert.Equal(3, missing);
    }

    [Theory]
    [InlineData("firewall")]
    [InlineData("inventory")]
    [InlineData("inventory", "drivers")]
    [InlineData("health", "extra")]
    [InlineData("--live=yes")]
    [InlineData("--unknown")]
    public void AWrongArgumentIsRefused(params string[] args) =>
        Assert.Throws<CliArgumentException>(() => HostCommand.Parse(args));

    private static string Line(string output, string label) =>
        output.Split('\n').First(l => l.TrimStart().StartsWith(label, StringComparison.Ordinal));

    /// <summary>A host with synthetic answers.</summary>
    private sealed class Source : IHostFactSource
    {
        public bool Fail { get; init; }

        public bool UpdateLogReadable { get; init; } = true;

        public HostFactReading ReadHealth(string? storePath, CancellationToken cancellationToken) =>
            HostFactReading.Of(HostFacts.Health, null, Now,
                new HostHealth(Now.AddDays(-3), 3 * 86_400, 12.5, 32L << 30, 8L << 30, [new HostVolume(@"C:\", 500L << 30, 120L << 30, true)], 1 << 20,
                    UpdateLogReadable
                        ? new HostPatchLevel("20348", 2849, "21H2", "10.0.20348.2849", true,
                            "2026-11 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5090001)", Now.AddDays(-22), 1)
                        : new HostPatchLevel("20348", 2849, "21H2", "10.0.20348.4405", false, null, null, null)));

        public HostRestartReading ReadRestarts(DateTimeOffset since, CancellationToken cancellationToken) =>
            new(Now, HostFactStatus.Ok, null, null, []);

        public HostFactReading ReadSites(CancellationToken cancellationToken) =>
            Fail ? throw new InvalidOperationException("synthetic")
                : HostFactReading.Of(HostFacts.Sites, null, Now, new HostSites([new HostSite(2, "shop.example", "Started", [], "shop", "SpecificUser", true)]));

        public HostFactReading ReadPosture(CancellationToken cancellationToken) =>
            HostFactReading.Of(HostFacts.Posture, null, Now, new HostPosture("collector", true, [], 3, 2, true, 1, 0));

        public HostFactReading ReadPorts(CancellationToken cancellationToken) =>
            HostFactReading.Of(HostFacts.Ports, null, Now, new HostPorts(
            [
                new HostListener("TCP", 445, "any", null, "System", "System", ExposureVerdicts.OpenToAny, true),
                new HostListener("TCP", 3306, "any", null, "mysqld.exe", @"C:\MySQL\mysqld.exe", ExposureVerdicts.Restricted, false),
                new HostListener("TCP", 1433, "loopback", "127.0.0.1", "sqlservr.exe", null, ExposureVerdicts.LocalOnly, false)
            ], true));

        public HostFactReading ReadSessions(DateTimeOffset since, CancellationToken cancellationToken) =>
            HostFactReading.Of(HostFacts.Sessions, null, Now,
                new HostSessions([new HostSession(2, "active", @"HOST\operator", Now.AddHours(-1))], [new HostRdpLogon(Now.AddHours(-1), @"HOST\operator", "198.51.100.20", "logon")]));

        public HostInventoryReading ReadInventory(string kind, CancellationToken cancellationToken) => kind switch
        {
            HostFacts.Accounts => new(HostFactReading.Of(HostFacts.Inventory, kind, Now,
                new HostAccounts([new HostAccount("operator", true, true, true, Now.AddDays(-1), 30, false)], null, null)), ["Synthetic Person"]),
            HostFacts.Services => new(HostFactReading.Of(HostFacts.Inventory, kind, Now, new HostServices(
                [new HostService("updater\u001b[31m", "Updater", "running", "automatic", "LocalSystem", @"C:\ProgramData\u\u.exe", HostSignature.Unsigned, null,
                    [CommandFlags.HasArguments, CommandFlags.EncodedCommand])], 0))),
            _ => new(HostFactReading.Of(HostFacts.Inventory, kind, Now, new HostTasks([], 0)))
        };
    }
}
