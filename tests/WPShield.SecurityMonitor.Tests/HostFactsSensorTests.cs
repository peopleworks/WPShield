using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using WPShield.Evidence;

namespace WPShield.SecurityMonitor.Tests;

/// <summary>
/// The host-fact snapshots of ADR 0013, driven by hand: what is read when, what is stored, and what never is.
/// </summary>
public sealed class HostFactsSensorTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-hostfacts-tests", Guid.NewGuid().ToString("N"));
    private readonly Logger logger = new();

    public HostFactsSensorTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string StorePath => Path.Combine(directory, EvidenceStore.FileName);

    private HostFactsSensor Sensor(FakeHostFactSource source) => new(source, logger) { RunInBackground = work => Task.FromResult(work()) };

    [Fact]
    public void EveryFactIsReadAtStartThenEachOnItsOwnCadence()
    {
        var source = new FakeHostFactSource();
        using var store = EvidenceStore.OpenForWriting(StorePath);
        var session = Sensor(source).Start(store, StorePath, Now);

        // One read per tick, in priority order; nine jobs at start.
        for (var i = 0; i < 9; i++) session.Tick(Now.AddSeconds(i));
        Assert.Equal(1, source.Calls[HostFacts.Health]);
        Assert.Equal(1, source.Calls["restarts"]);
        Assert.Equal(1, source.Calls[HostFacts.Sites]);
        Assert.Equal(1, source.Calls[HostFacts.Inventory + "/" + HostFacts.Tasks]);
        Assert.Equal(8, session.Written);

        // Five minutes on: health again, nothing else.
        for (var i = 0; i < 3; i++) session.Tick(Now.AddMinutes(5).AddSeconds(i));
        Assert.Equal(2, source.Calls[HostFacts.Health]);
        Assert.Equal(1, source.Calls[HostFacts.Sites]);

        // Fifteen minutes on: sites, ports, sessions and restarts too; posture and inventory wait for six hours.
        for (var i = 0; i < 6; i++) session.Tick(Now.AddMinutes(15).AddSeconds(i));
        Assert.Equal(2, source.Calls[HostFacts.Sites]);
        Assert.Equal(2, source.Calls["restarts"]);
        Assert.Equal(1, source.Calls[HostFacts.Posture]);
    }

    [Fact]
    public void AFullNameIsComparedInMemoryAndNeverStoredOrLogged()
    {
        // The attempt is stored lowercase, as an attacker typed it; the local full name has its own capitals.
        using (var writer = EvidenceStore.OpenForWriting(StorePath))
        {
            new EvidenceWriter(writer).Append([new AuthFailure(Now.AddHours(-1), AttemptPairing.SecurityChannel, IPAddress.Parse("203.0.113.9"),
                null, "zorro marker quinto", "unknown-account", 3, 1)]);
        }
        var source = new FakeHostFactSource { FullNames = ["Zorro Marker Quinto", "Nobody Tried This"] };
        using (var store = EvidenceStore.OpenForWriting(StorePath))
        {
            var session = Sensor(source).Start(store, StorePath, Now);
            for (var i = 0; i < 9; i++) session.Tick(Now.AddSeconds(i));
            var accounts = new HostFactsQueries(store).Latest(HostFacts.Inventory, HostFacts.Accounts)!.Value<HostAccounts>()!;
            Assert.True(accounts.FullNameTargeted);
            Assert.Equal(1, accounts.FullNameMatches);
        }

        var bytes = Encoding.UTF8.GetString(File.ReadAllBytes(StorePath)) +
                    (File.Exists(StorePath + "-wal") ? Encoding.UTF8.GetString(File.ReadAllBytes(StorePath + "-wal")) : "");
        Assert.DoesNotContain("Zorro Marker Quinto", bytes, StringComparison.Ordinal);
        Assert.DoesNotContain("Nobody Tried This", bytes, StringComparison.Ordinal);
        Assert.DoesNotContain(logger.Entries, e => e.Contains("Zorro", StringComparison.Ordinal) || e.Contains("Nobody", StringComparison.Ordinal));
    }

    [Fact]
    public void ACrashIsRecordedOnceAndTheReaderResumesWhereItStopped()
    {
        var source = new FakeHostFactSource
        {
            Restarts =
            [
                new HostRestartRecord(Now.AddDays(-2), 500, 41, null),
                new HostRestartRecord(Now.AddDays(-2).AddSeconds(5), 501, 6008, null),
                new HostRestartRecord(Now.AddDays(-2).AddMinutes(2), 520, 1001, 0x133)
            ]
        };
        using var store = EvidenceStore.OpenForWriting(StorePath);
        var session = Sensor(source).Start(store, StorePath, Now);
        for (var i = 0; i < 9; i++) session.Tick(Now.AddSeconds(i));
        for (var i = 0; i < 6; i++) session.Tick(Now.AddMinutes(15).AddSeconds(i));

        var restart = Assert.Single(new HostFactsQueries(store).Restarts(Now.AddDays(-30), Now.AddDays(1)));
        Assert.Equal("0x133 DPC_WATCHDOG_VIOLATION", restart.BugCheck);
        Assert.Equal([41, 1001, 6008], restart.EventIds);
        // The first read covers 30 days (it was the second job, one tick after start); the next starts a little before where the first stopped.
        Assert.Equal(Now.AddSeconds(1) - HostFacts.RestartWindow, source.RestartSince[0]);
        Assert.Equal(source.RestartTakenAt[0] - HostRestarts.Overlap, source.RestartSince[1]);
        Assert.Contains(logger.Entries, e => e.Contains("0x133 DPC_WATCHDOG_VIOLATION", StringComparison.Ordinal));
    }

    [Fact]
    public void AFailedRestartReadNeverOverwritesTheHealthSnapshot()
    {
        var source = new FakeHostFactSource { ThrowOn = "restarts" };
        using var store = EvidenceStore.OpenForWriting(StorePath);
        var session = Sensor(source).Start(store, StorePath, Now);
        for (var i = 0; i < 9; i++) session.Tick(Now.AddSeconds(i));

        Assert.Equal(HostFactStatus.Ok, new HostFactsQueries(store).Latest(HostFacts.Health)!.Status);
        Assert.Contains(logger.Entries, e => e.Contains("restarts", StringComparison.Ordinal) && e.Contains("unreadable", StringComparison.Ordinal));
    }

    [Fact]
    public void AReadThatOutlivesItsBudgetIsStoredAsPartialAndTheNextOneRuns()
    {
        var hung = new TaskCompletionSource<object>();
        var source = new FakeHostFactSource();
        var sensor = new HostFactsSensor(source, logger) { RunInBackground = _ => hung.Task, Budget = TimeSpan.FromSeconds(10) };
        using var store = EvidenceStore.OpenForWriting(StorePath);
        var session = sensor.Start(store, StorePath, Now);

        session.Tick(Now);
        session.Tick(Now.AddSeconds(15));
        Assert.Null(new HostFactsQueries(store).Latest(HostFacts.Health));
        session.Tick(Now.AddSeconds(25));

        var health = new HostFactsQueries(store).Latest(HostFacts.Health)!;
        Assert.Equal(HostFactStatus.Partial, health.Status);
        Assert.Equal("time-budget", health.Reason);
        Assert.NotNull(health.Remedy);
    }

    [Fact]
    public void AnInventoryChangeBetweenTwoSnapshotsIsRecorded()
    {
        var source = new FakeHostFactSource();
        using var store = EvidenceStore.OpenForWriting(StorePath);
        var session = Sensor(source).Start(store, StorePath, Now);
        for (var i = 0; i < 9; i++) session.Tick(Now.AddSeconds(i));

        source.Tasks = [.. source.Tasks, new HostTask(@"\Updater.example", "ready", "SYSTEM", null, null, @"C:\ProgramData\x\u.exe",
            HostSignature.Unsigned, null, [CommandFlags.HasArguments, CommandFlags.EncodedCommand])];
        for (var i = 0; i < 12; i++) session.Tick(Now.AddHours(6).AddSeconds(i));

        var change = Assert.Single(new HostFactsQueries(store).InventoryChanges(Now, Now.AddDays(1), HostFacts.Tasks));
        Assert.Equal("added", change.Change);
        Assert.Equal(@"\Updater.example", change.Item);
    }

    // ---------------------------------------------------------------------------------------------

    private sealed class Logger : ILogger
    {
        private readonly ConcurrentQueue<string> entries = new();

        public IReadOnlyList<string> Entries => [.. entries];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            entries.Enqueue(formatter(state, exception));
    }
}

/// <summary>A host-fact source with canned answers, counting what it was asked.</summary>
internal sealed class FakeHostFactSource : IHostFactSource
{
    public ConcurrentDictionary<string, int> Calls { get; } = new();

    public IReadOnlyList<string> FullNames { get; set; } = ["Synthetic Person"];

    public IReadOnlyList<HostRestartRecord> Restarts { get; set; } = [];

    public IReadOnlyList<HostTask> Tasks { get; set; } =
        [new HostTask(@"\Backup.example", "ready", "SYSTEM", null, null, @"C:\Tools\backup.exe", HostSignature.Signed, "Example Signer", [])];

    public List<DateTimeOffset> RestartSince { get; } = [];

    public List<DateTimeOffset> RestartTakenAt { get; } = [];

    public string? ThrowOn { get; set; }

    public DateTimeOffset TakenAt { get; set; } = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    private void Count(string name)
    {
        Calls.AddOrUpdate(name, 1, (_, n) => n + 1);
        if (ThrowOn == name) throw new InvalidOperationException("synthetic failure");
    }

    public HostFactReading ReadHealth(string? storePath, CancellationToken cancellationToken)
    {
        Count(HostFacts.Health);
        return HostFactReading.Of(HostFacts.Health, null, TakenAt,
            new HostHealth(TakenAt.AddDays(-3), 3 * 86_400, 12.5, 32L << 30, 8L << 30, [new HostVolume(@"C:\", 500L << 30, 120L << 30, true)], 1 << 20));
    }

    public HostRestartReading ReadRestarts(DateTimeOffset since, CancellationToken cancellationToken)
    {
        Count("restarts");
        RestartSince.Add(since);
        RestartTakenAt.Add(TakenAt);
        return new HostRestartReading(TakenAt, HostFactStatus.Ok, null, null, [.. Restarts.Where(r => r.At >= since)]);
    }

    public HostFactReading ReadSites(CancellationToken cancellationToken)
    {
        Count(HostFacts.Sites);
        return HostFactReading.Of(HostFacts.Sites, null, TakenAt,
            new HostSites([new HostSite(2, "shop.example", "Started", [new HostBinding("https", 443, "shop.example", false)], "shop", "SpecificUser", true)]));
    }

    public HostFactReading ReadPosture(CancellationToken cancellationToken)
    {
        Count(HostFacts.Posture);
        return HostFactReading.Of(HostFacts.Posture, null, TakenAt,
            new HostPosture("collector", true, [new HostPostureFinding("AUDIT-002", "critical", "2 application pool(s) run with administrator rights", 2)],
                3, 2, true, 1, 0));
    }

    public HostFactReading ReadPorts(CancellationToken cancellationToken)
    {
        Count(HostFacts.Ports);
        return HostFactReading.Of(HostFacts.Ports, null, TakenAt,
            new HostPorts([new HostListener("TCP", 445, "any", null, "System", "System", ExposureVerdicts.OpenToAny, true)], true));
    }

    public HostFactReading ReadSessions(DateTimeOffset since, CancellationToken cancellationToken)
    {
        Count(HostFacts.Sessions);
        return HostFactReading.Of(HostFacts.Sessions, null, TakenAt,
            new HostSessions([new HostSession(2, "active", @"HOST\operator", TakenAt.AddHours(-1))],
                [new HostRdpLogon(TakenAt.AddHours(-1), @"HOST\operator", "198.51.100.20", "logon")]));
    }

    public HostInventoryReading ReadInventory(string kind, CancellationToken cancellationToken)
    {
        Count(HostFacts.Inventory + "/" + kind);
        return kind switch
        {
            HostFacts.Accounts => new HostInventoryReading(HostFactReading.Of(HostFacts.Inventory, kind, TakenAt,
                new HostAccounts([new HostAccount("operator", true, true, true, TakenAt.AddDays(-1), 30, false)], null, null)), FullNames),
            HostFacts.Services => new HostInventoryReading(HostFactReading.Of(HostFacts.Inventory, kind, TakenAt,
                new HostServices([new HostService("backupsvc", "Backup", "running", "automatic", "LocalSystem", @"C:\Tools\backup.exe",
                    HostSignature.Signed, "Example Signer", [])], 0))),
            _ => new HostInventoryReading(HostFactReading.Of(HostFacts.Inventory, kind, TakenAt, new HostTasks(Tasks, 0)))
        };
    }
}
