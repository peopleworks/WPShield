using System.Net;
using System.Reflection;
using System.Text.Json.Nodes;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

public sealed class EvidenceStoreTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-evidence-tests", Guid.NewGuid().ToString("N"));
    private long record;

    public EvidenceStoreTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string DbPath => Path.Combine(directory, EvidenceStore.FileName);

    private AuthFailure Failure(double minutesAgo, string? ip, string account = "admin", string reason = "bad-password",
        string channel = AttemptPairing.SecurityChannel, int type = 10, double seconds = 0, long? id = null) =>
        new(Now.AddMinutes(-minutesAgo).AddSeconds(seconds), channel, ip is null ? null : IPAddress.Parse(ip), null,
            account, reason, type, id ?? ++record);

    [Fact]
    public void TheWriterNeverCreatesTheDirectory()
    {
        var missing = Path.Combine(directory, "missing", EvidenceStore.FileName);
        Assert.Throws<DirectoryNotFoundException>(() => EvidenceStore.OpenForWriting(missing));
        Assert.False(Directory.Exists(Path.GetDirectoryName(missing)));
    }

    [Fact]
    public void AReaderCannotOpenWhatDoesNotExistNorWrite()
    {
        Assert.Throws<FileNotFoundException>(() => EvidenceStore.OpenReadOnly(DbPath));
        using (EvidenceStore.OpenForWriting(DbPath)) { }
        using var reader = EvidenceStore.OpenReadOnly(DbPath);
        Assert.True(reader.ReadOnly);
        Assert.Throws<InvalidOperationException>(() => new EvidenceWriter(reader));
        Assert.Throws<InvalidOperationException>(() => new EvidenceSettings(reader).Set("retention.raw_days", "7", "test", "test"));
    }

    [Fact]
    public void CatchingUpTwiceNeverCountsAnAttemptTwice()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        AuthFailure[] batch = [Failure(10, "203.0.113.1", id: 1), Failure(9, "203.0.113.1", id: 2)];

        Assert.Equal(2, writer.Append(batch));
        Assert.Equal(0, writer.Append(batch));

        var summary = new EvidenceQueries(store).Summary(Now.AddHours(-1), Now);
        Assert.Equal(2, summary.Attempts);
        var hourly = store.Scalar<long>("SELECT SUM(attempts) FROM hourly_sources;");
        Assert.Equal(2, hourly);
        Assert.Equal(2, writer.LastRecord(AttemptPairing.SecurityChannel)!.Value.RecordId);
    }

    [Fact]
    public void AnNlaPairIsStoredOnceWithTheAddress()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.Append([Failure(5, null, type: 3), Failure(5, "198.51.100.4", channel: AttemptPairing.RdpChannel, seconds: 1)]);

        var summary = new EvidenceQueries(store).Summary(Now.AddHours(-1), Now);
        Assert.Equal(1, summary.Attempts);
        Assert.Equal(0, summary.WithoutAddress);
        Assert.Equal(1, summary.Sources);
    }

    [Fact]
    public void ThePairingBufferHoldsRecordsUntilTheirPartnerCanArrive()
    {
        var buffer = new PairingBuffer();
        buffer.Add(Failure(0, null, type: 3));
        Assert.Empty(buffer.TakeReady(Now));
        buffer.Add(Failure(0, "198.51.100.4", channel: AttemptPairing.RdpChannel, seconds: 1));
        var ready = buffer.TakeReady(Now.AddSeconds(30));
        var only = Assert.Single(ready);
        Assert.Equal(AttemptPairing.RdpChannel, only.Channel);
        Assert.Empty(buffer.TakeReady(Now.AddSeconds(60), flushAll: true));
    }

    [Fact]
    public void QueriesAnswerWithSourcesNeighboursAndAccounts()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.Append([
            Failure(30, "203.0.113.1", "admin"), Failure(29, "203.0.113.1", "admin"), Failure(28, "203.0.113.1", "sa", "unknown-account"),
            Failure(27, "203.0.113.2"), Failure(26, "192.0.2.9", "backup"), Failure(25, null, type: 3)]);
        var queries = new EvidenceQueries(store);

        var summary = queries.Summary(Now.AddHours(-1), Now);
        Assert.Equal(6, summary.Attempts);
        Assert.Equal(3, summary.Sources);
        Assert.Equal(1, summary.WithoutAddress);
        Assert.Equal("admin", summary.TopAccount);
        Assert.True(summary.Detailed);

        var top = queries.TopSources(Now.AddHours(-1), Now, 10);
        Assert.Equal("203.0.113.1", top[0].Address);
        Assert.Equal(3, top[0].Attempts);
        Assert.Equal(2, top[0].Accounts);
        Assert.Equal(1, top[0].Neighbors);
        Assert.Equal(0, top.Single(s => s.Address == "192.0.2.9").Neighbors);

        var history = queries.SourceHistory("203.0.113.1", Now.AddHours(-1), Now);
        Assert.Equal(("admin", 2), history.Accounts[0]);
        Assert.Equal("sa", history.Recent[0].Account);
        Assert.Equal(1, history.DaysSeen);
        Assert.NotNull(history.FirstSeen);
    }

    [Fact]
    public void TimelineMarksWhatTheCollectorDidNotCover()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.Append([Failure(10, "203.0.113.1")]);
        writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddMinutes(-30), Now);

        var buckets = new EvidenceQueries(store).Timeline(Now.AddHours(-1), Now, TimeSpan.FromMinutes(5));

        Assert.Equal(12, buckets.Count);
        Assert.All(buckets.Take(6), b => Assert.False(b.Covered));
        Assert.All(buckets.Skip(6), b => Assert.True(b.Covered));
        Assert.Equal(1, buckets.Sum(b => b.Attempts));
    }

    [Fact]
    public void AnotherSourcesCoverageDoesNotCoverFailedLogons()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.BeginCoverage("http-gateway", Now.AddHours(-1), Now);

        var buckets = new EvidenceQueries(store).Timeline(Now.AddHours(-1), Now, TimeSpan.FromMinutes(10));

        Assert.All(buckets, b => Assert.False(b.Covered));
    }

    [Fact]
    public void AFloodInOneInstantStaysBoundedAndStillPairsNeighbours()
    {
        var flood = Enumerable.Range(0, 20_000)
            .Select(i => Failure(1, $"203.0.113.{i % 250 + 1}", channel: AttemptPairing.SecurityChannel, type: 10, id: i + 1))
            .Append(Failure(1, null, type: 3, id: 30_000))
            .Append(Failure(1, "198.51.100.4", channel: AttemptPairing.RdpChannel, seconds: 0.5, id: 30_001));
        var timer = System.Diagnostics.Stopwatch.StartNew();

        var paired = AttemptPairing.Pair(flood);

        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(5), $"pairing took {timer.Elapsed}");
        Assert.Equal(20_001, paired.Count);
    }

    [Fact]
    public void AfterPruningOldPeriodsAnswerFromTheHourlyAggregatesAndSaySo()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.Append([Failure(60 * 24 * 20, "203.0.113.1", "admin"), Failure(60 * 24 * 20 - 1, "203.0.113.1", "sa", "unknown-account"),
            Failure(10, "203.0.113.1")]);

        var pruned = writer.Prune(Now, new EvidenceLimits());

        Assert.Equal(2, pruned.RawRowsDeleted);
        var queries = new EvidenceQueries(store);
        var month = queries.Summary(Now.AddDays(-30), Now);
        Assert.False(month.Detailed);
        Assert.Equal(3, month.Attempts);
        Assert.Equal(1, month.UnknownAccount);
        Assert.Null(month.TopAccount);
        Assert.True(queries.Summary(Now.AddDays(-1), Now).Detailed);
    }

    [Fact]
    public void PruningHonoursTheRowBoundAndKeepsAggregates()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.Append(Enumerable.Range(0, 50).Select(i => Failure(100 - i, "203.0.113.1")));

        writer.Prune(Now, new EvidenceLimits { MaxRawRows = 20 });

        Assert.Equal(20, store.Scalar<long>("SELECT COUNT(*) FROM auth_failures;"));
        Assert.Equal(50, store.Scalar<long>("SELECT SUM(attempts) FROM hourly_sources;"));
    }

    [Fact]
    public void DecisionsAreKeptAsAnAuditTrail()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var writer = new EvidenceWriter(store);
        writer.RecordDecision(new(Now.AddMinutes(-5), "would-block", "203.0.113.1", "WP-SEC-001", "monitor",
            "12 failures in 10 minutes", "security-4625", Now.AddHours(1)));

        var decision = Assert.Single(new EvidenceQueries(store).Decisions(Now.AddHours(-1), Now));
        Assert.Equal("would-block", decision.Action);
        Assert.Equal("monitor", decision.Mode);
    }

    [Fact]
    public void SettingsAreValidatedVersionedAndAudited()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var settings = new EvidenceSettings(store);
        Assert.Equal(14, settings.Get<int>("retention.raw_days"));

        var change = settings.Set("retention.raw_days", "30", "pedro", "keep a month of detail", Now);
        Assert.Null(change.OldValue);
        Assert.Equal("30", change.NewValue);
        Assert.Equal(30, settings.Get<int>("retention.raw_days"));
        Assert.Equal(TimeSpan.FromDays(30), settings.Limits().RawRetention);

        Assert.Throws<ArgumentException>(() => settings.Set("retention.raw_days", "0", "pedro", "too small"));
        Assert.Throws<ArgumentException>(() => settings.Set("retention.raw_days", "\"thirty\"", "pedro", "wrong type"));
        Assert.Throws<ArgumentException>(() => settings.Set("retention.raw_days", "{", "pedro", "not json"));
        Assert.Throws<KeyNotFoundException>(() => settings.Set("retention.rawdays", "7", "pedro", "typo"));
        Assert.Throws<ArgumentException>(() => settings.Set("retention.raw_days", "7", "pedro", ""));

        settings.Reset("retention.raw_days", "pedro", "back to default", Now.AddMinutes(1));
        Assert.Equal(14, settings.Get<int>("retention.raw_days"));
        var history = settings.History("retention.raw_days");
        Assert.Equal(2, history.Count);
        Assert.Null(history[0].NewValue);
        Assert.Equal("keep a month of detail", history[1].Reason);
        Assert.True(settings.List().Single(s => s.Key == "retention.raw_days").IsDefault);
    }

    [Fact]
    public void LabelsAcceptAddressesAndNetworksAndCleanTheText()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var settings = new EvidenceSettings(store);

        settings.Set("labels.addresses", """{"198.51.100.7":"My office","203.0.113.0/24":"Scanner\u001b network"}""", "pedro", "names");
        var labels = settings.Get("labels.addresses").AsObject();
        Assert.Equal("My office", labels["198.51.100.7"]!.GetValue<string>());
        Assert.Equal("Scanner� network", labels["203.0.113.0/24"]!.GetValue<string>());

        Assert.Throws<ArgumentException>(() => settings.Set("labels.addresses", """{"not-an-ip":"x"}""", "pedro", "bad"));
        Assert.Throws<ArgumentException>(() => settings.Set("labels.addresses", """{"203.0.113.0/33":"x"}""", "pedro", "bad"));
        Assert.Throws<ArgumentException>(() => settings.Set("labels.addresses", """{"010.0.0.1":"x"}""", "pedro", "bad"));
    }

    [Fact]
    public void EventsOfNewKindsNeedNoSchemaChange()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var events = new EvidenceEvents(store);
        var detail = new JsonObject { ["status"] = 403, ["rule"] = "WP-PATH-001", ["path"] = "/wp-content/uploads/x.php\u001b" };

        Assert.True(events.Append(new(Now.AddMinutes(-3), "http.request-refused", "gateway", "203.0.113.5", "/wp-content/uploads/x.php", detail, "req-1")));
        Assert.False(events.Append(new(Now.AddMinutes(-3), "http.request-refused", "gateway", "203.0.113.5", "/wp-content/uploads/x.php", detail, "req-1")));

        var stored = Assert.Single(events.Query("http.request-refused", Now.AddHours(-1), Now));
        Assert.Equal("203.0.113.5", stored.Address);
        Assert.Equal("/wp-content/uploads/x.php�", stored.Detail["path"]!.GetValue<string>());
        Assert.Equal(403, stored.Detail["status"]!.GetValue<int>());
        Assert.Equal(("http.request-refused", 1L), Assert.Single(events.Kinds(Now.AddHours(-1), Now)));

        Assert.Throws<ArgumentException>(() => events.Append(new(Now, "HTTP Refused", "gateway", null, "x", [])));
        Assert.Throws<ArgumentException>(() => events.Append(new(Now, "http.x", "gateway", "not-an-ip", "x", [])));
        var big = new JsonObject();
        for (var i = 0; i < 40; i++) big[$"k{i}"] = new string('a', 300);
        Assert.Throws<ArgumentException>(() => events.Append(new(Now, "http.x", "gateway", null, "x", big)));
    }

    [Fact]
    public void EventsArePrunedByAge()
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        var events = new EvidenceEvents(store);
        events.Append(new(Now.AddDays(-100), "sql.login-failed", "sqlserver", null, "MSSQLSERVER", []));
        events.Append(new(Now.AddDays(-1), "sql.login-failed", "sqlserver", null, "MSSQLSERVER", []));

        var result = new EvidenceWriter(store).Prune(Now, new EvidenceLimits());

        Assert.Equal(1, result.EventRowsDeleted);
        Assert.Single(events.Query("sql.login-failed", Now.AddDays(-400), Now));
    }

    [Fact]
    public void NoPublicMethodAcceptsAStreamOrRawBytes()
    {
        // ADR 0007: request bodies are never stored. The structural form of that promise is that no
        // public entry point of this assembly can be handed one.
        var offenders = typeof(EvidenceStore).Assembly.GetExportedTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Concat<MethodBase>(t.GetConstructors()))
            .Where(m => m.GetParameters().Any(p => typeof(Stream).IsAssignableFrom(p.ParameterType) ||
                p.ParameterType == typeof(byte[]) || p.ParameterType == typeof(ReadOnlyMemory<byte>)))
            .Select(m => $"{m.DeclaringType!.Name}.{m.Name}")
            .ToArray();
        Assert.Empty(offenders);
    }
}
