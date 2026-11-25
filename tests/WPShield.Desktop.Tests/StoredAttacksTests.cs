using System.Net;
using System.Text.Json.Nodes;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// The 7-day and 30-day ranges, read from a real evidence store in a temporary directory and turned
/// into what the attacks view draws. Synthetic RFC 5737 addresses only.
/// </summary>
public sealed class StoredAttacksTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private readonly string directory = Path.Combine(Path.GetTempPath(), "wpshield-desktop-evidence-tests", Guid.NewGuid().ToString("N"));
    private long record;

    public StoredAttacksTests() => Directory.CreateDirectory(directory);

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private string DbPath => Path.Combine(directory, EvidenceStore.FileName);

    private EvidenceAttackStore Store(bool elevated = true) => new(DbPath, () => elevated);

    private AuthFailure Failure(double hoursAgo, string ip, string account = "admin", string reason = "bad-password") =>
        new(Now.AddHours(-hoursAgo), AttemptPairing.SecurityChannel, IPAddress.Parse(ip), null, account, reason, 3, ++record);

    private void Fill(Action<EvidenceStore> fill)
    {
        using var store = EvidenceStore.OpenForWriting(DbPath);
        fill(store);
    }

    private void Week()
    {
        Fill(store =>
        {
            var writer = new EvidenceWriter(store);
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddDays(-8), Now.AddMinutes(-1));
            writer.Append([Failure(72, "203.0.113.10", "admin"), Failure(71, "203.0.113.10", "sa", "unknown-account"),
                Failure(48, "203.0.113.10", "admin"), Failure(30, "203.0.113.11", "backup"), Failure(2, "198.51.100.7", "pedro")]);
            new EvidenceSettings(store).Set(AddressLabels.SettingKey, """{"203.0.113.0/24":"Scanner‮ network","198.51.100.7":"My office"}""",
                "test", "names");
        });
    }

    [Fact]
    public void AWeekIsReadFromTheStoreWithLabelsAndHourlyBuckets()
    {
        Week();

        var data = Store().Read(AttackRange.Week, Now);
        var view = StoredAttackBoard.View(data, "");

        Assert.Equal(5, view.Attempts);
        Assert.Equal(3, view.Sources);
        Assert.True(view.Detailed);
        Assert.False(view.NoData);
        Assert.Equal("admin", view.TopAccount);
        var top = view.Rows[0];
        Assert.Equal("203.0.113.10", top.Address);
        Assert.Equal(2, top.Accounts);
        Assert.Equal(1, top.Neighbors);
        // The bidirectional override was replaced before it reached the window.
        Assert.Equal("Scanner� network", top.Label);
        Assert.Equal(StoredAttackBoard.NotAsked, top.TopAccounts);
        Assert.Equal("My office", view.Rows.Single(r => r.Address == "198.51.100.7").Label);
        Assert.Equal(168, view.Buckets.Count);
        Assert.All(view.Buckets, b => Assert.True(b.Covered));
        Assert.Equal(0, view.LastHour);
        Assert.True(view.LastHourKnown);
    }

    [Theory]
    [InlineData("scanner", 2)]
    [InlineData("office", 1)]
    [InlineData("203.0.113.0/24", 2)]
    public void SearchFindsLabelsAddressesAndNetworks(string query, int rows)
    {
        Week();

        Assert.Equal(rows, StoredAttackBoard.View(Store().Read(AttackRange.Week, Now), query).MatchingRows);
    }

    [Fact]
    public void HoursTheServiceDidNotRecordAreGreyNotQuiet()
    {
        Fill(store =>
        {
            var writer = new EvidenceWriter(store);
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddDays(-8), Now.AddHours(-50));
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddHours(-45), Now);
        });

        var buckets = StoredAttackBoard.View(Store().Read(AttackRange.Week, Now), "").Buckets;

        var gap = buckets.Where(b => !b.Covered).ToArray();
        Assert.Equal(5, gap.Length);
        Assert.All(gap, b => Assert.InRange(b.Start, Now.AddHours(-50), Now.AddHours(-46)));
    }

    [Fact]
    public void ALastHourTheServiceDidNotRecordIsUnknownNotZero()
    {
        Fill(store =>
        {
            var writer = new EvidenceWriter(store);
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddDays(-8), Now.AddHours(-3));
            writer.Append([Failure(5, "203.0.113.10")]);
        });

        var view = StoredAttackBoard.View(Store().Read(AttackRange.Week, Now), "");

        Assert.False(view.LastHourKnown);
        Assert.Equal(1, view.Attempts);
    }

    [Fact]
    public void NothingRecorded_IsNoDataNotAQuietMonth()
    {
        Fill(_ => { });

        var view = StoredAttackBoard.View(Store().Read(AttackRange.Month, Now), "");

        Assert.True(view.NoData);
        Assert.Equal(31, view.Buckets.Count);
        Assert.All(view.Buckets, b => Assert.False(b.Covered));
    }

    [Fact]
    public void AMonthFromAggregates_SaysAccountNamesAndSingleAttemptsAreGone()
    {
        Fill(store =>
        {
            var writer = new EvidenceWriter(store);
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddDays(-31), Now);
            writer.Append([Failure(24 * 20, "203.0.113.10", "admin"), Failure(24 * 20 - 1, "203.0.113.10", "sa"), Failure(1, "203.0.113.12")]);
            writer.Prune(Now, new EvidenceLimits());
        });
        var store = Store();
        var data = store.Read(AttackRange.Month, Now);

        var view = StoredAttackBoard.View(data, "");
        var detail = StoredAttackBoard.Detail(data, store.History("203.0.113.10", data.Window));

        Assert.False(view.Detailed);
        Assert.Equal(3, view.Attempts);
        Assert.Null(view.Rows.Single(r => r.Address == "203.0.113.10").Accounts);
        Assert.NotNull(detail);
        Assert.False(detail.Detailed);
        Assert.Empty(detail.Accounts);
        Assert.Empty(detail.Recent);
        Assert.NotNull(detail.FirstSeen);
        Assert.Equal(("203.0.113.12", 1), Assert.Single(detail.Neighbors));
    }

    [Fact]
    public void AWeeksDetailListsAccountsAndLatestAttempts()
    {
        Week();
        var store = Store();
        var data = store.Read(AttackRange.Week, Now);

        var detail = StoredAttackBoard.Detail(data, store.History("203.0.113.10", data.Window));

        Assert.NotNull(detail);
        Assert.True(detail.Detailed);
        Assert.Equal(("admin", 2), detail.Accounts[0]);
        Assert.Equal(3, detail.Recent.Count);
        Assert.Equal(7, detail.Timeline.Count);
        Assert.Equal(("203.0.113.11", 1), Assert.Single(detail.Neighbors));
    }

    [Fact]
    public void TheProbeReadsTheLabelsAndTheRangeToOpenWith()
    {
        Week();
        Fill(store => new EvidenceSettings(store).Set("attacks.default_range", "\"30d\"", "test", "a month"));

        var status = Store().Probe(Now);

        Assert.Equal("30d", status.DefaultRange);
        Assert.Equal("My office", status.Labels.For("198.51.100.7"));
    }

    [Fact]
    public void WithoutElevationAMissingStoreIsCouldNotLook()
    {
        var refusal = Assert.ThrowsAny<Exception>(() => Store(elevated: false).Probe(Now));

        Assert.Contains("not elevated", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheLiveBoardShowsAndSearchesLabelsToo()
    {
        var labels = AddressLabels.From(JsonNode.Parse("""{"203.0.113.0/24":"Scanner network"}"""));
        var board = new AttackBoard();
        board.Reset([new AuthFailure(Now.AddMinutes(-5), AttemptPairing.SecurityChannel, IPAddress.Parse("203.0.113.9"), null, "admin",
            "bad-password", 10, 1)], Now.AddHours(-24));

        var view = board.View(Now, AttackRange.Day, "scanner", labels: labels);

        Assert.Equal("Scanner network", Assert.Single(view.Rows).Label);
        Assert.Equal("Scanner network", board.Detail("203.0.113.9", Now, AttackRange.Day, labels)!.Source.Label);
        Assert.Equal("", board.View(Now, AttackRange.Day, "").Rows[0].Label);
    }

    // =============================================================================================
    //  Decisions (ADR 0009): a mark per source and a source's list. Monitor only.
    // =============================================================================================

    private static DecisionRecord Decision(double minutesAgo, string action, string target, double? lastsMinutes = 60,
        string rule = DecisionRules.RepeatedFailures) =>
        new(Now.AddMinutes(-minutesAgo), action, target, rule, DecisionActions.MonitorMode, "10 failed logons in 4 minutes (threshold 10 in 10 minutes)",
            AttemptPairing.SecurityChannel, lastsMinutes is null ? null : Now.AddMinutes(-minutesAgo + lastsMinutes.Value));

    private void Decided(params DecisionRecord[] decisions)
    {
        Week();
        Fill(store =>
        {
            var writer = new EvidenceWriter(store);
            writer.BeginCoverage(EvidenceWriter.RawSource, Now.AddMinutes(-1), Now);
            writer.RecordEngineStart(Now.AddHours(-2));
            foreach (var decision in decisions) writer.RecordDecision(decision);
        });
    }

    [Fact]
    public void TheProbeReadsTheDecisionsInForceAndTheViewMarksThem()
    {
        Decided(Decision(30, DecisionActions.WouldBlock, "203.0.113.0/24", rule: DecisionRules.Network),
            Decision(20, DecisionActions.Protected, "198.51.100.7"),
            Decision(10, DecisionActions.Report, "203.0.113.11", lastsMinutes: null, rule: DecisionRules.SharedAccount));

        var status = Store().Probe(Now);
        var view = AttackDecisions.Apply(StoredAttackBoard.View(Store().Read(AttackRange.Week, Now), ""), status.Decisions, spanish: false, Now);

        Assert.Equal(2, status.Decisions.Decisions.Count);
        // The network decision covers both of its addresses; a report is never "in force".
        Assert.Equal("would block", view.Rows.Single(r => r.Address == "203.0.113.10").Decision);
        Assert.Equal("would block", view.Rows.Single(r => r.Address == "203.0.113.11").Decision);
        Assert.Equal("protected", view.Rows.Single(r => r.Address == "198.51.100.7").Decision);
    }

    [Fact]
    public void AStoreNobodyCouldReadMarksADashAndNothingInForceMarksNothing()
    {
        Decided(Decision(30, DecisionActions.WouldBlock, "198.51.100.7"));
        var active = Store().Probe(Now).Decisions;

        Assert.Equal(StoredAttackBoard.NotAsked, AttackDecisions.Mark(null, "203.0.113.10", spanish: false, Now));
        Assert.Equal("", AttackDecisions.Mark(active, "203.0.113.10", spanish: false, Now));
        Assert.Equal("bloquearía", AttackDecisions.Mark(active, "198.51.100.7", spanish: true, Now));
    }

    [Fact]
    public void TheFooterSaysWhyNothingIsInForce()
    {
        Week();
        var never = Store().Probe(Now).Decisions;
        Fill(store => new EvidenceWriter(store).RecordEngineStart(Now.AddDays(-1)));
        // The week's coverage ends a minute before Now: recording. An hour later, it is not.
        var stopped = Store().Probe(Now.AddHours(1)).Decisions;

        Assert.Contains("never run", AttackDecisions.Status(never, spanish: false, Now), StringComparison.Ordinal);
        Assert.Contains("was not recording at 13:00 UTC", AttackDecisions.Status(stopped, spanish: false, Now.AddHours(1)), StringComparison.Ordinal);
        Assert.Contains("no estaba registrando", AttackDecisions.Status(stopped, spanish: true, Now.AddHours(1)), StringComparison.Ordinal);
        Assert.Contains("not read", AttackDecisions.Status(null, spanish: false, Now), StringComparison.Ordinal);
        Assert.Contains("decisions in force: 0, read at 12:00 UTC (Monitor: nothing is blocked)",
            AttackDecisions.Status(Store().Probe(Now).Decisions, spanish: false, Now), StringComparison.Ordinal);
    }

    /// <summary>The decisions are read once per load and the rows update live: an expiry passed since is drawn as passed.</summary>
    [Fact]
    public void ADecisionThatExpiredSinceItWasReadIsNoLongerMarked()
    {
        Decided(Decision(50, DecisionActions.WouldBlock, "198.51.100.7"));
        var read = Store().Probe(Now).Decisions;

        Assert.Equal("would block", AttackDecisions.Mark(read, "198.51.100.7", spanish: false, Now));
        Assert.Equal("", AttackDecisions.Mark(read, "198.51.100.7", spanish: false, Now.AddMinutes(11)));
        Assert.Contains("decisions in force: 0, read at 12:00 UTC", AttackDecisions.Status(read, spanish: false, Now.AddMinutes(11)), StringComparison.Ordinal);
    }
    [Fact]
    public void ASourcesDecisionsIncludeItsNetworksAndSayWouldNeverBlocked()
    {
        Decided(Decision(30, DecisionActions.WouldBlock, "203.0.113.0/24", rule: DecisionRules.Network),
            Decision(20, DecisionActions.WouldBlock, "203.0.113.10"),
            Decision(10, DecisionActions.Expire, "203.0.113.10", lastsMinutes: null),
            Decision(5, DecisionActions.WouldBlock, "198.51.100.7"));

        var rows = Store().Decisions("203.0.113.10", Now.AddDays(-30), Now.AddMinutes(1));
        var lines = rows.Select(d => AttackDecisions.Line(d, spanish: false)).ToArray();

        Assert.Equal(3, rows.Count);
        Assert.StartsWith("2026-11-24 11:50  ended  ·  HOST-AUTH-001  ·  203.0.113.10", lines[0], StringComparison.Ordinal);
        Assert.StartsWith("2026-11-24 11:30  would block until 2026-11-24 12:30  ·  HOST-AUTH-003  ·  203.0.113.0/24", lines[2], StringComparison.Ordinal);
        Assert.All(lines, l => Assert.DoesNotContain("blocked", l, StringComparison.Ordinal));
        Assert.Contains("hasta", AttackDecisions.Line(rows[1], spanish: true), StringComparison.Ordinal);
    }
    [Theory]
    [InlineData(1, "12:00–12:01 UTC")]
    [InlineData(60, "2026-11-24 12:00–13:00 UTC")]
    [InlineData(1440, "2026-11-24 UTC")]
    public void ABucketNamesItsDateOnceItSpansHours(int minutes, string expected)
    {
        var bucket = new AttackBucket(Now, Now.AddMinutes(minutes), 0, 1, true);

        Assert.Equal(expected, AttacksWindow.BucketTime(bucket));
    }

    [Theory]
    [InlineData(0, "1h")]
    [InlineData(1, "6h")]
    [InlineData(2, "24h")]
    [InlineData(3, "7d")]
    [InlineData(4, "30d")]
    public void RangeNamesMatchTheSettingAndTheCli(int value, string name)
    {
        var range = (AttackRange)value;
        Assert.Equal(name, StoredAttackBoard.Name(range));
        Assert.Equal(range, StoredAttackBoard.Parse(name));
    }
}
