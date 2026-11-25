using System.Text.Json;
using WPShield.Cli;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Cli.Tests;

/// <summary>
/// <c>wpshield decisions</c> reads the audit trail the decision engine writes and says what it rests
/// on: Monitor only, the coverage it was made under, and - for what is in force - the engine run and
/// whether the collector is still recording. Synthetic RFC 5737 and RFC 3849 addresses only.
/// </summary>
public sealed class DecisionsCommandTests : IDisposable
{
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly EvidenceTestStore store = new();

    public void Dispose() => store.Dispose();

    private (int Exit, string Output, string Error) Run(bool elevated, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = DecisionsCommand.Run(CliOptions.Parse(args), output, error, store.Path, () => elevated, () => Now);
        return (exit, output.ToString(), error.ToString());
    }

    private (int Exit, string Output, string Error) Run(params string[] args) => Run(true, args);

    private static DecisionRecord Decision(double minutesAgo, string action, string target, string rule = DecisionRules.RepeatedFailures,
        double? lastsMinutes = 60, string reason = "10 failed logons in 4 minutes (threshold 10 in 10 minutes)") =>
        new(Now.AddMinutes(-minutesAgo), action, target, rule, DecisionActions.MonitorMode, reason, AttemptPairing.SecurityChannel,
            lastsMinutes is null ? null : Now.AddMinutes(-minutesAgo + lastsMinutes.Value));

    private EvidenceTestStore Recorded(params DecisionRecord[] decisions) => store
        .Covered(Now.AddDays(-2), Now)
        .Write(s =>
        {
            var writer = new EvidenceWriter(s);
            writer.RecordEngineStart(Now.AddHours(-3));
            foreach (var decision in decisions) writer.RecordDecision(decision);
        });

    private EvidenceTestStore Typical() => Recorded(
        Decision(240, DecisionActions.WouldBlock, "192.0.2.44", lastsMinutes: 600),
        Decision(50, DecisionActions.WouldBlock, "203.0.113.7"),
        Decision(40, DecisionActions.Protected, "198.51.100.7", reason: "10 failed logons in 2 minutes (threshold 10 in 10 minutes); protected: on the allow-list (198.51.100.7)"),
        Decision(30, DecisionActions.WouldBlock, "203.0.113.0/24", DecisionRules.Network),
        Decision(25, DecisionActions.Report, "2001:db8::a", DecisionRules.SharedAccount, lastsMinutes: null),
        Decision(20, DecisionActions.Refused, "203.0.113.9", lastsMinutes: null,
            reason: "10 failed logons in 1 minute (threshold 10 in 10 minutes); refused: the Remote Desktop connections could not be read (access-denied)"),
        Decision(10, DecisionActions.WouldBlock, "2001:db8:1:2::/64", DecisionRules.Network),
        Decision(5, DecisionActions.Expire, "2001:db8:1:2::/64", DecisionRules.Network, lastsMinutes: null,
            reason: "ended with the process that made it; a decision never outlives it"));

    [Fact]
    public void ElevatedWithNoStore_SaysThereIsNoStore()
    {
        var (exit, output, error) = Run();

        Assert.Equal(3, exit);
        Assert.Empty(output);
        Assert.Contains("no evidence store", error, StringComparison.Ordinal);
    }

    [Fact]
    public void NotElevated_SaysItCouldNotLook()
    {
        var (exit, _, error) = Run(elevated: false, "--active");

        Assert.Equal(1, exit);
        Assert.Contains("not elevated", error, StringComparison.Ordinal);
    }

    [Fact]
    public void ARangeNobodyRecorded_IsNoDataNotNoDecisions()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run();
        var json = Run("--json");

        Assert.Equal(2, exit);
        Assert.Contains("Decisions        no data", output, StringComparison.Ordinal);
        Assert.DoesNotContain("No decision was made", output, StringComparison.Ordinal);
        Assert.Equal(2, json.Exit);
        using var document = JsonDocument.Parse(json.Output);
        Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("decisions").ValueKind);
        Assert.Equal("none", document.RootElement.GetProperty("coverage").GetProperty("state").GetString());
    }

    [Fact]
    public void ARecordedRangeWithoutDecisions_SaysNoneWereMade()
    {
        store.Covered(Now.AddDays(-2), Now);

        var (exit, output, _) = Run();

        Assert.Equal(0, exit);
        Assert.Contains("No decision was made in this range.", output, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRange_ListsEveryActionNewestFirstAndSaysItIsMonitor()
    {
        Typical();

        var (exit, output, error) = Run("--range", "24h");

        Assert.Equal(0, exit);
        Assert.Empty(error);
        Assert.Contains("Mode             monitor - nothing is blocked", output, StringComparison.Ordinal);
        Assert.Contains("Decisions        8  (would-block 4, protected 1, refused 1, report 1, expire 1)", output, StringComparison.Ordinal);
        var lines = output.Split(Environment.NewLine);
        var first = Array.FindIndex(lines, l => l.StartsWith("TIME (UTC)", StringComparison.Ordinal));
        Assert.StartsWith("2026-11-24 11:55  expire", lines[first + 1], StringComparison.Ordinal);
        var network = Assert.Single(lines, l => l.Contains("203.0.113.0/24", StringComparison.Ordinal));
        Assert.Contains("HOST-AUTH-003", network, StringComparison.Ordinal);
        Assert.Contains("2026-11-24 12:30", network, StringComparison.Ordinal);
        Assert.Contains("refused: the Remote Desktop connections could not be read", output, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRange_InJson()
    {
        Typical();

        var (exit, output, _) = Run("--range", "6h", "--json");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        var root = json.RootElement;
        Assert.Equal("monitor", root.GetProperty("mode").GetString());
        Assert.Equal(4, root.GetProperty("counts").GetProperty("wouldBlock").GetInt32());
        var decisions = root.GetProperty("decisions");
        Assert.Equal(8, decisions.GetArrayLength());
        Assert.Equal("expire", decisions[0].GetProperty("action").GetString());
        Assert.Equal(JsonValueKind.Null, decisions[0].GetProperty("expires").ValueKind);
        Assert.Equal("security-4625", decisions[1].GetProperty("requestedBy").GetString());
        Assert.False(root.GetProperty("truncated").GetBoolean());
    }

    /// <summary>A network decision covers the address too, so asking about the address shows both.</summary>
    [Fact]
    public void AnAddressTarget_IncludesItsNetworksDecisions()
    {
        Typical();

        var (exit, output, _) = Run("--target", "203.0.113.7");

        Assert.Equal(0, exit);
        Assert.Contains("Target           203.0.113.7 and its network 203.0.113.0/24", output, StringComparison.Ordinal);
        Assert.Contains("Decisions        2  (would-block 2", output, StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.7", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ANetworkTarget_MatchesExactly()
    {
        Typical();

        var (_, output, _) = Run("--target", "203.0.113.0/24", "--json");

        using var json = JsonDocument.Parse(output);
        Assert.Equal("203.0.113.0/24", json.RootElement.GetProperty("decisions")[0].GetProperty("target").GetString());
        Assert.Equal(1, json.RootElement.GetProperty("decisions").GetArrayLength());
    }

    [Fact]
    public void AnIPv4MappedTarget_IsTheIPv4Address()
    {
        Typical();

        Assert.Contains("Target           203.0.113.7 and", Run("--target", "::ffff:203.0.113.7").Output, StringComparison.Ordinal);
    }

    // =============================================================================================
    //  What is in force.
    // =============================================================================================

    [Fact]
    public void Active_ShowsTheUnexpiredDecisionsOfThisEngineRun()
    {
        Typical();

        var (exit, output, _) = Run("--active");

        Assert.Equal(0, exit);
        Assert.Contains("Engine           started 2026-11-24 09:00 UTC", output, StringComparison.Ordinal);
        Assert.Contains("Collector        recording", output, StringComparison.Ordinal);
        Assert.Contains("In force now     3  (would-block 2, protected 1)", output, StringComparison.Ordinal);
        var lines = output.Split(Environment.NewLine);
        Assert.Single(lines, l => l.StartsWith("203.0.113.7 ", StringComparison.Ordinal));
        Assert.Single(lines, l => l.StartsWith("203.0.113.0/24 ", StringComparison.Ordinal));
        Assert.Single(lines, l => l.StartsWith("198.51.100.7 ", StringComparison.Ordinal));
        // Made before this engine run started: a restart ended it, whatever its expiry says.
        Assert.DoesNotContain("192.0.2.44", output, StringComparison.Ordinal);
        // Ended with the process that made it.
        Assert.DoesNotContain("2001:db8:1:2::/64", output, StringComparison.Ordinal);
        // Never in force.
        Assert.DoesNotContain("2001:db8::a", output, StringComparison.Ordinal);
        Assert.DoesNotContain("203.0.113.9", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Active_ForAnAddressFindsItsNetworksDecision()
    {
        Recorded(Decision(30, DecisionActions.WouldBlock, "203.0.113.0/24", DecisionRules.Network));

        var (_, output, _) = Run("--active", "--target", "203.0.113.200", "--json");

        using var json = JsonDocument.Parse(output);
        Assert.Equal("203.0.113.0/24", Assert.Single(json.RootElement.GetProperty("active").EnumerateArray()).GetProperty("target").GetString());
        Assert.True(json.RootElement.GetProperty("collectorCurrent").GetBoolean());
    }

    /// <summary>A service that is not running has nothing in force, whatever the expiries in the trail say.</summary>
    [Fact]
    public void Active_WhenTheCollectorStoppedRecordingNothingIsInForce()
    {
        store.Covered(Now.AddDays(-2), Now.AddMinutes(-30)).Write(s =>
        {
            var writer = new EvidenceWriter(s);
            writer.RecordEngineStart(Now.AddHours(-3));
            writer.RecordDecision(Decision(40, DecisionActions.WouldBlock, "203.0.113.7"));
        });

        var (exit, output, _) = Run("--active");

        Assert.Equal(0, exit);
        Assert.Contains("Collector        not recording since 2026-11-24 11:30 UTC", output, StringComparison.Ordinal);
        Assert.Contains("No decision is in force: the collector has not recorded since 2026-11-24 11:30 UTC", output, StringComparison.Ordinal);
        Assert.DoesNotContain("203.0.113.7  ", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Active_WhenTheEngineNeverRanSaysSo()
    {
        store.Covered(Now.AddDays(-2), Now);

        var (exit, output, _) = Run("--active", "--json");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("engineStarted").ValueKind);
        Assert.Contains("never run", json.RootElement.GetProperty("note").GetString(), StringComparison.Ordinal);
        Assert.Equal(0, json.RootElement.GetProperty("active").GetArrayLength());
    }

    // =============================================================================================
    //  Text and arguments.
    // =============================================================================================

    [Fact]
    public void StoredTextIsCleanedForTheTerminalAndEscapedInJson()
    {
        Recorded(Decision(5, DecisionActions.WouldBlock, "203.0.113.7", reason: "x\u001b[31m‮ y"));

        var text = Run().Output;
        var json = Run("--json").Output;

        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('‮', text);
        Assert.DoesNotContain('\u001b', json);
        Assert.DoesNotContain('‮', json);
    }

    [Fact]
    public void MoreThanTheShownBoundSaysSo()
    {
        Recorded(Enumerable.Range(0, DecisionsCommand.Shown + 5)
            .Select(i => Decision(i * 0.1, DecisionActions.WouldBlock, $"2001:db8::{i:x}")).ToArray());

        var (exit, output, _) = Run();

        Assert.Equal(0, exit);
        Assert.Contains("Decisions        200+", output, StringComparison.Ordinal);
        Assert.Contains("Showing the newest 200", output, StringComparison.Ordinal);
        Assert.True(JsonDocument.Parse(Run("--json").Output).RootElement.GetProperty("truncated").GetBoolean());
    }

    [Theory]
    [InlineData("--range", "2d")]
    [InlineData("--target", "not-an-address")]
    [InlineData("--target", "203.0.113.7/24")]
    [InlineData("--json", "yes")]
    [InlineData("--active", "yes")]
    [InlineData("--store", "")]
    [InlineData("--top", "5")]
    public void ArgumentsTheCommandDoesNotUnderstand_AreRefused(string name, string value)
    {
        Typical();

        Assert.Throws<CliArgumentException>(() => Run(name, value));
    }

    [Fact]
    public void ActiveTakesNoRange()
    {
        Typical();

        var refused = Assert.Throws<CliArgumentException>(() => Run("--active", "--range", "7d"));

        Assert.Contains("takes no --range", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheHelpSaysMonitorAndNamesEveryAction()
    {
        Assert.Contains("MONITOR ONLY. Nothing is blocked.", DecisionsCommand.Help, StringComparison.Ordinal);
        foreach (var action in new[] { DecisionActions.WouldBlock, DecisionActions.Protected, DecisionActions.Refused, DecisionActions.Report, DecisionActions.Expire })
            Assert.Contains("  " + action + " ", DecisionsCommand.Help, StringComparison.Ordinal);
    }
}
