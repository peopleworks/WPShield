using System.Net;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// The decision engine of ADR 0009, driven by hand: synthetic RFC 5737 and RFC 3849 addresses, a clock
/// passed in, and the host's facts faked. Every rule is tested at, below and above its threshold.
/// </summary>
public sealed class DecisionEngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly IPAddress HostAddress = IPAddress.Parse("192.0.2.250");
    private readonly List<IPAddress> rdpClients = [];
    private string? rdpProblem;
    private IReadOnlyCollection<IPAddress>? hostAddresses = [HostAddress];
    private int rdpReads;
    private long record;

    private DecisionEngine Engine(DecisionEngineLimits? limits = null) => new(new AddressProtection(() => hostAddresses, () =>
    {
        rdpReads++;
        return rdpProblem is null ? RemoteDesktopSnapshot.Of(rdpClients) : RemoteDesktopSnapshot.Unreadable(rdpProblem);
    }), limits);

    private AuthFailure Failure(double seconds, string? ip, string account = "admin", string reason = "bad-password",
        string channel = AttemptPairing.SecurityChannel) =>
        new(Now.AddSeconds(seconds), channel, ip is null ? null : IPAddress.Parse(ip), null, account, reason, 10, ++record);

    private IEnumerable<AuthFailure> Repeated(string ip, int count, double from = 0, double every = 10, string reason = "bad-password") =>
        Enumerable.Range(0, count).Select(i => Failure(from + i * every, ip, reason: reason)).ToArray();

    private static IReadOnlyList<DecisionRecord> Observe(DecisionEngine engine, IEnumerable<AuthFailure> failures,
        DefenseOptions? options = null, double at = 600) =>
        engine.Observe(failures, options ?? DefenseOptions.Default, Now.AddSeconds(at));

    // =============================================================================================
    //  HOST-AUTH-001: one address, N failures within W.
    // =============================================================================================

    [Fact]
    public void RepeatedFailures_BelowTheThresholdDecideNothing()
    {
        Assert.Empty(Observe(Engine(), Repeated("203.0.113.7", 9)));
    }

    [Fact]
    public void RepeatedFailures_AtTheThresholdWouldBlockTheAddressForItsDuration()
    {
        var decision = Assert.Single(Observe(Engine(), Repeated("203.0.113.7", 10)));

        Assert.Equal(DecisionActions.WouldBlock, decision.Action);
        Assert.Equal("203.0.113.7", decision.Target);
        Assert.Equal(DecisionRules.RepeatedFailures, decision.RuleId);
        Assert.Equal("monitor", decision.Mode);
        Assert.Equal(AttemptPairing.SecurityChannel, decision.RequestedBy);
        Assert.Equal(Now.AddSeconds(600), decision.Timestamp);
        Assert.Equal(Now.AddSeconds(600).AddMinutes(60), decision.ExpiresAt);
        Assert.Equal("10 failed logons in 1 minute (threshold 10 in 10 minutes)", decision.Reason);
    }

    /// <summary>Monitor does not stop the attempts. One record per decision, not one per attempt after it.</summary>
    [Fact]
    public void RepeatedFailures_AboveTheThresholdStillDecideOnce()
    {
        var engine = Engine();

        Assert.Single(Observe(engine, Repeated("203.0.113.7", 30)));
        Assert.Empty(Observe(engine, Repeated("203.0.113.7", 30, from: 400)));
        Assert.Equal(1, engine.ActiveCount);
    }

    [Fact]
    public void RepeatedFailures_SpreadWiderThanTheWindowDecideNothing()
    {
        // Ten failures, one every two minutes: never ten within ten minutes.
        Assert.Empty(Observe(Engine(), Repeated("203.0.113.7", 10, every: 120), at: 1200));
    }

    [Fact]
    public void RecordsWithoutAnAddressCountButDecideNothing()
    {
        var engine = Engine();

        Assert.Empty(Observe(engine, Enumerable.Range(0, 50).Select(i => Failure(i, null))));
        Assert.Equal(50, engine.Observed);
        Assert.Equal(0, engine.TrackedAddresses);
    }

    [Fact]
    public void AnIPv4MappedAddressIsTheIPv4AddressItIs()
    {
        var engine = Engine();
        Observe(engine, Repeated("203.0.113.7", 5));

        var decision = Assert.Single(Observe(engine, Repeated("::ffff:203.0.113.7", 5, from: 60)));

        Assert.Equal("203.0.113.7", decision.Target);
    }

    // =============================================================================================
    //  HOST-AUTH-002: one address, M nonexistent account names within W.
    // =============================================================================================

    private IEnumerable<AuthFailure> Guessing(string ip, params string[] names) =>
        names.Select((name, i) => Failure(i * 10, ip, name, "unknown-account")).ToArray();

    [Fact]
    public void NonexistentAccounts_BelowTheThresholdDecideNothing()
    {
        Assert.Empty(Observe(Engine(), Guessing("198.51.100.9", "sa", "test", "backup")));
    }

    [Fact]
    public void NonexistentAccounts_AtTheThresholdWouldBlockForSixHours()
    {
        var decision = Assert.Single(Observe(Engine(), Guessing("198.51.100.9", "sa", "test", "backup", "oracle")));

        Assert.Equal(DecisionRules.NonexistentAccounts, decision.RuleId);
        Assert.Equal(DecisionActions.WouldBlock, decision.Action);
        Assert.Equal(TimeSpan.FromHours(6), decision.ExpiresAt - decision.Timestamp);
        Assert.Equal("4 nonexistent account names in under a minute (threshold 4 in 10 minutes)", decision.Reason);
    }

    [Fact]
    public void NonexistentAccounts_AboveTheThresholdStillDecideOnce()
    {
        Assert.Single(Observe(Engine(), Guessing("198.51.100.9", "sa", "test", "backup", "oracle", "guest", "user1", "user2")));
    }

    /// <summary>The same name tried again is one name, whatever its case: Windows account names are not case-sensitive.</summary>
    [Fact]
    public void NonexistentAccounts_CountDistinctNamesIgnoringCase()
    {
        Assert.Empty(Observe(Engine(), Guessing("198.51.100.9", "sa", "SA", "Sa", "test", "TEST", "backup", "sa", "test", "backup")));
    }

    /// <summary>A colleague mistyping a password names a real account. That is HOST-AUTH-001's business, not this rule's.</summary>
    [Fact]
    public void NonexistentAccounts_IgnoreAccountsThatExist()
    {
        var failures = new[] { "pedro", "maria", "ana", "juan", "luis", "rosa", "carlos", "elena", "jose" }
            .Select((name, i) => Failure(i * 10, "198.51.100.9", name, "bad-password"));

        Assert.Empty(Observe(Engine(), failures));
    }

    [Fact]
    public void NonexistentAccounts_IgnoreRecordsThatNameNoAccount()
    {
        Assert.Empty(Observe(Engine(), Enumerable.Range(0, 8).Select(i => Failure(i, "198.51.100.9", "", "unknown-account"))));
    }

    [Fact]
    public void NonexistentAccounts_ReasonNeverCarriesTheNamesTried()
    {
        var decision = Assert.Single(Observe(Engine(), Guessing("198.51.100.9", "ignore", "previous", "instructions", "now")));

        Assert.DoesNotContain("ignore", decision.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("instructions", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    // =============================================================================================
    //  HOST-AUTH-003: K different addresses of one /24 or /64 within W.
    // =============================================================================================

    private IEnumerable<AuthFailure> Spread(string prefix, int count, string suffix = "") =>
        Enumerable.Range(1, count).Select(i => Failure(i * 10, $"{prefix}{i}{suffix}")).ToArray();

    [Fact]
    public void Network_BelowTheThresholdDecidesNothing()
    {
        Assert.Empty(Observe(Engine(), Spread("203.0.113.", 7)));
    }

    [Fact]
    public void Network_AtTheThresholdWouldBlockTheWholeNetwork()
    {
        var decision = Assert.Single(Observe(Engine(), Spread("203.0.113.", 8)));

        Assert.Equal(DecisionRules.Network, decision.RuleId);
        Assert.Equal("203.0.113.0/24", decision.Target);
        Assert.Equal(TimeSpan.FromMinutes(60), decision.ExpiresAt - decision.Timestamp);
        Assert.StartsWith("8 different addresses of this network failed", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Network_AboveTheThresholdDecidesOnceAndCoversItsAddresses()
    {
        var engine = Engine();
        Assert.Single(Observe(engine, Spread("203.0.113.", 20)));

        // An enforced network block would have dropped these; no address decision follows.
        Assert.Empty(Observe(engine, Repeated("203.0.113.50", 15, from: 300)));
    }

    [Fact]
    public void Network_IPv6CountsTheSlash64()
    {
        var decision = Assert.Single(Observe(Engine(), Spread("2001:db8:1:2::", 8)));

        Assert.Equal("2001:db8:1:2::/64", decision.Target);
    }

    [Fact]
    public void Network_AddressesOfDifferentNetworksDoNotAddUp()
    {
        // One address in each of twelve /64s, each trying its own account so HOST-AUTH-004 stays out of it.
        var failures = Enumerable.Range(1, 12).Select(i => Failure(i * 10, $"2001:db8:{i:x}::7", $"user{i}"));

        Assert.Empty(Observe(Engine(), failures));
    }

    [Fact]
    public void Network_TheSameAddressRepeatedIsOneAddress()
    {
        var failures = Enumerable.Range(0, 9).Select(i => Failure(i, "203.0.113.5"))
            .Concat(Spread("203.0.113.", 6, suffix: "0"));

        var decisions = Observe(Engine(), failures);

        Assert.DoesNotContain(decisions, d => d.RuleId == DecisionRules.Network);
    }

    // =============================================================================================
    //  HOST-AUTH-004: one existing account from A different addresses. Report only.
    // =============================================================================================

    /// <summary>One address per /64 so that HOST-AUTH-003 stays out of it.</summary>
    private IEnumerable<AuthFailure> OneAccountFrom(int addresses, string account = "administrador", string reason = "bad-password") =>
        Enumerable.Range(1, addresses).Select(i => Failure(i * 10, $"2001:db8:0:{i:x}::1", account, reason)).ToArray();

    [Fact]
    public void SharedAccount_BelowTheThresholdReportsNothing()
    {
        Assert.Empty(Observe(Engine(), OneAccountFrom(9)));
    }

    [Fact]
    public void SharedAccount_AtTheThresholdReportsAndNeverBlocks()
    {
        var engine = Engine();

        var report = Assert.Single(Observe(engine, OneAccountFrom(10)));

        Assert.Equal(DecisionActions.Report, report.Action);
        Assert.Equal(DecisionRules.SharedAccount, report.RuleId);
        Assert.Equal("2001:db8:0:a::1", report.Target);
        Assert.Null(report.ExpiresAt);
        Assert.Equal(0, engine.ActiveCount);
        Assert.Contains("10 different addresses", report.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("administrador", report.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("administrador", report.Target, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SharedAccount_AboveTheThresholdReportsOncePerWindow()
    {
        var engine = Engine();

        Assert.Single(Observe(engine, OneAccountFrom(25)));
    }

    [Fact]
    public void SharedAccount_CountsTheAccountIgnoringCase()
    {
        var failures = OneAccountFrom(5, "Administrador").Concat(
            Enumerable.Range(6, 5).Select(i => Failure(i * 10, $"2001:db8:0:{i:x}::1", "ADMINISTRADOR")));

        Assert.Single(Observe(Engine(), failures), d => d.RuleId == DecisionRules.SharedAccount);
    }

    [Theory]
    [InlineData("unknown-account")]
    [InlineData("bad-credentials")]
    [InlineData("other")]
    public void SharedAccount_CountsOnlyReasonsThatProveTheAccountExists(string reason)
    {
        Assert.DoesNotContain(Observe(Engine(), OneAccountFrom(12, reason: reason)), d => d.RuleId == DecisionRules.SharedAccount);
    }

    // =============================================================================================
    //  Repeat offenders.
    // =============================================================================================

    [Fact]
    public void ARepeatWithinSevenDaysDoublesTheDurationUpToSevenDays()
    {
        var engine = Engine();
        var at = Now;
        var durations = new List<TimeSpan>();
        for (var round = 0; round < 10; round++)
        {
            var failures = Enumerable.Range(0, 10).Select(i => new AuthFailure(at.AddSeconds(i), AttemptPairing.SecurityChannel,
                IPAddress.Parse("203.0.113.7"), null, "admin", "bad-password", 10, ++record));
            var decision = Assert.Single(engine.Observe(failures, DefenseOptions.Default, at.AddSeconds(10)));
            durations.Add(decision.ExpiresAt!.Value - decision.Timestamp);
            at = decision.ExpiresAt.Value;
            Assert.Single(engine.Expire(at));
        }

        Assert.Equal(new[] { 60, 120, 240, 480, 960, 1920, 3840, 7680, 10080, 10080 }, durations.Select(d => (int)d.TotalMinutes));
    }

    [Fact]
    public void AnEscalatedDecisionSaysSo()
    {
        var engine = Engine();
        Observe(engine, Repeated("203.0.113.7", 10));
        engine.Expire(Now.AddHours(2));

        var again = Assert.Single(engine.Observe(Repeated("203.0.113.7", 10, from: 7300), DefenseOptions.Default, Now.AddSeconds(7400)));

        Assert.Contains("a repeat within 7 days: 2 hours, twice the previous 60 minutes", again.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void ARepeatAfterSevenDaysStartsAgainFromTheRulesDuration()
    {
        var engine = Engine();
        Observe(engine, Repeated("203.0.113.7", 10));
        var later = Now.AddDays(8);
        engine.Expire(later);

        var failures = Enumerable.Range(0, 10).Select(i => new AuthFailure(later.AddSeconds(i), AttemptPairing.SecurityChannel,
            IPAddress.Parse("203.0.113.7"), null, "admin", "bad-password", 10, ++record));
        var decision = Assert.Single(engine.Observe(failures, DefenseOptions.Default, later.AddSeconds(10)));

        Assert.Equal(TimeSpan.FromMinutes(60), decision.ExpiresAt - decision.Timestamp);
    }

    [Fact]
    public void AProtectedOutcomeIsNotAPreviousDecision()
    {
        var engine = Engine();
        rdpClients.Add(IPAddress.Parse("203.0.113.7"));
        Assert.Equal(DecisionActions.Protected, Assert.Single(Observe(engine, Repeated("203.0.113.7", 10))).Action);
        rdpClients.Clear();
        engine.Expire(Now.AddHours(2));

        var decision = Assert.Single(engine.Observe(Repeated("203.0.113.7", 10, from: 7300), DefenseOptions.Default, Now.AddSeconds(7400)));

        Assert.Equal(DecisionActions.WouldBlock, decision.Action);
        Assert.Equal(TimeSpan.FromMinutes(60), decision.ExpiresAt - decision.Timestamp);
    }

    // =============================================================================================
    //  Addresses the engine never decides against.
    // =============================================================================================

    private DecisionRecord Decide(string ip, DefenseOptions? options = null) =>
        Assert.Single(Observe(Engine(), Repeated(ip, 10), options));

    [Theory]
    [InlineData("198.51.100.7", "198.51.100.7")]
    [InlineData("198.51.100.7", "198.51.100.0/24")]
    [InlineData("2001:db8:5::17", "2001:db8:5::/48")]
    public void TheAllowListIsProtected(string ip, string entry)
    {
        AddressRanges.TryParseCanonical(entry, out var network);

        var decision = Decide(ip, DefenseOptions.Default with { Allow = [network] });

        Assert.Equal(DecisionActions.Protected, decision.Action);
        Assert.Contains($"protected: on the allow-list ({entry})", decision.Reason, StringComparison.Ordinal);
        Assert.Equal(TimeSpan.FromMinutes(60), decision.ExpiresAt - decision.Timestamp);
    }

    [Fact]
    public void TheHostsOwnAddressIsProtected()
    {
        var decision = Decide(HostAddress.ToString());

        Assert.Equal(DecisionActions.Protected, decision.Action);
        Assert.EndsWith("protected: an address of this host", decision.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("127.0.0.1", "loopback")]
    [InlineData("::1", "loopback")]
    [InlineData("169.254.10.20", "link-local")]
    [InlineData("fe80::1234", "link-local")]
    [InlineData("0.0.0.0", "unspecified")]
    [InlineData("::", "unspecified")]
    public void LoopbackLinkLocalAndUnspecifiedAreProtected(string ip, string kind)
    {
        var decision = Decide(ip);

        Assert.Equal(DecisionActions.Protected, decision.Action);
        Assert.Contains(kind, decision.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("10.20.30.40", "10.0.0.0/8")]
    [InlineData("172.20.1.2", "172.16.0.0/12")]
    [InlineData("192.168.1.20", "192.168.0.0/16")]
    [InlineData("100.64.7.8", "100.64.0.0/10")]
    [InlineData("fd12:3456::7", "fc00::/7")]
    public void PrivateRangesAreProtectedUnlessIncluded(string ip, string range)
    {
        var decision = Decide(ip);
        Assert.Equal(DecisionActions.Protected, decision.Action);
        Assert.Contains($"in the private range {range} (defense.include_private is false)", decision.Reason, StringComparison.Ordinal);

        Assert.Equal(DecisionActions.WouldBlock, Decide(ip, DefenseOptions.Default with { IncludePrivate = true }).Action);
    }

    [Fact]
    public void AnAddressHoldingARemoteDesktopSessionIsProtected()
    {
        rdpClients.Add(IPAddress.Parse("203.0.113.7"));

        var decision = Decide("203.0.113.7");

        Assert.Equal(DecisionActions.Protected, decision.Action);
        Assert.EndsWith("protected: holds a Remote Desktop session", decision.Reason, StringComparison.Ordinal);
    }

    /// <summary>"Nobody could look" is not "nobody is connected": unreadable connections refuse the decision.</summary>
    [Fact]
    public void AnUnreadableRemoteDesktopTableRefusesTheDecision()
    {
        rdpProblem = "access-denied";

        var decision = Decide("203.0.113.7");

        Assert.Equal(DecisionActions.Refused, decision.Action);
        Assert.Null(decision.ExpiresAt);
        Assert.Contains("refused: the Remote Desktop connections could not be read (access-denied)", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void UnreadableHostAddressesRefuseTheDecision()
    {
        hostAddresses = null;

        var decision = Decide("203.0.113.7");

        Assert.Equal(DecisionActions.Refused, decision.Action);
        Assert.Contains("the host's own addresses could not be read", decision.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AThrowingProbeRefusesRatherThanThrows()
    {
        var engine = new DecisionEngine(new AddressProtection(() => throw new InvalidOperationException("synthetic"),
            () => throw new InvalidOperationException("synthetic")));

        Assert.Equal(DecisionActions.Refused, Assert.Single(Observe(engine, Repeated("203.0.113.7", 10))).Action);
    }

    [Fact]
    public void ARefusalIsRecordedOncePerWindowNotPerAttempt()
    {
        rdpProblem = "query-failed";
        var engine = Engine();

        Assert.Single(Observe(engine, Repeated("203.0.113.7", 40, every: 5)));
    }

    [Fact]
    public void AProtectedAddressIsRecordedOnceWhileItsWouldBeBlockLasts()
    {
        var engine = Engine();
        rdpClients.Add(IPAddress.Parse("203.0.113.7"));

        Assert.Single(Observe(engine, Repeated("203.0.113.7", 50, every: 5)));
        Assert.Empty(Observe(engine, Repeated("203.0.113.7", 50, from: 400, every: 5)));
    }

    [Fact]
    public void ANetworkHoldingTheHostsAddressAnAllowedOneOrARemoteDesktopClientIsProtected()
    {
        Assert.Contains("contains an address of this host",
            Assert.Single(Observe(Engine(), Spread("192.0.2.", 8))).Reason, StringComparison.Ordinal);

        AddressRanges.TryParseCanonical("203.0.113.200", out var allowed);
        Assert.Contains("on the allow-list (203.0.113.200)",
            Assert.Single(Observe(Engine(), Spread("203.0.113.", 8), DefenseOptions.Default with { Allow = [allowed] })).Reason,
            StringComparison.Ordinal);

        rdpClients.Add(IPAddress.Parse("198.51.100.99"));
        var decision = Assert.Single(Observe(Engine(), Spread("198.51.100.", 8)));
        Assert.Equal(DecisionActions.Protected, decision.Action);
        Assert.Equal("198.51.100.0/24", decision.Target);
    }

    [Fact]
    public void TheRemoteDesktopTableIsReadOnlyWhenARuleFiresAndOncePerEvaluation()
    {
        var engine = Engine();
        Observe(engine, Repeated("203.0.113.7", 9));
        Assert.Equal(0, rdpReads);

        var failures = Repeated("203.0.113.7", 1, from: 100).Concat(Repeated("198.51.100.8", 10)).Concat(Repeated("192.0.2.9", 10));
        Assert.Equal(3, Observe(engine, failures).Count);
        Assert.Equal(1, rdpReads);
    }

    // =============================================================================================
    //  Bounds.
    // =============================================================================================

    [Fact]
    public void PerAddressStateEvictsTheLeastRecentlySeen()
    {
        var engine = Engine(new DecisionEngineLimits { MaxEntries = 5 });
        Observe(engine, Repeated("203.0.113.1", 9));
        Observe(engine, Enumerable.Range(2, 10).Select(i => Failure(100 + i, $"2001:db8:{i:x}::1", $"user{i}")));

        Assert.Equal(5, engine.TrackedAddresses);
        Assert.True(engine.Evicted > 0);
        // 203.0.113.1 was seen least recently and was forgotten: its tenth failure starts again from one.
        Assert.Empty(Observe(engine, Repeated("203.0.113.1", 1, from: 200)));
    }

    [Fact]
    public void TheItemsInsideTheEntriesAreBoundedToo()
    {
        var engine = Engine(new DecisionEngineLimits { MaxItems = 20 });

        Observe(engine, Enumerable.Range(1, 6).SelectMany(n => Repeated($"2001:db8:{n:x}::1", 9)));

        Assert.True(engine.TrackedAddressItems <= 20, $"{engine.TrackedAddressItems} items held");
    }

    [Fact]
    public void NetworkAndAccountStateAreBoundedLikeAddresses()
    {
        var engine = Engine(new DecisionEngineLimits { MaxEntries = 3 });

        Observe(engine, Enumerable.Range(1, 10).Select(i => Failure(i, $"2001:db8:{i:x}::1", $"account{i}")));

        Assert.Equal(3, engine.TrackedNetworks);
        Assert.Equal(3, engine.TrackedAccounts);
    }

    [Fact]
    public void PastTheActiveBoundANewDecisionIsRefusedAndTheRefusalRecorded()
    {
        var engine = Engine(new DecisionEngineLimits { MaxActive = 2 });

        var decisions = Observe(engine, Repeated("203.0.113.1", 10).Concat(Repeated("203.0.113.2", 10, from: 1)).Concat(Repeated("198.51.100.3", 10, from: 2)));

        Assert.Equal(2, decisions.Count(d => d.Action == DecisionActions.WouldBlock));
        var refused = Assert.Single(decisions, d => d.Action == DecisionActions.Refused);
        Assert.Contains("refused: 2 decisions are already active", refused.Reason, StringComparison.Ordinal);
        Assert.Equal(2, engine.ActiveCount);
    }

    // =============================================================================================
    //  Expiry.
    // =============================================================================================

    [Fact]
    public void ExpiryIsRecordedWhenTheDecisionEnds()
    {
        var engine = Engine();
        var decision = Assert.Single(Observe(engine, Repeated("203.0.113.7", 10)));

        Assert.Empty(engine.Expire(decision.ExpiresAt!.Value.AddSeconds(-1)));
        var expired = Assert.Single(engine.Expire(decision.ExpiresAt.Value.AddSeconds(30)));

        Assert.Equal(DecisionActions.Expire, expired.Action);
        Assert.Equal("203.0.113.7", expired.Target);
        Assert.Equal(DecisionRules.RepeatedFailures, expired.RuleId);
        Assert.Equal(decision.ExpiresAt, expired.Timestamp);
        Assert.StartsWith("would-block for 60 minutes reached its expiry", expired.Reason, StringComparison.Ordinal);
        Assert.Equal(0, engine.ActiveCount);
        Assert.Empty(engine.Expire(decision.ExpiresAt.Value.AddHours(1)));
    }

    [Fact]
    public void AnExpiryThatPassedBeforeTheMinutesPassIsRecordedBeforeTheNextDecision()
    {
        var engine = Engine();
        var first = Assert.Single(Observe(engine, Repeated("203.0.113.7", 10)));

        var after = first.ExpiresAt!.Value;
        var failures = Enumerable.Range(0, 10).Select(i => new AuthFailure(after.AddSeconds(i), AttemptPairing.SecurityChannel,
            IPAddress.Parse("203.0.113.7"), null, "admin", "bad-password", 10, ++record));
        var decisions = engine.Observe(failures, DefenseOptions.Default, after.AddSeconds(20));

        Assert.Equal(new[] { DecisionActions.Expire, DecisionActions.WouldBlock }, decisions.Select(d => d.Action));
    }

    /// <summary>A block lives exactly as long as the process. Stopping ends every decision, on the record.</summary>
    [Fact]
    public void EndingTheProcessEndsEveryDecision()
    {
        var engine = Engine();
        Observe(engine, Repeated("203.0.113.7", 10).Concat(Repeated("198.51.100.8", 10)));

        var ended = engine.EndAll(Now.AddMinutes(15));

        Assert.Equal(2, ended.Count);
        Assert.All(ended, e => Assert.Equal(DecisionActions.Expire, e.Action));
        Assert.All(ended, e => Assert.StartsWith("ended with the process", e.Reason, StringComparison.Ordinal));
        Assert.Equal(0, engine.ActiveCount);
    }

    [Fact]
    public void ExpiryForgetsQuietPeriodsAndStaleState()
    {
        var engine = Engine();
        rdpClients.Add(IPAddress.Parse("203.0.113.7"));
        Observe(engine, Repeated("203.0.113.7", 10).Concat(Repeated("198.51.100.8", 3)));
        Assert.Equal(1, engine.Quiet);
        Assert.Equal(1, engine.TrackedAddresses);

        engine.Expire(Now.AddDays(2));

        Assert.Equal(0, engine.Quiet);
        Assert.Equal(0, engine.TrackedAddresses);
        Assert.Equal(0, engine.TrackedNetworks);
    }

    // =============================================================================================
    //  Settings.
    // =============================================================================================

    [Fact]
    public void ThresholdsApplyAtTheNextEvaluation()
    {
        var engine = Engine();
        Assert.Empty(Observe(engine, Repeated("203.0.113.7", 4)));

        var stricter = DefenseOptions.Default with { RepeatedFailures = new(5, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30)) };
        var decision = Assert.Single(Observe(engine, Repeated("203.0.113.7", 1, from: 50), stricter));

        Assert.Equal(TimeSpan.FromMinutes(30), decision.ExpiresAt - decision.Timestamp);
        Assert.Contains("threshold 5 in 10 minutes", decision.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The store keeps 200 characters of a reason, and the trigger comes first. The longest reason each
    /// action can carry, with every setting at its widest, must come back from the store whole.
    /// </summary>
    [Fact]
    public void TheLongestReasonsFitWhatTheStoreKeeps()
    {
        var window = TimeSpan.FromMinutes(1439);
        var widest = new DefenseOptions
        {
            RepeatedFailures = new(100, window, TimeSpan.FromMinutes(6000)),
            NonexistentAccounts = new(50, window, TimeSpan.FromMinutes(10080)),
            Network = new(64, window, TimeSpan.FromMinutes(10080)),
            SharedAccount = new(100, window, TimeSpan.Zero)
        };
        AuthFailure At(DateTimeOffset start, double minutes, string ip, string account, string reason = "bad-password") =>
            new(start.AddMinutes(minutes), AttemptPairing.SecurityChannel, IPAddress.Parse(ip), null, account, reason, 10, ++record);
        IEnumerable<AuthFailure> Network(DateTimeOffset start) =>
            Enumerable.Range(1, 64).Select(i => At(start, (i - 1) * 1438.0 / 63, $"2001:db8:ffff:ffff::{i:x}", $"user{i}"));
        var records = new List<DecisionRecord>();

        rdpProblem = new string('x', 64);
        records.AddRange(Engine().Observe(Network(Now), widest, Now.AddDays(1)));
        rdpProblem = null;
        AddressRanges.TryParseCanonical("2001:db8:ffff:ffff:ffff:ffff:ffff:fff0", out var allowed);
        records.AddRange(Engine().Observe(Network(Now), widest with { Allow = [allowed] }, Now.AddDays(1)));

        var engine = Engine();
        var start = Now;
        for (var round = 0; round < 2; round++)
        {
            var decided = engine.Observe(Enumerable.Range(0, 100).Select(i => At(start, i * 1438.0 / 99, "2001:db8:ffff:fffe:ffff:ffff:ffff:ffff", "admin")),
                widest, start.AddDays(1));
            records.AddRange(decided);
            start = decided.Single(d => d.Action == DecisionActions.WouldBlock).ExpiresAt!.Value;
            records.AddRange(engine.Expire(start));
        }
        records.AddRange(Engine().Observe(Enumerable.Range(1, 100).Select(i => At(Now, (i - 1) * 1438.0 / 99, $"2001:db8:{i:x}::ffff", "administrador")),
            widest, Now.AddDays(1)));
        records.AddRange(Engine().Observe(Enumerable.Range(1, 50).Select(i => At(Now, (i - 1) * 1438.0 / 49, "2001:db8:ffff:fffd:ffff:ffff:ffff:ffff",
            $"name{i}", "unknown-account")), widest, Now.AddDays(1)));

        Assert.Contains(records, r => r.Action == DecisionActions.Refused && r.RuleId == DecisionRules.Network);
        Assert.Contains(records, r => r.Action == DecisionActions.Protected && r.RuleId == DecisionRules.Network);
        Assert.Contains(records, r => r.Reason.Contains("capped at 7 days", StringComparison.Ordinal));
        Assert.Contains(records, r => r.Action == DecisionActions.Report);
        Assert.Contains(records, r => r.Action == DecisionActions.Expire);
        Assert.Contains(records, r => r.RuleId == DecisionRules.NonexistentAccounts);
        var directory = Path.Combine(Path.GetTempPath(), "wpshield-engine-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using var store = EvidenceStore.OpenForWriting(Path.Combine(directory, EvidenceStore.FileName));
            var writer = new EvidenceWriter(store);
            foreach (var decision in records) writer.RecordDecision(decision);
            var stored = new EvidenceQueries(store).Decisions(Now.AddDays(-1), Now.AddDays(30), 1000).Select(d => d.Reason).ToHashSet(StringComparer.Ordinal);

            Assert.All(records, r => Assert.True(r.Reason.Length <= 200, $"{r.Reason.Length} characters: {r.Reason}"));
            Assert.All(records, r => Assert.Contains(r.Reason, stored));
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }
    [Fact]
    public void EveryRecordIsMonitorMode()
    {
        rdpClients.Add(IPAddress.Parse("198.51.100.8"));
        var engine = Engine();

        var records = Observe(engine, Repeated("203.0.113.7", 10).Concat(Repeated("198.51.100.8", 10)).Concat(OneAccountFrom(10)))
            .Concat(engine.EndAll(Now.AddHours(1)));

        Assert.All(records, r => Assert.Equal("monitor", r.Mode));
        Assert.Equal(new[] { "expire", "protected", "report", "would-block" }, records.Select(r => r.Action).Distinct().Order(StringComparer.Ordinal));
    }
}
