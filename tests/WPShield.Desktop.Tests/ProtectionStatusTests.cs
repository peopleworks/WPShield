using System.Text.Json.Nodes;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// What the Protection window says, decided from synthetic reads of the store and the service controller.
/// Synthetic RFC 5737 and RFC 3849 addresses only.
/// </summary>
public sealed class ProtectionStatusTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly ServiceReading Running = new(ServiceState.Running);
    private static readonly ServiceReading Stopped = new(ServiceState.Stopped);

    private static EvidenceCoverage Row(string status, DateTimeOffset from, DateTimeOffset to, string? reason = null) =>
        new(EvidenceWriter.RawSource, from, to, status, reason);

    private static DecisionRecord Decision(string action, string target, string rule, DateTimeOffset at, DateTimeOffset? until,
        string reason = "10 failed logons in 2 minutes (threshold 10 in 10 minutes)") =>
        new(at, action, target, rule, DecisionActions.MonitorMode, reason, "security-4625", until);

    private static ProtectionRead Read(bool current = true, EvidenceCoverage[]? coverage = null, DecisionRecord[]? active = null,
        bool engine = true, Dictionary<string, long>? day = null, Dictionary<string, long>? month = null, DecisionRecord[]? dayRows = null,
        DecisionRecord[]? monthRows = null, string dayCoverage = "full", string monthCoverage = "partial", JsonNode? labels = null,
        DateTimeOffset? collectedUntil = null) =>
        new(Now, coverage ?? (current ? [Row("collected", Now.AddHours(-3), Now)] : []),
            new ActiveDecisions(Now, engine ? Now.AddHours(-3) : null, collectedUntil ?? (current ? Now : Now.AddHours(-1)), current,
                active ?? [], false),
            day ?? [], month ?? [], dayRows ?? [], monthRows ?? [], dayCoverage, monthCoverage, JsonValue.Create("monitor"), labels);

    [Fact]
    public void TheCollectorIsRecordingOnlyWhenTheStoresOneDefinitionSaysSo()
    {
        Assert.Equal(CollectorState.Recording, ProtectionStatus.Collector(Read()).State);
        Assert.Equal(CollectorState.Unread, ProtectionStatus.Collector(null).State);

        var stopped = ProtectionStatus.Collector(Read(current: false, collectedUntil: Now.AddHours(-1)));
        Assert.Equal(CollectorState.Stopped, stopped.State);
        Assert.Equal(Now.AddHours(-1), stopped.LastRecorded);
        Assert.Equal("Stopped - last recorded 2026-11-24 11:00 UTC", ProtectionStatus.CollectorLine(stopped, false).Title);
        Assert.Equal(Tone.Grey, ProtectionStatus.CollectorLine(stopped, false).Tone);
    }

    [Fact]
    public void ACollectorThatIsAliveButCannotReadTheSecurityLogIsBlindNotStoppedNorRecording()
    {
        var blind = ProtectionStatus.Collector(Read(current: false,
            coverage: [Row("unavailable", Now.AddHours(-2), Now.AddSeconds(-30), "security-4625: access-denied")]));

        Assert.Equal(CollectorState.Blind, blind.State);
        Assert.Equal("security-4625: access-denied", Assert.Single(blind.Problems));
        var line = ProtectionStatus.CollectorLine(blind, spanish: false);
        Assert.Equal("Running, not recording", line.Title);
        Assert.Equal(Tone.Amber, line.Tone);

        // An unavailable interval that ended long ago says nothing about now.
        var old = ProtectionStatus.Collector(Read(current: false,
            coverage: [Row("unavailable", Now.AddHours(-2), Now.AddMinutes(-9), "security-4625: access-denied")]));
        Assert.Equal(CollectorState.Stopped, old.State);
    }

    [Theory]
    [InlineData("Stopped")]
    [InlineData("NotInstalled")]
    public void AServiceThatIsAbsentWhileTheStoreRecordsSaysTheForegroundCollectorIsWriting(string state)
    {
        var line = ProtectionStatus.ServiceLine(new ServiceReading(Enum.Parse<ServiceState>(state)), ProtectionStatus.Collector(Read()), spanish: false);

        Assert.Contains("'wpshield evidence collect' running in the foreground", line.Detail, StringComparison.Ordinal);
        Assert.Equal(Tone.Amber, line.Tone);
    }

    [Fact]
    public void TheServiceLineNeverContradictsTheCollector()
    {
        var recording = ProtectionStatus.Collector(Read());
        var stopped = ProtectionStatus.Collector(Read(current: false));

        var ok = ProtectionStatus.ServiceLine(Running, recording, spanish: false);
        Assert.Equal("Windows service WPShield: running", ok.Title);
        Assert.Equal(Tone.Green, ok.Tone);

        var idle = ProtectionStatus.ServiceLine(Running, stopped, spanish: false);
        Assert.Contains("Evidence:Enabled", idle.Detail, StringComparison.Ordinal);
        Assert.Equal(Tone.Amber, idle.Tone);

        Assert.Equal(Tone.Grey, ProtectionStatus.ServiceLine(Stopped, stopped, spanish: false).Tone);
        var unknown = ProtectionStatus.ServiceLine(new ServiceReading(ServiceState.Unknown, "access is denied"), recording, spanish: true);
        Assert.Equal("Servicio de Windows WPShield: no se pudo leer", unknown.Title);
        Assert.Contains("access is denied", unknown.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void TheLogonChipIsGreenOnlyWhenEarned()
    {
        var chip = ProtectionStatus.Logons(ProtectionStatus.Collector(Read()), Running, spanish: false);
        Assert.Equal(Tone.Green, chip.Tone);
        Assert.Equal("Windows logons (Remote Desktop, SMB, network)", chip.Name);
        Assert.False(chip.Planned);

        Assert.Equal(Tone.Grey, ProtectionStatus.Logons(ProtectionStatus.Collector(Read(current: false)), Running, spanish: false).Tone);
        var unread = ProtectionStatus.Logons(ProtectionStatus.Collector(null), Running, spanish: false);
        Assert.Equal(Tone.Grey, unread.Tone);
        Assert.Contains("nobody could look", unread.Tooltip, StringComparison.Ordinal);
    }

    [Fact]
    public void ABlindChipNamesTheRemedyForWhoeverIsCollecting()
    {
        var blind = ProtectionStatus.Collector(Read(current: false,
            coverage: [Row("unavailable", Now.AddHours(-2), Now, "security-4625: access-denied")]));

        var service = ProtectionStatus.Logons(blind, Running, spanish: false);
        Assert.Equal(Tone.Amber, service.Tone);
        Assert.Equal("configured but blind", service.Status);
        Assert.Contains(@"Add NT SERVICE\WPShield to Event Log Readers", service.Tooltip, StringComparison.Ordinal);
        Assert.Contains(EvidenceCollector.EventLogReadersRemedy, service.Tooltip, StringComparison.Ordinal);
        Assert.Contains("the Security log could not be read: access denied", service.Tooltip, StringComparison.Ordinal);

        var foreground = ProtectionStatus.Logons(blind, Stopped, spanish: false);
        Assert.Contains("from an elevated prompt", foreground.Tooltip, StringComparison.Ordinal);
        Assert.DoesNotContain("Event Log Readers", foreground.Tooltip, StringComparison.Ordinal);

        var unknown = ProtectionStatus.Logons(blind, new ServiceReading(ServiceState.Unknown, "x"), spanish: true);
        Assert.Contains("Lectores del registro de eventos", unknown.Tooltip, StringComparison.Ordinal);
        Assert.Contains("consola elevada", unknown.Tooltip, StringComparison.Ordinal);
    }

    [Fact]
    public void RecordingWithAProblemInTheCoverageIsAmberAndSaysWhat()
    {
        var reading = ProtectionStatus.Collector(Read(coverage:
        [
            Row("collected", Now.AddHours(-3), Now),
            Row("limited", Now.AddHours(-3), Now, "rdpcorets-140: channel-missing")
        ]));

        var chip = ProtectionStatus.Logons(reading, Running, spanish: false);
        Assert.Equal(CollectorState.Recording, reading.State);
        Assert.Equal(Tone.Amber, chip.Tone);
        Assert.Contains("coverage reports a problem", chip.Tooltip, StringComparison.Ordinal);
        Assert.Contains("Remote Desktop's log (RdpCoreTS) is not present on this system", chip.Tooltip, StringComparison.Ordinal);
        Assert.Contains("failed logons were not recorded (12 dropped)", ProtectionStatus.Describe("buffer-full: 12 dropped", false),
            StringComparison.Ordinal);
    }

    [Fact]
    public void AServiceThatDoesNotExistIsNotInstalledNotUnreadable() =>
        Assert.Equal(new ServiceReading(ServiceState.NotInstalled), ServiceReader.Read("WPShieldAbsent" + Guid.NewGuid().ToString("N")));

    [Fact]
    public void PlannedSensorsAreTheRoadmapsAndRecordNothing()
    {
        var planned = ProtectionStatus.Planned(spanish: false);

        Assert.Equal(["SQL Server logins", "Requests to the sites (gateway)"], planned.Select(p => p.Name));
        Assert.All(planned, p =>
        {
            Assert.True(p.Planned);
            Assert.Equal(Tone.Grey, p.Tone);
            Assert.Equal("planned", p.Status);
            Assert.Contains("not recording", p.Tooltip, StringComparison.Ordinal);
            Assert.Contains("ADR 0007", p.Tooltip, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void TheModeIsMonitorAndBlockIsNeverOffered()
    {
        Assert.Equal("Monitor - nothing is blocked", ProtectionStatus.ModeLine(Read(), spanish: false).Title);
        Assert.Equal("Monitor: no se bloquea nada", ProtectionStatus.ModeLine(Read(), spanish: true).Title);
        Assert.Equal("Mode: —", ProtectionStatus.ModeLine(null, spanish: false).Title);
        Assert.Contains("ADR 0006", ProtectionStatus.BlockNotAvailable(spanish: false), StringComparison.Ordinal);
        Assert.Contains("does not exist", ProtectionStatus.BlockNotAvailable(spanish: false), StringComparison.Ordinal);
    }

    [Fact]
    public void NobodyCouldLookIsADashAndARecordedNothingIsZero()
    {
        var unread = ProtectionStatus.Counts(null, Now);
        Assert.Equal(new ProtectionCounts("—", "—", "—", "—"), unread);
        Assert.All(Enum.GetValues<DecisionTab>(), t => Assert.Equal("—", ProtectionStatus.TabCount(null, t, Now)));

        var quiet = ProtectionStatus.Counts(Read(), Now);
        Assert.Equal(new ProtectionCounts("0", "0", "0", "0"), quiet);
        Assert.Equal("0", ProtectionStatus.TabCount(Read(), DecisionTab.Day, Now));

        // Nothing recorded in the last 24 hours: no decision because nobody decided, which is not zero.
        var unrecorded = Read(current: false, dayCoverage: "none", monthCoverage: "none");
        Assert.Equal(new ProtectionCounts("0", "—", "—", "—"), ProtectionStatus.Counts(unrecorded, Now));
        Assert.Equal("—", ProtectionStatus.TabCount(unrecorded, DecisionTab.Day, Now));
        Assert.Equal("—", ProtectionStatus.TabCount(unrecorded, DecisionTab.Month, Now));
        Assert.Contains("No data", ProtectionStatus.Empty(unrecorded, DecisionTab.Month, false, spanish: false), StringComparison.Ordinal);
        Assert.Contains("not recording", ProtectionStatus.Empty(unrecorded, DecisionTab.InForce, false, spanish: false), StringComparison.Ordinal);
        Assert.Contains("never run", ProtectionStatus.Empty(Read(engine: false), DecisionTab.InForce, false, spanish: false), StringComparison.Ordinal);
        Assert.Contains("nobody could look", ProtectionStatus.Empty(null, DecisionTab.InForce, false, spanish: false), StringComparison.Ordinal);
    }

    [Fact]
    public void TabsCountTheirPeriodExactlyAndTheSearchFindsTargetLabelAndRule()
    {
        var labels = JsonNode.Parse("""{"203.0.113.0/24":"Scanner network","198.51.100.7":"My office"}""");
        DecisionRecord[] active =
        [
            Decision(DecisionActions.WouldBlock, "203.0.113.0/24", DecisionRules.Network, Now.AddMinutes(-20), Now.AddMinutes(40)),
            Decision(DecisionActions.Protected, "198.51.100.7", DecisionRules.RepeatedFailures, Now.AddMinutes(-10), Now.AddMinutes(50)),
            // Expired since the store was read: drawn as what it is now, not as what it was.
            Decision(DecisionActions.WouldBlock, "2001:db8:5::17", DecisionRules.NonexistentAccounts, Now.AddHours(-6), Now.AddSeconds(-1))
        ];
        var read = Read(active: active, labels: labels,
            day: new() { [DecisionActions.WouldBlock] = 3, [DecisionActions.Protected] = 1, [DecisionActions.Expire] = 1, [DecisionActions.Report] = 2 },
            month: new() { [DecisionActions.WouldBlock] = 40, [DecisionActions.Refused] = 2 },
            dayRows: [.. active]);

        var counts = ProtectionStatus.Counts(read, Now);
        Assert.Equal(new ProtectionCounts("1", "1", "0", "2"), counts);
        Assert.Equal("In force (2)", ProtectionStatus.TabTitle(DecisionTab.InForce, ProtectionStatus.TabCount(read, DecisionTab.InForce, Now), false));
        Assert.Equal("Last 24 h (7)", ProtectionStatus.TabTitle(DecisionTab.Day, ProtectionStatus.TabCount(read, DecisionTab.Day, Now), false));
        Assert.Equal("30 días (42)", ProtectionStatus.TabTitle(DecisionTab.Month, ProtectionStatus.TabCount(read, DecisionTab.Month, Now), true));

        var inForce = ProtectionStatus.Rows(read, DecisionTab.InForce, "", spanish: false, Now);
        Assert.Equal(["203.0.113.0/24", "198.51.100.7"], inForce.Select(r => r.Target));
        var network = inForce[0];
        Assert.Equal(("Scanner network", "HOST-AUTH-003", "would block", "2026-11-24 11:40", "2026-11-24 12:40"),
            (network.Label, network.Rule, network.Action, network.Since, network.Until));

        Assert.Equal("203.0.113.0/24", Assert.Single(ProtectionStatus.Rows(read, DecisionTab.InForce, "SCANNER", false, Now)).Target);
        Assert.Equal("198.51.100.7", Assert.Single(ProtectionStatus.Rows(read, DecisionTab.InForce, "host-auth-001", false, Now)).Target);
        Assert.Equal("198.51.100.7", Assert.Single(ProtectionStatus.Rows(read, DecisionTab.InForce, "198.51", false, Now)).Target);
        Assert.Empty(ProtectionStatus.Rows(read, DecisionTab.InForce, "192.0.2", false, Now));
        Assert.Contains("matches the search", ProtectionStatus.Empty(read, DecisionTab.InForce, true, false), StringComparison.Ordinal);
        // The day's list holds every record of the period, the expired one too.
        Assert.Equal(3, ProtectionStatus.Rows(read, DecisionTab.Day, "", false, Now).Count);
    }

    [Fact]
    public void ANetworkTakesItsOwnLabelOrABroaderOneNeverThatOfAnAddressInsideIt()
    {
        var labels = JsonNode.Parse("""{"203.0.113.0":"One host","203.0.113.0/28":"Narrower","192.0.2.0/24":"Lab network","2001:db8:5::/48":"Lab"}""");
        var matcher = AddressLabels.From(labels);

        Assert.Equal("", ProtectionStatus.LabelOf(labels, matcher, "203.0.113.0/24"));
        Assert.Equal("Lab network", ProtectionStatus.LabelOf(labels, matcher, "192.0.2.0/24"));
        Assert.Equal("Lab", ProtectionStatus.LabelOf(labels, matcher, "2001:db8:5::/64"));
        Assert.Equal("One host", ProtectionStatus.LabelOf(labels, matcher, "203.0.113.0"));
    }

    [Fact]
    public void ATabSaysWhenItListsFewerRecordsThanItCounts()
    {
        var rows = Enumerable.Range(0, EvidenceProtectionStore.Shown + 1)
            .Select(i => Decision(DecisionActions.Refused, "203.0.113.9", DecisionRules.NonexistentAccounts, Now.AddSeconds(-i), null, "unreadable"))
            .ToArray();
        var read = Read(day: new() { [DecisionActions.Refused] = 900 }, dayRows: rows);

        Assert.True(ProtectionStatus.Truncated(read, DecisionTab.Day));
        Assert.Equal(EvidenceProtectionStore.Shown, ProtectionStatus.Rows(read, DecisionTab.Day, "", false, Now).Count);
        Assert.Equal("900", ProtectionStatus.TabCount(read, DecisionTab.Day, Now));
        Assert.Equal("", ProtectionStatus.Rows(read, DecisionTab.Day, "", false, Now)[0].Until);
    }
}
