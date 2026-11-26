using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// The refinements from the first real <c>wpshield host</c> run (ADR 0013, as built): the rules behind an open port,
/// how far back the event logs reach, the hotfix fallback of the patch level, services stuck in a start loop, and the
/// Microsoft tasks folded out of the default listing. Synthetic names only.
/// </summary>
public sealed class HostFactRefinementsTests
{
    private const int Public = 4;
    private static readonly DateTimeOffset Now = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
    private const string Vnc = @"C:\Program Files\SyntheticVnc\vncserver.exe";

    private static FirewallRule Allow(string? ports, string remote = "*", string? app = null, string? name = null, bool enabled = true) =>
        new(enabled, true, true, ExposureVerdicts.ProtocolTcp, ports, remote, 7, app, name);

    private static FirewallPolicy Policy(params FirewallRule[] rules) => new(Public, 0, 0, rules);

    // ---------------------------------------------------------------------------------------------
    //  The rules that open a port
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AProgramRuleOnAnyPortIsNamedBesideTheRestrictedPortRuleItOverrides()
    {
        var policy = Policy(
            Allow("5900", "198.51.100.20", name: "Synthetic VNC (operator only)"),
            Allow("*", app: Vnc, name: "Synthetic VNC server"));

        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 5900, "any", Vnc, policy));
        Assert.Equal(["Synthetic VNC server [program rule, any port]"], ExposureVerdicts.OpenedBy("TCP", 5900, "any", Vnc, policy));
        // The same program rule opens every other port the program listens on.
        Assert.Equal(["Synthetic VNC server [program rule, any port]"], ExposureVerdicts.OpenedBy("TCP", 49670, "any", Vnc, policy));
    }

    [Fact]
    public void OnlyARuleThatAdmitsAnyAddressIsNamedAndARestrictedPortNamesNone()
    {
        var policy = Policy(Allow("1433", "198.51.100.0/24", name: "Synthetic SQL office"), Allow("445", name: "Synthetic SMB"),
            Allow("445", name: "Synthetic SMB disabled", enabled: false));

        Assert.Empty(ExposureVerdicts.OpenedBy("TCP", 1433, "any", null, policy));
        Assert.Equal(["Synthetic SMB"], ExposureVerdicts.OpenedBy("TCP", 445, "any", null, policy));
        Assert.Empty(ExposureVerdicts.OpenedBy("TCP", 445, "loopback", null, policy));
        Assert.Empty(ExposureVerdicts.OpenedBy("TCP", 445, "any", null, null));
    }

    [Fact]
    public void AStoreAppsPerUserRuleDoesNotOpenAPortTheKernelOwns()
    {
        // Per-user and app-container rules from store apps admit "any port, any address" for that app only.
        var perUser = new FirewallRule(true, true, true, ExposureVerdicts.ProtocolAny, null, "*", 7, null, "Synthetic Chat", UserOwner: "S-1-5-21-1-2-3-1001");
        var packaged = new FirewallRule(true, true, true, ExposureVerdicts.ProtocolAny, null, "*", 7, null, "Synthetic Store", AppPackage: "S-1-15-2-1");
        var policy = Policy(perUser, packaged);

        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 445, "any", "System", policy));
        Assert.Empty(ExposureVerdicts.OpenedBy("TCP", 445, "any", "System", policy));
        Assert.Equal(["Synthetic Store [any port]"], ExposureVerdicts.OpenedBy("TCP", 5000, "any",
            @"C:\Program Files\WindowsApps\Synthetic.Store_1.0_x64__abc\store.exe", Policy(packaged)));
        // An owner nobody could read keeps every rule: the open direction.
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 445, "any", null, policy));
    }

    [Fact]
    public void WithNoRuleTheCauseIsNamedInstead()
    {
        Assert.Equal([ExposureVerdicts.FirewallTurnedOff], ExposureVerdicts.OpenedBy("TCP", 445, "any", null, new FirewallPolicy(Public, Public, 0, [])));
        Assert.Equal([ExposureVerdicts.DefaultInboundAllow], ExposureVerdicts.OpenedBy("TCP", 445, "any", null, new FirewallPolicy(Public, 0, Public, [])));
    }

    [Fact]
    public void RuleNamesAreBoundedCleanedAndAtMostFive()
    {
        var rules = Enumerable.Range(0, 9).Select(i => Allow("445", name: $"Synthetic rule {i}")).Append(Allow("445", name: "Evil\u001b[31m\r\n" + new string('x', 400)))
            .Append(Allow("445", name: null)).ToArray();

        var names = ExposureVerdicts.OpenedBy("TCP", 445, "any", null, Policy(rules));

        Assert.Equal(ExposureVerdicts.MaxOpenedBy, names.Count);
        var hostile = ExposureVerdicts.OpenedBy("TCP", 445, "any", null, Policy(rules[^2]));
        Assert.DoesNotContain(hostile[0], c => char.IsControl(c));
        Assert.True(hostile[0].Length <= ExposureVerdicts.MaxRuleNameLength);
        Assert.Equal(["(unnamed rule)"], ExposureVerdicts.OpenedBy("TCP", 445, "any", null, Policy(rules[^1])));
        Assert.Equal(["Synthetic any [any port]"], ExposureVerdicts.OpenedBy("TCP", 445, "any", null, Policy(Allow(null, name: "Synthetic any"))));
    }

    // ---------------------------------------------------------------------------------------------
    //  How far back a log reaches
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void TheDominantEventIsTheMostFrequentPairOfTheNewestRecords()
    {
        (int, string?) control = (7036, "Service Control Manager"), app = (1000, "Synthetic App");
        var records = Enumerable.Repeat(control, 4986).Concat(Enumerable.Repeat(app, 30)).Concat(Enumerable.Repeat(control, 900)).ToArray();

        var dominant = HostLogHorizon.Dominant(records);

        Assert.NotNull(dominant);
        Assert.Equal(7036, dominant.Value.EventId);
        Assert.Equal("Service Control Manager", dominant.Value.Provider);
        Assert.Equal(HostLogHorizon.SampleSize, dominant.Value.Sampled);
        // Newest first and bounded: the last 900 records are never sampled.
        Assert.Equal(4986, dominant.Value.Count);
        Assert.Null(HostLogHorizon.Dominant([]));
    }

    [Fact]
    public void AHorizonUnderAWeekIsShortAndAnUnreadLogIsUnknown()
    {
        var system = new HostLogHorizon("System", true, 20L << 20, 63_818, Now.AddHours(-6), 7036, "Service Control Manager", 4986, 5000);
        var application = new HostLogHorizon("Application", true, 20L << 20, 900, Now.AddDays(-40), 1000, "Synthetic App", 300, 900);
        var security = new HostLogHorizon("Security", false, null, null, null, null, null, null, null, "access-denied");

        Assert.True(system.IsShort(Now));
        Assert.Equal(0.9972, system.DominantShare!.Value, 4);
        Assert.False(application.IsShort(Now));
        Assert.Null(security.IsShort(Now));
        Assert.Null(security.DominantShare);
    }

    // ---------------------------------------------------------------------------------------------
    //  The patch level's fallback, and the kernel file
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AKernelRevisionALittleBelowTheUbrIsADeltaNotAVerdict()
    {
        var patch = new HostPatchLevel("20348", 5761, "21H2", "10.0.20348.5756", true, null, null, 0);

        Assert.Equal(-5, patch.KernelRevisionDelta);
        Assert.True(patch.KernelDiffersFromRegistry);
        Assert.Null(new HostPatchLevel("20348", null, null, "10.0.20348.5756", true, null, null, 0).KernelRevisionDelta);
    }

    [Theory]
    [InlineData("11/2/2026", "2026-11-02")]
    [InlineData("02/11/2026", "2026-02-11")]
    [InlineData("20261102", "2026-11-02")]
    [InlineData("01dd4a3b8c5e8000", null)]
    [InlineData("not a date", null)]
    [InlineData("", null)]
    public void InstalledOnIsReadInTheShapesWindowsWritesAndNothingIsGuessed(string text, string? expected)
    {
        var parsed = Hotfixes.ParseInstalledOn(text);
        if (expected is null && text.Length == 16)
        {
            // A hexadecimal FILETIME reads as some date; the point is that it is read, not guessed.
            Assert.NotNull(parsed);
            return;
        }
        Assert.Equal(expected, parsed?.UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void TheNewestDatedHotfixWinsAndAnUndatedListStillNamesOne()
    {
        Assert.Equal("KB5090002", Hotfixes.Newest([new("KB5090001", "10/14/2026"), new("KB5090002", "11/2/2026"), new("KB5090003", "")])!.Value.Id);
        var undated = Hotfixes.Newest([new("KB5090008", null), new("KB5090009", "garbage")])!.Value;
        Assert.Equal("KB5090009", undated.Id);
        Assert.Null(undated.InstalledOn);
        Assert.Null(Hotfixes.Newest([]));
        Assert.DoesNotContain('\u001b', Hotfixes.Newest([new("KB\u001b[31m5090001", "11/2/2026")])!.Value.Id!);
    }

    // ---------------------------------------------------------------------------------------------
    //  Services stuck in a start loop
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AnAutomaticServiceThatIsNotRunningIsFlaggedAndAFlappingOneToo()
    {
        Assert.Equal([ServiceStates.NotRunning, ServiceStates.StartPending], ServiceStates.Flags("startpending", "automatic", 0, 0));
        Assert.Equal([ServiceStates.StartPending], ServiceStates.Flags("startpending", "manual", 0, 0));
        Assert.Equal([ServiceStates.NotRunning], ServiceStates.Flags("paused", "automatic", null, null));
        Assert.Equal([ServiceStates.NotRunning], ServiceStates.Flags("stopped", "automatic", 0, 2));
        Assert.Empty(ServiceStates.Flags("stopped", "automatic", 0, 0));
        Assert.Empty(ServiceStates.Flags("stopped", "automatic", null, null));
        Assert.Empty(ServiceStates.Flags("stopped", "manual", 0, 5));
        Assert.Equal([ServiceStates.Flapping], ServiceStates.Flags("running", "automatic", ServiceStates.FlappingThreshold, 0));
        Assert.Empty(ServiceStates.Flags("running", "automatic", ServiceStates.FlappingThreshold - 1, 0));
    }

    [Fact]
    public void StateChangesCountForAnHourAndFailuresForADayByDisplayName()
    {
        var events = new List<ServiceControlEvent>();
        for (var i = 0; i < 12; i++) events.Add(new(Now.AddMinutes(-i * 4.0), ServiceStates.StateChange, "Synthetic Worker"));
        events.Add(new(Now.AddHours(-2), ServiceStates.StateChange, "Synthetic Worker"));
        events.Add(new(Now.AddHours(-3), 7031, "synthetic worker"));
        events.Add(new(Now.AddHours(-30), 7034, "Synthetic Worker"));
        events.Add(new(Now.AddMinutes(5), ServiceStates.StateChange, "Synthetic Worker"));
        events.Add(new(Now.AddMinutes(-1), 7000, null));

        var (changes, failures) = ServiceStates.Count(events, Now);

        Assert.Equal(12, changes["Synthetic Worker"]);
        Assert.Equal(1, failures["SYNTHETIC WORKER"]);
        Assert.Equal(1, ServiceStates.NameIndex(7009));
        Assert.Equal(0, ServiceStates.NameIndex(7031));
    }

    // ---------------------------------------------------------------------------------------------
    //  Microsoft tasks folded out of the default listing
    // ---------------------------------------------------------------------------------------------

    private static HostTask TaskOf(string path, string executable, string signature = HostSignature.Signed, string? signer = "Microsoft Windows",
        string[]? flags = null) => new(path, "ready", "SYSTEM", null, null, executable, signature, signer, flags ?? []);

    [Fact]
    public void OnlyAQuietMicrosoftScriptHostTaskIsFolded()
    {
        Assert.True(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\Cleanup", @"%windir%\system32\rundll32.exe",
            flags: [CommandFlags.HasArguments])));
        Assert.True(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\Inventory", @"%systemroot%\system32\cmd.exe")));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\Encoded", @"%windir%\system32\cmd.exe",
            flags: [CommandFlags.HasArguments, CommandFlags.EncodedCommand])));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\Writable", @"%windir%\system32\cmd.exe",
            flags: [CommandFlags.HasArguments, CommandFlags.UserWritablePath])));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Vendor\Cleanup", @"%windir%\system32\rundll32.exe")));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Office\Cleanup", @"%windir%\system32\rundll32.exe")));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\Other", @"C:\Windows\System32\failover.exe")));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\NotChecked", @"%windir%\system32\rundll32.exe",
            HostSignature.NotChecked, null)));
        Assert.False(TaskGroups.IsMicrosoftScriptHostOnly(TaskOf(@"\Microsoft\Windows\Synthetic\Vendor", @"%windir%\system32\rundll32.exe",
            signer: "Synthetic Vendor")));
    }

    // ---------------------------------------------------------------------------------------------
    //  The payloads keep the new fields
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void TheNewFieldsSurviveTheSnapshotRoundTrip()
    {
        var health = new HostHealth(Now.AddDays(-1), 86_400, 5, 100, 50, [], 10,
            new HostPatchLevel("20348", 5761, "21H2", "10.0.20348.5756", true, null, null, 0, null, "KB5090002", Now.AddDays(-24), true),
            [new HostLogHorizon("System", true, 20L << 20, 63_818, Now.AddHours(-6), 7036, "Service Control Manager", 4986, 5000)]);
        var ports = new HostPorts([new HostListener("TCP", 5900, "any", null, "vncserver.exe", Vnc, ExposureVerdicts.OpenToAny, true,
            ["Synthetic VNC server [program rule, any port]"])], true);

        var readHealth = HostFactReading.Of(HostFacts.Health, null, Now, health).Value<HostHealth>()!;
        var readPorts = HostFactReading.Of(HostFacts.Ports, null, Now, ports).Value<HostPorts>()!;

        Assert.Equal("KB5090002", readHealth.Patch!.LastHotfixId);
        Assert.True(readHealth.Patch.HotfixListRead);
        Assert.Equal(7036, Assert.Single(readHealth.Logs!).DominantEventId);
        Assert.Equal("Synthetic VNC server [program rule, any port]", Assert.Single(readPorts.Listeners[0].OpenedBy!));
        // An older snapshot, written before these fields existed, reads them as unknown.
        var old = HostFactReading.Of(HostFacts.Health, null, Now, new HostHealth(Now, 1, null, null, null, [], null)).Value<HostHealth>()!;
        Assert.Null(old.Logs);
    }
}
