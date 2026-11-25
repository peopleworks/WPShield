using WPShield.Evidence;
using Xunit;

namespace WPShield.Evidence.Tests;

/// <summary>
/// The pure decisions behind the host facts (ADR 0013): exposure verdicts, command-line flags, bugcheck codes,
/// restarts, inventory changes and the full-name indicator.
/// </summary>
public sealed class HostFactAnalysisTests
{
    private const int Public = 4;

    private static FirewallPolicy Policy(params FirewallRule[] rules) => new(Public, 0, 0, rules);

    private static FirewallRule Allow(string ports, string remote = "*", int protocol = ExposureVerdicts.ProtocolTcp, string? app = null) =>
        new(true, true, true, protocol, ports, remote, 7, app);

    private static FirewallRule Block(string ports, string remote = "*") => new(true, true, false, ExposureVerdicts.ProtocolTcp, ports, remote, 7, null);

    // ---------------------------------------------------------------------------------------------
    //  Exposure, by the Windows Firewall rules
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void ALoopbackListenerIsLocalOnlyAndAnUnreadPolicyIsUnknownNeverClosed()
    {
        Assert.Equal(ExposureVerdicts.LocalOnly, ExposureVerdicts.Classify("TCP", 1433, "loopback", null, Policy()));
        Assert.Equal(ExposureVerdicts.Unknown, ExposureVerdicts.Classify("TCP", 1433, "any", null, null));
    }

    [Fact]
    public void AnAllowRuleForAnyAddressIsOpenAndOneForSomeAddressesIsRestricted()
    {
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 3306, "any", null, Policy(Allow("3306"))));
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 3306, "any", null, Policy(Allow("3306", "Internet"))));
        Assert.Equal(ExposureVerdicts.Restricted, ExposureVerdicts.Classify("TCP", 3306, "any", null, Policy(Allow("3306", "198.51.100.20"))));
        Assert.Equal(ExposureVerdicts.Restricted, ExposureVerdicts.Classify("TCP", 3306, "any", null, Policy(Allow("3306", "LocalSubnet"))));
    }

    [Fact]
    public void BlockWinsAndTheDefaultActionDecidesWhenNoRuleMatches()
    {
        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 445, "any", null, Policy(Allow("445"), Block("445"))));
        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 445, "any", null, Policy()));
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 445, "any", null, new FirewallPolicy(Public, 0, Public, [])));
    }

    [Fact]
    public void AProfileWithItsFirewallOffAdmitsEverything()
    {
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 5900, "any", null, new FirewallPolicy(Public, Public, 0, [Block("5900")])));
    }

    [Fact]
    public void RulesForOtherProfilesProtocolsPortsOrProgramsDoNotApply()
    {
        var privateOnly = new FirewallRule(true, true, true, ExposureVerdicts.ProtocolTcp, "1433", "*", 2, null);
        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 1433, "any", null, Policy(privateOnly)));
        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 1433, "any", null, Policy(Allow("1433", protocol: ExposureVerdicts.ProtocolUdp))));
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 1433, "any", null, Policy(Allow("1000-2000"))));
        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 2433, "any", null, Policy(Allow("80,443,1433"))));
        Assert.Equal(ExposureVerdicts.Blocked, ExposureVerdicts.Classify("TCP", 1433, "any", @"C:\SQL\sqlservr.exe", Policy(Allow("*", app: @"C:\Other\x.exe"))));
        // An owner nobody could read: the program-scoped rule may well apply, and guessing "closed" hides a port.
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 1433, "any", null, Policy(Allow("*", app: @"C:\Other\x.exe"))));
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 135, "any", null, Policy(Allow("RPC-EPMap"))));
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 49670, "any", null, Policy(Allow("RPC"))));
    }

    [Fact]
    public void OnlyTheRedServicesOpenToAnyAreRed()
    {
        foreach (var port in new[] { 135, 139, 445, 1433, 3306, 33060, 5432, 5900, 5985, 5986 })
        {
            Assert.True(ExposureVerdicts.IsRed("TCP", port, ExposureVerdicts.OpenToAny));
            Assert.False(ExposureVerdicts.IsRed("TCP", port, ExposureVerdicts.Restricted));
        }
        Assert.False(ExposureVerdicts.IsRed("TCP", 443, ExposureVerdicts.OpenToAny));
        Assert.False(ExposureVerdicts.IsRed("UDP", 445, ExposureVerdicts.OpenToAny));
    }

    // ---------------------------------------------------------------------------------------------
    //  Command lines: the executable and flags, never the arguments
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(@"""C:\Program Files\Vendor\svc.exe"" -run", @"C:\Program Files\Vendor\svc.exe")]
    [InlineData(@"C:\Program Files\Vendor\svc.exe -run", @"C:\Program Files\Vendor\svc.exe")]
    [InlineData(@"C:\Windows\system32\svchost.exe -k netsvcs -p", @"C:\Windows\system32\svchost.exe")]
    [InlineData(@"C:\tools\agent", @"C:\tools\agent")]
    public void TheExecutableIsFoundTheWayTheServiceControlManagerReadsIt(string line, string executable) =>
        Assert.Equal(executable, CommandFlags.Inspect(line).Executable);

    [Theory]
    [InlineData("powershell.exe -enc SQBFAFgA", true)]
    [InlineData("powershell.exe -EncodedCommand SQBFAFgA", true)]
    [InlineData("pwsh.exe -ec SQBFAFgA", true)]
    [InlineData("powershell.exe /e SQBFAFgA", true)]
    [InlineData("powershell.exe -ExecutionPolicy Bypass -File x.ps1", false)]
    [InlineData("powershell.exe -NoProfile -File x.ps1", false)]
    public void AnEncodedCommandIsFlagged(string line, bool encoded) =>
        Assert.Equal(encoded, CommandFlags.Inspect(line).Flags.Contains(CommandFlags.EncodedCommand));

    [Fact]
    public void FlagsSayWhatTheArgumentsContainedAndNothingOfThemIsKept()
    {
        const string secret = "Password=Sup3rS3cret!";
        var (executable, flags) = CommandFlags.Inspect(@"C:\Tools\sync.exe --conn ""Server=db;" + secret + @""" --from https://example.test/x",
            isUserWritable: path => path.StartsWith(@"C:\Tools", StringComparison.OrdinalIgnoreCase));

        Assert.Equal(@"C:\Tools\sync.exe", executable);
        Assert.Equal([CommandFlags.HasArguments, CommandFlags.ContainsUrl, CommandFlags.UserWritablePath], flags);
        Assert.DoesNotContain(flags, f => f.Contains("Sup3r", StringComparison.Ordinal));
        Assert.Empty(CommandFlags.Inspect(@"""C:\Tools\sync.exe""").Flags);
    }

    [Fact]
    public void ATaskKeepsItsArgumentsApartAndTheyAreReducedToFlagsToo()
    {
        var (executable, flags) = CommandFlags.Inspect(@"""C:\Windows\System32\cmd.exe""", "/c powershell -enc AAAA");
        Assert.Equal(@"C:\Windows\System32\cmd.exe", executable);
        Assert.Contains(CommandFlags.EncodedCommand, flags);
    }

    // ---------------------------------------------------------------------------------------------
    //  Restarts and bugchecks
    // ---------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("0x00000133 (0x0000000000000000, 0x0000000000000501, 0x0000000000000500, 0xfffff80085710328)", 0x133u)]
    [InlineData("0x0000000a", 0xAu)]
    [InlineData("307", 0x133u)]
    [InlineData("0", null)]
    [InlineData("", null)]
    [InlineData("not a code", null)]
    public void ABugcheckCodeIsReadFromWhatWindowsWrites(string text, uint? code) => Assert.Equal(code, BugChecks.Parse(text));

    [Fact]
    public void ABugcheckIsNamedTheWayOperatorsSearchForIt()
    {
        Assert.Equal("0x133 DPC_WATCHDOG_VIOLATION", BugChecks.Describe(0x133));
        Assert.Equal("0x7777", BugChecks.Describe(0x7777));
    }

    [Fact]
    public void TheRecordsOfOneCrashAreOneRestartAndTwoCrashesAreTwo()
    {
        var day = new DateTimeOffset(2026, 10, 19, 6, 0, 0, TimeSpan.Zero);
        var restarts = HostRestarts.Group(
        [
            new HostRestartRecord(day, 10, 41, null),
            new HostRestartRecord(day.AddSeconds(2), 11, 6008, null),
            new HostRestartRecord(day.AddMinutes(4), 15, 1001, 0x133),
            new HostRestartRecord(day.AddDays(5), 90, 41, 0x133)
        ]);

        Assert.Equal(2, restarts.Count);
        Assert.Equal("10@" + day.ToUnixTimeMilliseconds(), restarts[0].Key);
        Assert.Equal(0x133u, restarts[0].BugCheckCode);
        Assert.Equal([41, 1001, 6008], restarts[0].EventIds);
    }

    // ---------------------------------------------------------------------------------------------
    //  Patch level: facts, never a verdict
    // ---------------------------------------------------------------------------------------------

    private static readonly DateTimeOffset PatchNow = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void TheNewestSuccessfulCumulativeUpdateIsFoundWhateverElseWasInstalled()
    {
        var (title, at, failed) = PatchLevels.FromUpdateEvents(
        [
            new UpdateEvent(PatchNow.AddDays(-1), 19, "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.400.1.0)"),
            new UpdateEvent(PatchNow.AddDays(-23), 19, "2026-11 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5090001)"),
            new UpdateEvent(PatchNow.AddDays(-55), 19, "2026-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5080001)"),
            new UpdateEvent(PatchNow.AddDays(-2), 20, "2026-11 Cumulative Update for .NET Framework (KB5090002)"),
            new UpdateEvent(PatchNow.AddDays(-12), 20, "Some driver"),
            new UpdateEvent(PatchNow.AddDays(-40), 20, "An old failure")
        ], PatchNow);

        Assert.Contains("KB5090001", title, StringComparison.Ordinal);
        Assert.Equal(PatchNow.AddDays(-23), at);
        Assert.Equal(2, failed);
    }

    [Fact]
    public void NoCumulativeUpdateInTheLogIsNotFoundNotNoneAndAHostileTitleIsCleanedAndBounded()
    {
        var (title, at, failed) = PatchLevels.FromUpdateEvents([new UpdateEvent(PatchNow, 19, "Driver update")], PatchNow);
        Assert.Null(title);
        Assert.Null(at);
        Assert.Equal(0, failed);

        var hostile = "Cumulative Update \u001b[31m" + new string('x', 500);
        var (cleaned, _, _) = PatchLevels.FromUpdateEvents([new UpdateEvent(PatchNow, 19, hostile)], PatchNow);
        Assert.DoesNotContain('\u001b', cleaned!);
        Assert.True(cleaned!.Length <= HostPatchLevel.MaxTitleLength);
    }

    [Theory]
    [InlineData("20348", 2849, "10.0.20348.2849", false)]
    [InlineData("20348", 4405, "10.0.20348.2849", true)]
    [InlineData("26200", 9974, "10.0.26100.9974", false)]
    [InlineData(null, null, "10.0.20348.2849", null)]
    [InlineData("20348", 2849, null, null)]
    public void TheKernelFileIsComparedWithTheRegistryByRevisionOnly(string? build, int? ubr, string? kernel, bool? differs)
    {
        var patch = new HostPatchLevel(build, ubr, "21H2", kernel, true, null, null, 0);
        Assert.Equal(differs, patch.KernelDiffersFromRegistry);
    }

    [Fact]
    public void TheBuildAndTheDaysSinceTheLastCumulativeUpdateAreFacts()
    {
        var patch = new HostPatchLevel("20348", 2849, "21H2", "10.0.20348.2849", true, "2026-11 Cumulative Update (KB5090001)", PatchNow.AddDays(-23), 0);

        Assert.Equal("20348.2849", patch.Build);
        Assert.Equal(23, patch.DaysSinceCumulativeUpdate(PatchNow));
        Assert.Null(new HostPatchLevel("20348", 2849, null, null, false, null, null, null).DaysSinceCumulativeUpdate(PatchNow));
    }

    // ---------------------------------------------------------------------------------------------
    //  Inventory changes and the full-name indicator
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AnItemAddedRemovedOrChangedIsAChangeAndAnUncheckedSignatureIsNot()
    {
        var before = new[]
        {
            new InventoryItemView(@"\Backup", @"C:\Tools\backup.exe", "SYSTEM", HostSignature.Signed),
            new InventoryItemView(@"\Old", @"C:\Tools\old.exe", "SYSTEM", HostSignature.Signed),
            new InventoryItemView(@"\Sync", @"C:\Tools\sync.exe", "SYSTEM", HostSignature.Signed)
        };
        var after = new[]
        {
            new InventoryItemView(@"\Backup", @"C:\Tools\backup.exe", "SYSTEM", HostSignature.NotChecked),
            new InventoryItemView(@"\Sync", @"C:\Users\Public\sync.exe", "Administrator", HostSignature.Unsigned),
            new InventoryItemView(@"\New", @"C:\ProgramData\n.exe", "SYSTEM", HostSignature.Unsigned)
        };

        var changes = InventoryDiff.Compare(HostFacts.Tasks, before, after);

        Assert.Equal(3, changes.Count);
        Assert.Equal(["executable", "account", "signature"], Assert.Single(changes, c => c.Change == "changed").Fields);
        Assert.Equal(@"\New", Assert.Single(changes, c => c.Change == "added").Key);
        Assert.Equal(@"\Old", Assert.Single(changes, c => c.Change == "removed").Key);
    }

    [Fact]
    public void AFullNameMatchesWhateverCaseSpacingOrHostPrefixTheAttackerUsed()
    {
        Assert.Equal(2, FullNameIndicator.Matches(
            ["Ana Ejemplo", "Build Agent Example", "Never Tried"],
            ["ana  ejemplo", @"HOST\Build Agent Example", "administrator", "build agent example@host.example"]));
        Assert.Equal(0, FullNameIndicator.Matches(["Ana Ejemplo"], ["aejemplo", "administrator"]));
        Assert.Equal(1, FullNameIndicator.Matches(["Andrés Muestra"], ["ANDRES MUESTRA"]));
        Assert.Equal(0, FullNameIndicator.Matches([], ["anything"]));
    }
}
