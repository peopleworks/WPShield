using WPShield.Cli;

namespace WPShield.Cli.Tests;

/// <summary>
/// The first verb of the CLI ADR 0003 introduces, and the reason it is first: every question it
/// answers had to be answered by hand during the first real deployment, and the one that mattered
/// most was the one nobody thought to ask.
/// </summary>
public sealed class StatusCommandTests
{
    [Fact]
    public void NotInstalled_IsReportedAsSuchRatherThanAsAFailure()
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(new InstallationReport { ServiceInstalled = false }, writer);

        Assert.Equal(StatusCommand.ExitNotInstalled, exit);
        Assert.Contains("not installed", writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ACompleteInstall_IsHealthyAndSaysNothingElse()
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(Healthy(), writer);

        Assert.Equal(StatusCommand.ExitHealthy, exit);
        Assert.Contains("Healthy.", writer.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("finding", writer.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The defect this verb was written for. An install that threw at step 4 of 6 left the gateway
    /// running as the most privileged account on the machine, with both directories still inheriting
    /// their parents — and every summary the installer had printed still said otherwise.
    /// </summary>
    [Theory]
    [InlineData("LocalSystem")]
    [InlineData(@"NT AUTHORITY\SYSTEM")]
    [InlineData(null)]
    public void AnAccountThatIsNotTheVirtualOne_IsAFinding(string? account)
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(Build(account: account), writer);

        Assert.Equal(StatusCommand.ExitDegraded, exit);
        Assert.Contains(@"NT SERVICE\WPShield", writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingOperatorConfiguration_IsAFinding()
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(
            Build(operatorConfigurationPresent: false),
            writer);

        Assert.Equal(StatusCommand.ExitDegraded, exit);
        Assert.Contains("appsettings.Local.json", writer.ToString(), StringComparison.Ordinal);
        Assert.Contains(".example placeholders", writer.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// In Monitor mode the log is the only artefact WPShield produces, so an empty one is a finding
    /// rather than a quiet night. That distinction is the whole reason this project writes evidence.
    /// </summary>
    [Fact]
    public void AnEmptyLogDirectory_IsAFindingRatherThanSilence()
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(Build(newestLogFile: null), writer);

        Assert.Equal(StatusCommand.ExitDegraded, exit);
        Assert.Contains("quiet night", writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ALogDirectoryReadableByAnUnprivilegedGroup_IsAFinding()
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(
            Build(broadAccess: [@"BUILTIN\Users (S-1-5-32-545)"]),
            writer);

        Assert.Equal(StatusCommand.ExitDegraded, exit);
        Assert.Contains("PRE-016", writer.ToString(), StringComparison.Ordinal);
        Assert.Contains("S-1-5-32-545", writer.ToString(), StringComparison.Ordinal);
    }

    /// <summary>
    /// Something that could not be read is reported rather than dropped. A status verb that silently
    /// omits what it failed to look at is the same defect as a check that cannot fail.
    /// </summary>
    [Fact]
    public void AProblemGatheringTheReport_ReachesTheOutput()
    {
        var writer = new StringWriter();

        var exit = StatusCommand.Run(
            Build(problems: ["appsettings.Local.json is not valid JSON: unexpected token"]),
            writer);

        Assert.Equal(StatusCommand.ExitDegraded, exit);
        Assert.Contains("not valid JSON", writer.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void EveryFindingIsCounted()
    {
        var writer = new StringWriter();

        StatusCommand.Run(
            Build(
                operatorConfigurationPresent: false,
                newestLogFile: null,
                broadAccess: [@"BUILTIN\Users (S-1-5-32-545)"]),
            writer);

        Assert.Contains("3 findings:", writer.ToString(), StringComparison.Ordinal);
    }

    private static InstallationReport Healthy() => Build();

    private static InstallationReport Build(
        string? account = @"NT SERVICE\WPShield",
        bool operatorConfigurationPresent = true,
        string? newestLogFile = "wpshield-20260908.jsonl",
        IReadOnlyList<string>? broadAccess = null,
        IReadOnlyList<string>? problems = null)
    {
        return new InstallationReport
        {
            ServiceInstalled = true,
            ServiceState = "Running",
            ServiceAccount = account,
            InstallDirectory = @"C:\Program Files\WPShield",
            ConfiguredLogDirectory = @"C:\ProgramData\WPShield\logs",
            ConfiguredUrls = "http://127.0.0.1:10000",
            OperatorConfigurationPresent = operatorConfigurationPresent,
            NewestLogFile = newestLogFile,
            NewestLogWritten = newestLogFile is null ? null : DateTimeOffset.UtcNow,
            LogDirectoryBroadAccess = broadAccess ?? [],
            Problems = problems ?? []
        };
    }
}
