using WPShield.SecurityMonitor;

namespace WPShield.Cli.Tests;

/// <summary>
/// <c>wpshield evidence collect</c>: the guards that keep it from being a second writer, an
/// unelevated half-reader, or the thing that creates the evidence directory.
/// </summary>
public sealed class EvidenceCommandTests
{
    private const string Store = @"C:\evidence-test\wpshield-evidence.db";

    [Fact]
    public void WithoutElevation_ItRefusesBeforeCollecting()
    {
        var facts = new FakeFacts { Elevated = false };

        var exception = Assert.Throws<CliArgumentException>(() => Run(facts));

        Assert.Contains("elevated", exception.Message, StringComparison.Ordinal);
        Assert.False(facts.Collected);
    }

    /// <summary>The service is the evidence writer; one writer is the rule.</summary>
    [Theory]
    [InlineData("Running")]
    [InlineData("StartPending")]
    [InlineData("Paused")]
    public void WhileTheServiceIsNotStopped_ItRefuses(string state)
    {
        var facts = new FakeFacts { ServiceState = state };

        var exception = Assert.Throws<CliArgumentException>(() => Run(facts));

        Assert.Contains(state, exception.Message, StringComparison.Ordinal);
        Assert.Contains("Stop-Service WPShield", exception.Message, StringComparison.Ordinal);
        Assert.False(facts.Collected);
    }

    [Fact]
    public void AStoppedOrAbsentService_DoesNotBlockIt()
    {
        Assert.Equal(0, Run(new FakeFacts { ServiceState = "Stopped" }));
        Assert.Equal(0, Run(new FakeFacts { ServiceState = null }));
    }

    /// <summary>
    /// In the foreground a missing directory is one line and exit 1, never an idle wait - and never a
    /// directory created here, which would inherit ProgramData's permissions.
    /// </summary>
    [Fact]
    public void AMissingDirectory_IsAnErrorNamingTheInstall()
    {
        var facts = new FakeFacts { DirectoryExists = false };

        var exception = Assert.Throws<CliArgumentException>(() => Run(facts));

        Assert.Contains("wpshield install", exception.Message, StringComparison.Ordinal);
        Assert.Contains(@"C:\evidence-test", exception.Message, StringComparison.Ordinal);
        Assert.False(facts.Collected);
    }

    [Fact]
    public void TheStoreOptionIsPassedToTheCollector()
    {
        var facts = new FakeFacts();

        Assert.Equal(0, Run(facts));

        Assert.Equal(Store, facts.CollectedPath);
    }

    [Fact]
    public void ARelativeStoreIsRefused()
    {
        Assert.Throws<CliArgumentException>(() => Run(new FakeFacts(), "collect", "--store", "evidence.db"));
    }

    [Fact]
    public void AnUnknownActionOrOptionIsRefused()
    {
        Assert.Throws<CliArgumentException>(() => Run(new FakeFacts(), "export"));
        Assert.Throws<CliArgumentException>(() => Run(new FakeFacts(), "collect", "--store", Store, "--dry-run"));
    }

    [Fact]
    public void AStoreTheCollectorReportsMissing_ExitsOne()
    {
        Assert.Equal(1, Run(new FakeFacts { Exit = EvidenceCollectorExit.StoreMissing }));
    }

    private static int Run(FakeFacts facts, params string[] args)
    {
        if (args.Length == 0) args = ["collect", "--store", Store];
        using var output = new StringWriter();
        return EvidenceCommand.Run(CliOptions.Parse(args), output, args[0], facts.ToFacts(), _ => new Nothing());
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose()
        {
        }
    }

    private sealed class FakeFacts
    {
        public bool Elevated { get; init; } = true;
        public string? ServiceState { get; init; }
        public bool DirectoryExists { get; init; } = true;
        public EvidenceCollectorExit Exit { get; init; } = EvidenceCollectorExit.Stopped;
        public bool Collected { get; private set; }
        public string? CollectedPath { get; private set; }

        public EvidenceCommand.Facts ToFacts() => new(
            () => Elevated,
            () => ServiceState,
            _ => DirectoryExists,
            (path, _, _) =>
            {
                Collected = true;
                CollectedPath = path;
                return Task.FromResult(Exit);
            });
    }
}
