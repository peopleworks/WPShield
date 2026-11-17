namespace WPShield.NetworkFilter.Tests;

public sealed class NetworkFilterSelfTestTests
{
    [Fact]
    public void AgainstAnEvaluatorThatAgrees_EveryCheckPasses()
    {
        var report = NetworkFilterSelfTest.Run(
            new FakeDivertDriver(),
            [Ranges.Allow("203.0.113.50"), Ranges.Allow("10.0.0.0/8")],
            [Ranges.Block("94.0.0.0/24"), Ranges.Block("198.51.100.9"), Ranges.Block("2001:db8:9::/64")]);

        Assert.True(report.Passed, string.Join("; ", report.Failures.Select(f => $"{f.Name}: {f.Detail}")));
        Assert.Contains(report.Checks, check => check.Name.Contains("198.51.99.255", StringComparison.Ordinal));
    }

    [Fact]
    public void ALibraryThatOrdersRangesDifferently_FailsTheProbe()
    {
        var driver = new FakeDivertDriver
        {
            EvaluateOverride = (filter, source) =>
                filter.Contains(">=", StringComparison.Ordinal) && source.ToString() == "198.51.101.0" ? true : null,
        };

        var report = NetworkFilterSelfTest.Run(driver, [], []);

        Assert.False(report.Passed);
        Assert.Contains(report.Failures, failure => failure.Name.Contains("198.51.101.0", StringComparison.Ordinal));
    }

    [Fact]
    public void AFilterTheLibraryRejects_FailsTheSelfTest()
    {
        var driver = new FakeDivertDriver { CompileFails = filter => filter.Contains("ipv6", StringComparison.Ordinal) };

        var report = NetworkFilterSelfTest.Run(driver, [], []);

        Assert.False(report.Passed);
        Assert.Contains(report.Failures, failure => failure.Name.Contains("compiles", StringComparison.Ordinal));
    }

    [Fact]
    public void AConfiguredBlockOverlappingTheAllowList_FailsTheSelfTest()
    {
        var report = NetworkFilterSelfTest.Run(new FakeDivertDriver(), [Ranges.Allow("94.0.0.9")], [Ranges.Block("94.0.0.0/24")]);

        Assert.False(report.Passed);
        Assert.Contains(report.Failures, failure => failure.Detail!.Contains("94.0.0.0/24", StringComparison.Ordinal));
    }

    [Fact]
    public void TheSelfTest_NeverOpensAHandle()
    {
        var driver = new FakeDivertDriver();

        NetworkFilterSelfTest.Run(driver, [Ranges.Allow("203.0.113.50")], [Ranges.Block("94.0.0.0/24")]);

        Assert.Empty(driver.Opened);
    }
}
