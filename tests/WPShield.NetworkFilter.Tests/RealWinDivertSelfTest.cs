namespace WPShield.NetworkFilter.Tests;

/// <summary>
/// The self-test against the real WinDivert library, when it is present. Opt-in in the same way the
/// IIS validation tests are: CI has no WinDivert.dll and returns early; a machine with the official
/// 2.2.2 x64 files copied next to the test assembly runs it. It needs neither elevation nor the driver,
/// because the compile and evaluate helpers are plain user-mode functions.
/// </summary>
public sealed class RealWinDivertSelfTest
{
    private static bool LibraryIsPresent =>
        File.Exists(Path.Combine(AppContext.BaseDirectory, "WinDivert.dll"));

    [Fact]
    public void TheRealLibrary_EvaluatesWPShieldFiltersAsIntended()
    {
        if (!LibraryIsPresent)
        {
            return;
        }

        var report = NetworkFilterSelfTest.Run(
            new WinDivertDriver(mayInstallDriver: false),
            [Ranges.Allow("203.0.113.50"), Ranges.Allow("2001:db8::50")],
            [Ranges.Block("94.0.0.0/24"), Ranges.Block("198.51.100.9"), Ranges.Block("2001:db8:9::/64")]);

        Assert.True(report.Passed, string.Join("; ", report.Failures.Select(f => $"{f.Name}: {f.Detail}")));
    }
}
