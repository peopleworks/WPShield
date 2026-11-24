using WPShield.Cli;

namespace WPShield.Cli.Tests;

public sealed class NetworkFilterCommandTests
{
    [Fact]
    public void RetiredFilterRefusesDefaultAndLegacyInvocations()
    {
        Assert.Equal(1, ProgramMain.Run(["network-filter"]));
        Assert.Equal(1, ProgramMain.Run(["network-filter", "--block-list", "192.0.2.1"]));
        Assert.Equal(0, ProgramMain.Run(["network-filter", "--help"]));
        Assert.Contains("blocking is unavailable", NetworkFilterCommand.Help, StringComparison.Ordinal);
    }
}
