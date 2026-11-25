using WPShield.Cli.Preflight;

namespace WPShield.Cli.Tests;

public sealed class LocalGroupMembershipTests
{
    /// <summary>
    /// An account that does not resolve - which is what <c>NT SERVICE\WPShield</c> is before the
    /// install - is "nobody could look", never "not a member".
    /// </summary>
    [Fact]
    public void AnAccountThatDoesNotResolve_IsUnknownNotAbsent()
    {
        var membership = LocalGroupMembership.Read("S-1-5-32-573", @"NT SERVICE\WPShield-test-no-such-service-7f3a");

        Assert.Null(membership.IsMember);
        Assert.False(string.IsNullOrWhiteSpace(membership.Problem));
    }
}
