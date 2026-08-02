using WPShield.Core;

namespace WPShield.Core.Tests;

public sealed class SiteResolverTests
{
    [Fact]
    public void Resolve_IsCaseInsensitive_AndIgnoresPort()
    {
        var expected = new SiteOptions
        {
            Id = "one",
            Hosts = ["Example.test"],
            Destination = new Uri("http://127.0.0.1:8081")
        };
        var resolver = new SiteResolver([expected]);

        var actual = resolver.Resolve("EXAMPLE.TEST:443");

        Assert.Same(expected, actual);
    }
}
