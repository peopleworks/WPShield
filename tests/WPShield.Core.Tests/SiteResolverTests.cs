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

    [Fact]
    public void Constructor_RejectsWhitespaceOnlyHosts()
    {
        var site = new SiteOptions
        {
            Id = "one",
            Hosts = ["  "],
            Destination = new Uri("http://127.0.0.1:51001")
        };

        var exception = Assert.Throws<ArgumentException>(() => new SiteResolver([site]));

        Assert.Equal("Site 'one' requires at least one non-empty host.", exception.Message);
    }

    [Fact]
    public void Constructor_RejectsDuplicatesAfterHostNormalization()
    {
        var first = new SiteOptions
        {
            Id = "one",
            Hosts = [" Example.test. "],
            Destination = new Uri("http://127.0.0.1:51001")
        };
        var second = new SiteOptions
        {
            Id = "two",
            Hosts = ["example.TEST:443"],
            Destination = new Uri("http://127.0.0.1:51002")
        };

        Assert.Throws<InvalidOperationException>(() => new SiteResolver([first, second]));
    }
}
