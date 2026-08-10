using WPShield.Core;

namespace WPShield.Gateway.Tests;

public sealed class GatewayConfigurationValidatorTests
{
    [Fact]
    public void Validate_RejectsEmptySiteList()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), []));

        Assert.Equal("At least one site must be configured.", exception.Message);
    }

    [Fact]
    public void Validate_RejectsDuplicateHostsCaseInsensitively()
    {
        var sites = new[]
        {
            CreateSite("one", "Example.test", 51001),
            CreateSite("two", "example.TEST", 51002)
        };

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), sites));

        Assert.Equal("Host 'example.TEST' is assigned more than once.", exception.Message);
    }

    [Fact]
    public void Validate_RejectsWhitespaceOnlyHost()
    {
        var exception = Assert.Throws<ArgumentException>(
            () => GatewayConfigurationValidator.Validate(
                CreateGatewayOptions(),
                [CreateSite("one", "  ", 51001)]));

        Assert.Contains("non-empty host", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsDuplicateHostsAfterNormalization()
    {
        var sites = new[]
        {
            CreateSite("one", " Example.test. ", 51001),
            CreateSite("two", "example.TEST:443", 51002)
        };

        Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), sites));
    }

    [Theory]
    [InlineData("ftp://127.0.0.1:51001")]
    [InlineData("file:///C:/site")]
    public void Validate_RejectsUnsupportedDestinationScheme(string destination)
    {
        var site = CreateSite("one", "example.test", 51001, destination);

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), [site]));

        Assert.Contains("absolute HTTP or HTTPS URI", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectsPublicDestination()
    {
        var site = CreateSite("one", "example.test", 51001, "https://example.com");

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), [site]));

        Assert.Contains("must remain on loopback", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://localhost:10000")]
    [InlineData("http://127.0.0.1:10000")]
    [InlineData("http://[::1]:10000")]
    public void Validate_RejectsEquivalentLoopbackDestinationOnListenerPort(string destination)
    {
        var site = CreateSite("one", "example.test", 10000, destination);

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), [site]));

        Assert.Contains("must not point back", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://0.0.0.0:10000")]
    [InlineData("http://192.0.2.10:10000")]
    [InlineData("http://localhost:10000")]
    [InlineData("ftp://127.0.0.1:10000")]
    public void Validate_RejectsNonLoopbackOrUnsupportedListener(string listener)
    {
        var options = new GatewayOptions { Urls = [listener] };

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(options, [CreateSite("one", "example.test", 51001)]));

        Assert.Contains("loopback HTTP or HTTPS IP", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AcceptsLoopbackListenerAndDistinctDestination()
    {
        GatewayConfigurationValidator.Validate(
            CreateGatewayOptions(),
            [CreateSite("one", "example.test", 51001)]);
    }

    [Fact]
    public void Validate_AcceptsIpv6LoopbackListener()
    {
        var options = new GatewayOptions { Urls = ["http://[::1]:10000"] };

        GatewayConfigurationValidator.Validate(
            options,
            [CreateSite("one", "example.test", 51001)]);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(GatewayOptions.AbsoluteMaximumRequestBytes + 1)]
    public void Validate_RejectsInvalidMaximumRequestBytes(long maximumRequestBytes)
    {
        var options = new GatewayOptions
        {
            Urls = ["http://127.0.0.1:51999"],
            MaximumRequestBytes = maximumRequestBytes
        };

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(
                options,
                [CreateSite("one", "example.test", 51001)]));

        Assert.Contains("MaximumRequestBytes", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AcceptsAbsoluteMaximumRequestBytes()
    {
        var options = new GatewayOptions
        {
            Urls = ["http://127.0.0.1:51999"],
            MaximumRequestBytes = GatewayOptions.AbsoluteMaximumRequestBytes
        };

        GatewayConfigurationValidator.Validate(
            options,
            [CreateSite("one", "example.test", 51001)]);
    }

    [Fact]
    public void Validate_RejectsRealHostAlongsidePlaceholderSite()
    {
        var sites = new[]
        {
            CreateSite("real", "operator-site.tld", 51001),
            CreateSite("leftover", "wordpress-two.example", 51002)
        };

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), sites));

        Assert.Contains("documentation placeholders", exception.Message, StringComparison.Ordinal);
        Assert.Contains("leftover:wordpress-two.example", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Reproduces the observed failure mode: JSON providers merge the nested <c>Hosts</c> array by
    /// index, so an overlay declaring one host leaves the second shipped host alive inside an
    /// otherwise correctly overridden site.
    /// </summary>
    [Fact]
    public void Validate_RejectsPlaceholderSurvivingInsideMergedHostArray()
    {
        var site = CreateSiteWithHosts("site-one", ["operator-site.tld", "www.wordpress-one.example"], 51001);

        var exception = Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), [site]));

        Assert.Contains("merges arrays", exception.Message, StringComparison.Ordinal);
        Assert.Contains("site-one:www.wordpress-one.example", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("wordpress-one.example")]
    [InlineData("www.wordpress-one.example.")]
    [InlineData("EXAMPLE.COM")]
    [InlineData("www.example.org")]
    [InlineData("shop.example.net")]
    public void Validate_TreatsReservedDocumentationNamesAsPlaceholders(string placeholderHost)
    {
        var sites = new[]
        {
            CreateSite("real", "operator-site.tld", 51001),
            CreateSite("placeholder", placeholderHost, 51002)
        };

        Assert.Throws<InvalidOperationException>(
            () => GatewayConfigurationValidator.Validate(CreateGatewayOptions(), sites));
    }

    [Fact]
    public void Validate_AcceptsUntouchedShippedExampleConfiguration()
    {
        var sites = new[]
        {
            CreateSiteWithHosts("wordpress-one", ["wordpress-one.example", "www.wordpress-one.example"], 8081),
            CreateSiteWithHosts("wordpress-two", ["wordpress-two.example", "www.wordpress-two.example"], 8082)
        };

        GatewayConfigurationValidator.Validate(CreateGatewayOptions(), sites);
    }

    [Fact]
    public void Validate_AcceptsFullyOverriddenOperatorConfiguration()
    {
        var sites = new[]
        {
            CreateSiteWithHosts("site-one", ["operator-one.tld", "www.operator-one.tld"], 8081),
            CreateSiteWithHosts("site-two", ["operator-two.tld", "www.operator-two.tld"], 8082)
        };

        GatewayConfigurationValidator.Validate(CreateGatewayOptions(), sites);
    }

    private static GatewayOptions CreateGatewayOptions()
    {
        return new GatewayOptions { Urls = ["http://127.0.0.1:10000"] };
    }

    private static SiteOptions CreateSiteWithHosts(string id, string[] hosts, int destinationPort)
    {
        return new SiteOptions
        {
            Id = id,
            Hosts = hosts,
            Destination = new Uri($"http://127.0.0.1:{destinationPort}"),
            Mode = ProtectionMode.Monitor
        };
    }

    private static SiteOptions CreateSite(
        string id,
        string host,
        int destinationPort,
        string? destination = null)
    {
        return new SiteOptions
        {
            Id = id,
            Hosts = [host],
            Destination = new Uri(destination ?? $"http://127.0.0.1:{destinationPort}"),
            Mode = ProtectionMode.Monitor
        };
    }
}
