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

    private static GatewayOptions CreateGatewayOptions()
    {
        return new GatewayOptions { Urls = ["http://127.0.0.1:10000"] };
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
