using Xunit;

namespace WPShield.SecurityMonitor.Tests;

public sealed class RdpAuditReaderTests
{
    [Theory]
    [InlineData("-", "49152")]
    [InlineData("1", "49152")]
    [InlineData("::", "123")]
    [InlineData("192.0.2.1", "-")]
    [InlineData("192.0.2.1", "0")]
    [InlineData("192.0.2.1", "65536")]
    public void MissingOrInvalidSourceCannotBecomeAnEndpoint(string address, string port) =>
        Assert.Null(RdpAuditReader.ParseSource(address, port));

    [Fact]
    public void MappedIpv4AndNativeIpv6AreSupported()
    {
        Assert.Equal("192.0.2.1:49152", RdpAuditReader.ParseSource("::ffff:192.0.2.1", "49152")?.ToString());
        Assert.Equal("[2001:db8::1]:65535", RdpAuditReader.ParseSource("2001:db8::1", "65535")?.ToString());
    }
}
