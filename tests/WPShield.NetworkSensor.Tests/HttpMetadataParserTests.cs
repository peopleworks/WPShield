using Xunit;

namespace WPShield.NetworkSensor.Tests;

public class HttpMetadataParserTests
{
    private static byte[] ToBytes(string s) =>
        System.Text.Encoding.UTF8.GetBytes(s);

    [Fact]
    public void ParsesGetRequestLine()
    {
        var buffer = ToBytes("GET /wp-admin/admin-ajax.php HTTP/1.1\r\nHost: example\r\n\r\n");
        var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);

        Assert.NotNull(metadata);
        Assert.True(metadata.IsRequest);
        Assert.Equal("GET", metadata.HttpMethod);
        Assert.Equal("/wp-admin/admin-ajax.php", metadata.Path);
        Assert.Null(metadata.StatusCode);
    }

    [Fact]
    public void StripsQueryStringFromPath()
    {
        var buffer = ToBytes("POST /wp-login.php?redirect-to=/wp-admin/ HTTP/1.1\r\nHost: example\r\n\r\n");
        var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);

        Assert.NotNull(metadata);
        Assert.Equal("/wp-login.php", metadata.Path);
    }

    [Fact]
    public void ParsesStatusLine()
    {
        var buffer = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n");
        var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);

        Assert.NotNull(metadata);
        Assert.False(metadata.IsRequest);
        Assert.Equal(200, metadata.StatusCode);
    }

    [Fact]
    public void ParsesContentLength()
    {
        var buffer = ToBytes("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n");
        var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);

        Assert.NotNull(metadata);
        Assert.Equal(1024L, metadata.BodySizeBytes);
    }

    [Fact]
    public void NonHttpPayloadReturnsNull()
    {
        var buffer = ToBytes("not http at all\r\n");
        var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);

        Assert.Null(metadata);
    }

    [Fact]
    public void EmptyBufferReturnsNull()
    {
        var metadata = HttpMetadataParser.TryParse(Array.Empty<byte>(), 0, 0);
        Assert.Null(metadata);
    }

    [Fact]
    public void UnknownMethodReturnsNull()
    {
        var buffer = ToBytes("FOO /path HTTP/1.1\r\n");
        var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);
        Assert.Null(metadata);
    }

    [Fact]
    public void AllKnownMethodsAreRecognized()
    {
        foreach (var method in new[] { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT" })
        {
            var line = $"{method} /path HTTP/1.1\r\n";
            var buffer = ToBytes(line);
            var metadata = HttpMetadataParser.TryParse(buffer, 0, buffer.Length);
            Assert.NotNull(metadata);
            Assert.Equal(method, metadata.HttpMethod);
        }
    }
}
