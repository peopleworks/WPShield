using System.Threading;
using Xunit;

namespace WPShield.NetworkSensor.Tests;

public class JsonLinesEventSinkTests : IDisposable
{
    private readonly string _tempFile;
    private readonly JsonLinesEventSink _sink;

    public JsonLinesEventSinkTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"wpshield-network-test-{Guid.NewGuid():n}.ndjson");
        _sink = new JsonLinesEventSink(_tempFile, maxFileSizeBytes: 1_048_576, retentionDays: 1);
    }

    [Fact]
    public async Task WritesEventAsJsonLine()
    {
        var @event = new NetworkEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Level = "Information",
            Category = "WPShield.NetworkSensor",
            Message = "GET /wp-admin/",
            State = "request_observed",
            RequestId = "test-id-123",
            InterfaceName = "Ethernet",
            SourceIp = "192.0.2.10",
            DestinationIp = "192.0.2.1",
            SourcePort = 51422,
            DestinationPort = 443,
            HttpMethod = "GET",
            Path = "/wp-admin/",
            StatusCode = 200,
            BodySizeBytes = 1234,
            Tls = true,
        };

        await _sink.WriteAsync(@event, CancellationToken.None);
        _sink.Dispose();

        var lines = File.ReadAllLines(_tempFile);
        Assert.Single(lines);

        var json = lines[0];
        Assert.Contains("\"message\":\"GET /wp-admin/\"", json);
        Assert.Contains("\"state\":\"request_observed\"", json);
        Assert.Contains("\"path\":\"/wp-admin/\"", json);
        Assert.Contains("\"statusCode\":200", json);
        Assert.Contains("\"tls\":true", json);
    }

    [Fact]
    public async Task MultipleEventsAreAppended()
    {
        var e1 = new NetworkEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Level = "Information",
            Category = "WPShield.NetworkSensor",
            Message = "first",
            State = "observed",
            RequestId = "id-1",
            InterfaceName = "Ethernet",
            SourceIp = "192.0.2.1",
            DestinationIp = "192.0.2.2",
            SourcePort = 1000,
            DestinationPort = 443,
            HttpMethod = "GET",
            Path = "/a",
            StatusCode = 200,
            BodySizeBytes = 10,
            Tls = false,
        };
        var e2 = new NetworkEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Level = "Information",
            Category = "WPShield.NetworkSensor",
            Message = "second",
            State = "observed",
            RequestId = "id-2",
            InterfaceName = "Ethernet",
            SourceIp = "192.0.2.1",
            DestinationIp = "192.0.2.2",
            SourcePort = 1001,
            DestinationPort = 443,
            HttpMethod = "POST",
            Path = "/b",
            StatusCode = 201,
            BodySizeBytes = 20,
            Tls = false,
        };

        await _sink.WriteAsync(e1, CancellationToken.None);
        await _sink.WriteAsync(e2, CancellationToken.None);
        _sink.Dispose();

        var lines = File.ReadAllLines(_tempFile);
        Assert.Equal(2, lines.Length);
    }

    public void Dispose()
    {
        _sink.Dispose();
        try { File.Delete(_tempFile); } catch { }
        GC.SuppressFinalize(this);
    }
}
