namespace WPShield.NetworkSensor;

using System.Text.Json;

/// <summary>
/// Writes <see cref="NetworkEvent"/> records to a JSON Lines file with rotation and retention.
/// This is the only file the NetworkSensor component writes.
/// </summary>
public sealed class JsonLinesEventSink : INetworkEventSink, IDisposable
{
    private readonly LogRotation _rotation;
    private readonly JsonSerializerOptions _options;

    public JsonLinesEventSink(string outputPath, long maxFileSizeBytes, int retentionDays)
    {
        _rotation = new LogRotation(outputPath, maxFileSizeBytes, retentionDays);

        _options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
            WriteIndented = false,
        };
    }

    /// <summary>
    /// Appends a single event as one JSON line to the output file.
    /// </summary>
    public Task WriteAsync(NetworkEvent @event, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var json = JsonSerializer.Serialize(@event, _options);
        _rotation.Write(json);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Purges rotated files older than the configured retention period.
    /// </summary>
    public void EnforceRetention()
    {
        _rotation.EnforceRetention();
    }

    public void Dispose()
    {
        _rotation.Dispose();
        GC.SuppressFinalize(this);
    }
}
