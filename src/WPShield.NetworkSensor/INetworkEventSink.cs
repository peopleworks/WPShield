namespace WPShield.NetworkSensor;

/// <summary>
/// Writes <see cref="NetworkEvent"/> records to durable storage. The sensor makes exactly one
/// write: to this sink.
/// </summary>
public interface INetworkEventSink : IDisposable
{
    /// <summary>
    /// Appends a single event to the JSON Lines output.
    /// </summary>
    Task WriteAsync(NetworkEvent @event, CancellationToken cancellationToken);
}
