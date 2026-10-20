namespace WPShield.NetworkSensor;

/// <summary>
/// Passive network metadata capture. Starts and stops on explicit operator command; never blocks
/// traffic and never modifies IIS.
/// </summary>
public interface INetworkSensor : IAsyncDisposable
{
    /// <summary>
    /// Begins capturing on the configured interfaces and ports. Fails closed (throws) if Npcap is
    /// missing, elevation is absent, or configuration is invalid.
    /// </summary>
    Task StartAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Stops capturing and flushes the output sink.
    /// </summary>
    Task StopAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Whether the sensor is currently capturing.
    /// </summary>
    bool IsRunning { get; }
}
