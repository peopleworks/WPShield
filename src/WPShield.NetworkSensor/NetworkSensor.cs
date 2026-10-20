namespace WPShield.NetworkSensor;

using System.Diagnostics;

/// <summary>
/// WPShield.NetworkSensor orchestration.
///
/// Starts and stops passive network metadata capture on operator-named ports. Every observed
/// HTTP request/response is emitted as a privacy-safe <see cref="NetworkEvent"/> to the JSON
/// Lines sink. The sensor never blocks traffic and never modifies IIS.
/// </summary>
public sealed class NetworkSensor : INetworkSensor, IDisposable
{
    private readonly NetworkSensorConfiguration _configuration;
    private readonly INetworkEventSink _sink;
    private readonly RateLimiter _rateLimiter;
    private readonly PcapCapture? _capture;
    private readonly ActivitySource _activitySource = new("WPShield.NetworkSensor");
    private bool _isRunning;
    private long _eventsDroppedByRateLimit;

    public NetworkSensor(NetworkSensorConfiguration configuration, INetworkEventSink sink)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));

        NetworkSensorConfigurationValidator.Validate(configuration);

        _rateLimiter = new RateLimiter(configuration.MaxEventsPerSecond);

        _capture = configuration.Enabled
            ? new PcapCapture(configuration.Interfaces, configuration.Ports, configuration.PromiscuousMode, OnTcpPayload)
            : null;

        IsRunning = false;
    }

    /// <summary>
    /// Whether the sensor is currently capturing packets.
    /// </summary>
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (_isRunning != value)
            {
                _isRunning = value;
                IsRunningChanged?.Invoke(this, value);
            }
        }
    }

    /// <summary>
    /// Fired when the running state changes. Used by hosts to reflect status in UIs or logs.
    /// </summary>
    public event EventHandler<bool>? IsRunningChanged;

    /// <summary>
    /// Number of events dropped by the rate limiter since the sensor started.
    /// </summary>
    public long EventsDroppedByRateLimit => _eventsDroppedByRateLimit;

    /// <summary>
    /// Begins capturing. Fails closed if Npcap is missing, elevation is absent, or any device
    /// cannot be opened.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_configuration.Enabled)
        {
            return Task.CompletedTask;
        }

        if (_capture is null)
        {
            throw new InvalidOperationException("NetworkSensor capture instance was not created.");
        }

        if (IsRunning)
        {
            return Task.CompletedTask;
        }

        using var activity = _activitySource.StartActivity("NetworkSensor.Start");

        _capture.Start();
        IsRunning = true;

        activity?.SetTag("networksensor.interfaces", string.Join(",", _configuration.Interfaces));
        activity?.SetTag("networksensor.ports", string.Join(",", _configuration.Ports));
        activity?.SetTag("networksensor.promiscuous", _configuration.PromiscuousMode);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Stops capturing and flushes the output sink.
    /// </summary>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsRunning)
        {
            return Task.CompletedTask;
        }

        using var activity = _activitySource.StartActivity("NetworkSensor.Stop");

        _capture!.Stop();
        IsRunning = false;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Forces retention enforcement: purges rotated files older than the configured retention.
    /// </summary>
    public void EnforceRetention()
    {
        if (_sink is JsonLinesEventSink jsonSink)
        {
            jsonSink.EnforceRetention();
        }
    }

    private void OnTcpPayload(byte[] buffer, int offset, int length)
    {
        if (!IsRunning)
        {
            return;
        }

        // Rate limit: drop events when the bucket is empty.
        if (!_rateLimiter.TryConsume())
        {
            Interlocked.Increment(ref _eventsDroppedByRateLimit);
            return;
        }

        var metadata = HttpMetadataParser.TryParse(buffer, offset, length);
        if (metadata is null)
        {
            return;
        }

        var @event = new NetworkEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Level = "Information",
            Category = "WPShield.NetworkSensor",
            Message = metadata.IsRequest
                ? $"HTTP {metadata.HttpMethod} {metadata.Path}"
                : $"HTTP response {metadata.StatusCode}",
            State = metadata.IsRequest ? "request_observed" : "response_observed",
            RequestId = Activity.Current?.Id ?? Guid.NewGuid().ToString("n"),
            InterfaceName = string.Empty, // populated by host if interface info is available
            SourceIp = string.Empty,      // populated by host if IP info is available
            DestinationIp = string.Empty, // populated by host if IP info is available
            SourcePort = 0,
            DestinationPort = 0,
            HttpMethod = metadata.HttpMethod,
            Path = metadata.Path,
            StatusCode = metadata.StatusCode ?? 0,
            BodySizeBytes = metadata.BodySizeBytes ?? 0,
            Tls = false, // populated by host if TLS handshake metadata is available
        };

        _sink.WriteAsync(@event, CancellationToken.None).GetAwaiter().GetResult();
    }

    public ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            StopAsync(CancellationToken.None).GetAwaiter().GetResult();
            _sink.Dispose();
            _activitySource.Dispose();
            _disposed = true;
        }
        return ValueTask.CompletedTask;
    }

    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
        GC.SuppressFinalize(this);
    }

    private bool _disposed;
}
