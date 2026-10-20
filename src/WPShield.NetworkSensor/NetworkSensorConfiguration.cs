namespace WPShield.NetworkSensor;

/// <summary>
/// Configuration for WPShield.NetworkSensor, a passive network metadata capture component.
///
/// All values are operator-supplied. The sensor captures nothing until <see cref="Enabled"/> is
/// <c>true</c> and <see cref="Ports"/> contains at least one port.
/// </summary>
public sealed class NetworkSensorConfiguration
{
    /// <summary>
    /// Whether the sensor is allowed to capture. Defaults to <c>false</c>: zero packets observed.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Optional list of network interface names to capture from. Empty means all interfaces that
    /// match the port filter.
    /// </summary>
    public IReadOnlyList<string> Interfaces { get; init; } = [];

    /// <summary>
    /// Ports to capture, for example 80 and 443. Mandatory when <see cref="Enabled"/> is true.
    /// An empty list means capture nothing.
    /// </summary>
    public IReadOnlyList<int> Ports { get; init; } = [];

    /// <summary>
    /// Whether to capture in promiscuous mode. Defaults to <c>false</c>; enabling it is an
    /// explicit operator choice and is logged as a blocker-level event.
    /// </summary>
    public bool PromiscuousMode { get; init; }

    /// <summary>
    /// Maximum events emitted per second, used as a token bucket so the sensor cannot amplify
    /// noise. Defaults to 1000.
    /// </summary>
    public int MaxEventsPerSecond { get; init; } = 1000;

    /// <summary>
    /// Path to the JSON Lines output file. This is the only file the sensor writes.
    /// </summary>
    public string OutputPath { get; init; } = string.Empty;

    /// <summary>
    /// Rotation and retention for the output file.
    /// </summary>
    public RotationConfiguration Rotation { get; init; } = new();
}

/// <summary>
/// Rotation and retention settings for the NetworkSensor output file.
/// </summary>
public sealed class RotationConfiguration
{
    /// <summary>
    /// Maximum file size in bytes before rotation. Defaults to 100 MiB.
    /// </summary>
    public long MaxFileSizeBytes { get; init; } = 100_000_000;

    /// <summary>
    /// Number of days to retain rotated files. Defaults to 30.
    /// </summary>
    public int RetentionDays { get; init; } = 30;
}
