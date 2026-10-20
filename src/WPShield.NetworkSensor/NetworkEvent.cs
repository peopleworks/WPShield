namespace WPShield.NetworkSensor;

/// <summary>
/// A single privacy-safe network observation emitted by WPShield.NetworkSensor.
///
/// Only metadata is recorded. The request path excludes its query string, and no
/// Authorization, Cookie, Set-Cookie, body content, or full query string ever appears here.
/// The envelope fields (Timestamp, Level, Category, Message, State, RequestId) mirror the
/// gateway's log envelope so a forensic report and a gateway log correlate on the same names.
/// </summary>
public sealed record NetworkEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Level { get; init; } = string.Empty;
    public required string Category { get; init; } = string.Empty;
    public required string Message { get; init; } = string.Empty;
    public required string State { get; init; } = string.Empty;
    public required string RequestId { get; init; } = string.Empty;
    public required string InterfaceName { get; init; } = string.Empty;
    public required string SourceIp { get; init; } = string.Empty;
    public required string DestinationIp { get; init; } = string.Empty;
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string HttpMethod { get; init; } = string.Empty;
    public required string Path { get; init; } = string.Empty; // query string stripped
    public required int StatusCode { get; init; }
    public required long BodySizeBytes { get; init; }
    public required bool Tls { get; init; }
}
