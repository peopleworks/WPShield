namespace WPShield.Abstractions;

/// <summary>
/// Context presented to security inspection rules. All fields are read from the Windows
/// Security event log and are attacker-controlled where they originate from the network.
/// </summary>
public sealed record SecurityInspectionContext
{
    public required int EventId { get; init; }
    public required string SourceIp { get; init; } = string.Empty;
    public required string UserName { get; init; } = string.Empty;
    public required string LogonType { get; init; } = string.Empty;
    public required string ProcessName { get; init; } = string.Empty;
    public required string ComputerName { get; init; } = string.Empty;
    public required DateTimeOffset TimeCreated { get; init; }
    public required string Message { get; init; } = string.Empty;
}
