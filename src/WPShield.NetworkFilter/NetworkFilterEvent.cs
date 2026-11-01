namespace WPShield.NetworkFilter;

/// <summary>
/// One thing the network filter did or would have done. Rendered by the CLI in the gateway's log
/// envelope - <c>timestamp, level, category, message, state</c> - so one parser reads every WPShield log.
/// </summary>
/// <remarks>
/// <see cref="Message"/> is always a fixed sentence written here, never text taken from a packet or a
/// log record. <see cref="State"/> holds normalized values only: rule IDs, printed IP addresses,
/// numbers, and the fixed action vocabulary below.
/// </remarks>
public sealed record NetworkFilterEvent(
    DateTimeOffset Timestamp,
    NetworkFilterEventLevel Level,
    string Message,
    IReadOnlyDictionary<string, object> State)
{
    public const string Category = "WPShield.NetworkFilter";
}

public enum NetworkFilterEventLevel
{
    Information,
    Warning,
    Error,
}

/// <summary>Where events go. Implementations must not throw back into the observer.</summary>
public interface INetworkFilterEventSink
{
    void Write(NetworkFilterEvent networkFilterEvent);
}

/// <summary>Rule identifiers the network filter emits itself.</summary>
public static class NetworkFilterRuleIds
{
    /// <summary>
    /// <c>WP-NET-001</c>: an address on the block list. Carried by <c>blocked</c> and <c>expired</c>
    /// events, with the finding that asked for the block in <c>requested_by</c>.
    /// </summary>
    public const string BlockList = "WP-NET-001";
}

/// <summary>The fixed vocabulary of the <c>action</c> state field.</summary>
public static class NetworkFilterActions
{
    public const string Started = "started";
    public const string Stopped = "stopped";
    public const string SelfTestFailed = "self-test-failed";
    public const string Observed = "observed";
    public const string WouldBlock = "would-block";
    public const string NotBlockedSpoofable = "not-blocked-spoofable-evidence";
    public const string Blocked = "blocked";
    public const string Expired = "expired";
    public const string RefusedAllowListed = "refused-allow-listed";
    public const string RefusedFull = "refused-block-set-full";
    public const string RefusedUnblockable = "refused-unblockable-address";
    public const string RefusedRdpClient = "refused-rdp-client";
    public const string EnforcementUpdated = "enforcement-updated";
    public const string EnforcementFailed = "enforcement-failed";
    public const string ObserverFailed = "observer-failed";
}
