using System.Net;
using WPShield.Abstractions;
using WPShield.NetworkFilter;

namespace WPShield.Integration;

/// <summary>
/// Turns a Security-log finding with a Block action into a block request on the network filter.
/// </summary>
/// <remarks>
/// <para>
/// The address comes from the event's own <c>IpAddress</c> field, not from the finding's evidence,
/// and is used for network and remote-interactive failed logons (4625, types 3 and 10). The TCP
/// handshake established the remote address. Everything else - the
/// allow-list, Monitor mode, unblockable addresses such as <c>::1</c> or <c>-</c>, the capacity of the
/// block set - is decided by <see cref="NetworkFilterService.RequestBlock"/>, the one place blocks are
/// created.
/// </para>
/// <para>
/// The standalone CLI enforces operator entries. A consumer must submit current evidence only,
/// and connecting the decision engine requires a separate ADR.
/// </para>
/// </remarks>
public sealed class NetworkFilterBlockListSink : ISecurityEventSink
{
    private readonly NetworkFilterService _filter;

    public NetworkFilterBlockListSink(NetworkFilterService filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        _filter = filter;
    }

    public void Publish(SecurityInspectionResult finding, SecurityInspectionContext context)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(context);

        if (finding.Action != NetworkInspectionAction.Block || context.EventId != 4625 ||
            context.LogonType is not ("3" or "10") ||
            finding.RuleId is not ("WP-SEC-001" or "WP-SEC-002") ||
            !IPAddress.TryParse(context.SourceIp, out var address))
        {
            return;
        }

        _ = _filter.RequestBlock(address, finding.RuleId);
    }
}
