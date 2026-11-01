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
/// and is handed over as <see cref="EvidenceGrade.Authenticated"/>: a logon fails after the TCP
/// handshake completed, so the address answered packets and was not forged. Everything else - the
/// allow-list, Monitor mode, unblockable addresses such as <c>::1</c> or <c>-</c>, the capacity of the
/// block set - is decided by <see cref="NetworkFilterService.RequestBlock"/>, the one place blocks are
/// created.
/// </para>
/// <para>
/// Not wired to the CLI yet. The Security-log reader replays the whole log on start and holds it in
/// memory; feeding that into a blocker would block every address that ever failed a logon. It is wired
/// once the reader subscribes to new events only (ADR 0002's "subscribe, do not read files").
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

        if (finding.Action != NetworkInspectionAction.Block ||
            !IPAddress.TryParse(context.SourceIp, out var address))
        {
            return;
        }

        _ = _filter.RequestBlock(address, finding.RuleId, EvidenceGrade.Authenticated);
    }
}
