using System.Collections.Generic;
using WPShield.Abstractions;
using WPShield.NetworkFilter.Rules;

namespace WPShield.Integration;

/// <summary>
/// <see cref="ISecurityEventSink"/> implementation that publishes security findings
/// to a <see cref="BlockListRule"/>, so IPs detected by
/// <see cref="WPShield.SecurityMonitor"/> (RDP brute force, failed logons, etc.) are
/// blocked at the packet layer by <see cref="WPShield.NetworkFilter.NetworkFilterEngine"/>.
///
/// Use this sink when you want <see cref="WPShield.SecurityMonitor.SecurityEventMonitor"/>
/// to feed <see cref="WPShield.NetworkFilter.Rules.BlockListRule"/> automatically.
/// </summary>
public sealed class NetworkFilterBlockListSink : ISecurityEventSink
{
    private readonly BlockListRule _blockListRule;
    private readonly HashSet<string> _pendingIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>
    /// Creates a sink that adds blocking source IPs to <paramref name="blockListRule"/>.
    /// </summary>
    public NetworkFilterBlockListSink(BlockListRule blockListRule)
    {
        _blockListRule = blockListRule ?? throw new System.ArgumentNullException(nameof(blockListRule));
    }

    /// <summary>
    /// Publishes a security finding. If the finding's action is <see cref="WPShield.Abstractions.NetworkInspectionAction.Block"/>
    /// and the evidence contains a <c>source_ip</c>, that IP is added to the pending block list
    /// and immediately applied to <see cref="BlockListRule"/>.
    /// </summary>
    public void Publish(
        WPShield.Abstractions.SecurityInspectionResult finding,
        WPShield.Abstractions.SecurityInspectionContext context)
    {
        if (finding.Action != WPShield.Abstractions.NetworkInspectionAction.Block)
        {
            return;
        }

        if (!finding.Evidence.TryGetValue("source_ip", out var sourceIpObj) ||
            sourceIpObj is not string sourceIp ||
            string.IsNullOrWhiteSpace(sourceIp))
        {
            return;
        }

        lock (_lock)
        {
            if (_pendingIps.Add(sourceIp))
            {
                // Apply immediately so the network filter starts dropping the IP without delay.
                _blockListRule.AddIp(sourceIp);
            }
        }
    }

    /// <summary>
    /// Returns the IPs currently pending in this sink (not yet flushed to the rule).
    /// </summary>
    public IReadOnlyCollection<string> PendingIps
    {
        get
        {
            lock (_lock)
            {
                return new HashSet<string>(_pendingIps, StringComparer.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>
    /// Clears the pending set without touching the block list rule.
    /// </summary>
    public void ClearPending()
    {
        lock (_lock)
        {
            _pendingIps.Clear();
        }
    }
}
