using System.Collections.Generic;
using WPShield.Abstractions;

namespace WPShield.NetworkFilter.Rules;

/// <summary>
/// Blocks packets whose source IP appears in a dynamic block list.
///
/// The list is maintained externally (for example, by a separate process that parses
/// IIS or firewall logs) and supplied to the rule constructor. This rule performs no
/// file I/O on the packet path; it only checks an in-memory hash set.
/// </summary>
public sealed class BlockListRule : INetworkInspectionRule
{
    private readonly HashSet<string> _blockList;

    public string RuleId => "WP-NET-001";

    public BlockListRule(IEnumerable<string> blockList)
    {
        _blockList = new HashSet<string>(blockList, StringComparer.OrdinalIgnoreCase);
    }

    public NetworkInspectionResult Inspect(
        NetworkInspectionContext context,
        CancellationToken cancellationToken = default)
    {
        bool isBlocked = _blockList.Contains(context.SourceIp);

        return new NetworkInspectionResult
        {
            RuleId = RuleId,
            Score = isBlocked ? 100 : 0,
            Action = isBlocked
                ? WPShield.Abstractions.NetworkInspectionAction.Block
                : WPShield.Abstractions.NetworkInspectionAction.Allow,
            MessageKey = "Findings.NetworkBlockListMatch",
            Evidence = new Dictionary<string, object>
            {
                ["source_ip"] = context.SourceIp,
                ["is_blocked"] = isBlocked,
                ["block_list_count"] = _blockList.Count
            }
        };
    }

    /// <summary>
    /// Atomically replaces the block list contents without blocking the packet path
    /// for longer than a dictionary copy.
    /// </summary>
    public void UpdateBlockList(IEnumerable<string> newList)
    {
        lock (_blockList)
        {
            _blockList.Clear();
            foreach (var ip in newList)
            {
                _blockList.Add(ip);
            }
        }
    }

    /// <summary>
    /// Adds a single source IP to the block list. Thread-safe; safe to call from
    /// a security event sink on the packet path.
    /// </summary>
    public void AddIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        lock (_blockList)
        {
            _blockList.Add(ip);
        }
    }

    /// <summary>
    /// Removes a single source IP from the block list. Thread-safe.
    /// </summary>
    public void RemoveIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        lock (_blockList)
        {
            _blockList.Remove(ip);
        }
    }
}
