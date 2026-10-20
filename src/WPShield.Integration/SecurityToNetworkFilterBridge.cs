using WPShield.Abstractions;
using WPShield.NetworkFilter;
using WPShield.NetworkFilter.Rules;
using WPShield.SecurityMonitor;
using WPShield.SecurityMonitor.Rules;

namespace WPShield.Integration;

/// <summary>
/// Convenience bridge that wires <see cref="SecurityEventMonitor"/> to
/// <see cref="WPShield.NetworkFilter.Rules.BlockListRule"/> through
/// <see cref="NetworkFilterBlockListSink"/>.
///
/// Use this when you want security event findings (for example, RDP brute force
/// detected by <see cref="RdpBruteForceRule"/>) to automatically block the offending
/// IP at the packet layer via <see cref="WPShield.NetworkFilter.NetworkFilterEngine"/>.
/// </summary>
public sealed class SecurityToNetworkFilterBridge : IDisposable
{
    private readonly SecurityEventConfiguration _securityConfig;
    private readonly NetworkFilterConfiguration _networkConfig;
    private readonly SecurityEventMonitor _monitor;
    private readonly NetworkFilterEngine _filterEngine;
    private readonly BlockListRule _blockListRule;
    private readonly NetworkFilterBlockListSink _sink;
    private bool _disposed;

    public SecurityToNetworkFilterBridge(
        SecurityEventConfiguration? securityConfig = null,
        NetworkFilterConfiguration? networkConfig = null)
    {
        _securityConfig = securityConfig ?? new SecurityEventConfiguration
        {
            MaxFailedLogonsPerWindow = 5,
            WindowMinutes = 5,
            PublishingEnabled = true
        };

        _networkConfig = networkConfig ?? new NetworkFilterConfiguration
        {
            Filter = "tcp.Inbound",
            MaxInspectionTime = TimeSpan.FromMilliseconds(5),
            MaxConnectionsPerMinute = 60,
            MaxDistinctPortsPerMinute = 20,
            BlockList = new List<string>()
        };

        // Block list rule starts empty; the sink populates it from security findings.
        _blockListRule = new BlockListRule(_networkConfig.BlockList);

        // Network filter engine includes the block list rule by default via the builder.
        // We rebuild the rule list manually so the block list rule is the same instance
        // the sink writes to.
        var rules = new List<INetworkInspectionRule>
        {
            _blockListRule,
            new RateLimitRule(_networkConfig.MaxConnectionsPerMinute),
            new PortScanRule(_networkConfig.MaxDistinctPortsPerMinute)
        };

        _filterEngine = new NetworkFilterEngine(rules, _networkConfig.Filter, _networkConfig.MaxInspectionTime);

        _sink = new NetworkFilterBlockListSink(_blockListRule);

        _monitor = SecurityEventBuilder.Build(
            _securityConfig,
            extraRules: null,
            sink: _sink);
    }

    /// <summary>
    /// The <see cref="BlockListRule"/> instance shared between the security sink and
    /// the network filter engine. Operators can inspect or modify it directly.
    /// </summary>
    public BlockListRule BlockListRule => _blockListRule;

    /// <summary>
    /// The <see cref="SecurityEventMonitor"/> instance. Operators can call
    /// <see cref="SecurityEventMonitor.ScanOnce"/> on their own schedule.
    /// </summary>
    public SecurityEventMonitor SecurityMonitor => _monitor;

    /// <summary>
    /// The <see cref="NetworkFilterEngine"/> instance. Operators can call
    /// <see cref="NetworkFilterEngine.Run"/> to start the capture loop.
    /// </summary>
    public NetworkFilterEngine NetworkFilterEngine => _filterEngine;

    /// <summary>
    /// Scans the Security event log once and applies any new block-listed IPs to the
    /// network filter.
    /// </summary>
    public int ScanSecurityLogOnce() => _monitor.ScanOnce();

    public void Dispose()
    {
        if (!_disposed)
        {
            _monitor.Dispose();
            _filterEngine.Dispose();
            _disposed = true;
        }
    }
}
