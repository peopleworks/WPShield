using System.Diagnostics.Eventing.Reader;
using WPShield.Abstractions;

namespace WPShield.SecurityMonitor;

/// <summary>
/// Monitors the Windows Security event log for authentication failures and other security
/// events, evaluates them against configured rules, and publishes findings to a sink.
///
/// Design constraint: this monitor runs in user mode and only reads the Security log. It
/// never modifies, clears, or archives the log. If elevation is absent, it refuses to start
/// rather than running in a degraded mode.
/// </summary>
public sealed class SecurityEventMonitor : IDisposable
{
    private readonly SecurityEventConfiguration _configuration;
    private readonly IEnumerable<ISecurityInspectionRule> _rules;
    private readonly ISecurityEventSink _sink;
    private readonly WinEventLogReader _reader;
    private bool _disposed;

    /// <summary>
    /// Creates a monitor that reads the Security log and publishes findings to <paramref name="sink"/>.
    /// </summary>
    public SecurityEventMonitor(
        SecurityEventConfiguration configuration,
        IEnumerable<ISecurityInspectionRule> rules,
        ISecurityEventSink sink)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));

        _reader = new WinEventLogReader(configuration.LogName, configuration.EventIds);
    }

    /// <summary>
    /// Reads all currently available matching events from the Security log, evaluates them
    /// against the rules, and publishes any findings. Returns the number of events processed.
    /// </summary>
    public int ScanOnce()
    {
        int processed = 0;

        foreach (var record in _reader.ReadAvailable())
        {
            processed++;

            var context = SecurityEventContextBuilder.Build(record);

            // Skip allow-listed source IPs.
            if (!string.IsNullOrEmpty(context.SourceIp) &&
                _configuration.AllowList.Contains(context.SourceIp, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var rule in _rules)
            {
                var result = rule.Inspect(context, CancellationToken.None);

                if (result.Action == NetworkInspectionAction.Block ||
                    result.Action == NetworkInspectionAction.Observe)
                {
                    if (_configuration.PublishingEnabled)
                    {
                        _sink.Publish(result, context);
                    }
                }
            }
        }

        return processed;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _reader.Dispose();
            _disposed = true;
        }
    }
}
