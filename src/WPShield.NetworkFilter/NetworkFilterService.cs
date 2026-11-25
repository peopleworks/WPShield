using System.Net;
using System.Net.NetworkInformation;
using System.Security;

namespace WPShield.NetworkFilter;

/// <summary>Reads the configured RDP port and established TCP connections for the lockout guard.</summary>
internal sealed record LockoutProbe(int RdpPort, IReadOnlyList<TcpConnectionSnapshot> Connections)
{
    internal static LockoutProbe ReadFromHost() => new(LockoutGuard.ReadRdpPort(), LockoutGuard.ReadEstablishedConnections());
}

public sealed record StartOutcome(bool Started, string? Refusal);

/// <summary>Owns the block set and one dynamic WFP session in Block mode.</summary>
public sealed class NetworkFilterService : IDisposable
{
    private static readonly TimeSpan MaintenanceInterval = TimeSpan.FromSeconds(5);
    private readonly NetworkFilterOptions _options;
    private readonly string? _configurationError;
    private readonly Func<IWfpSession> _openSession;
    private readonly INetworkFilterEventSink _sink;
    private readonly TimeProvider _time;
    private readonly Func<LockoutProbe> _lockoutProbe;
    private readonly FindingThrottle _throttle = new(10_000);
    private readonly object _gate = new();
    private Dictionary<IpRange, ulong> _filters = [];
    private IWfpSession? _session;
    private ITimer? _timer;
    private bool _started;
    private bool _running;

    public NetworkFilterService(NetworkFilterOptions options, INetworkFilterEventSink sink)
        : this(options, WfpSession.Open, sink)
    {
    }

    internal NetworkFilterService(
        NetworkFilterOptions options,
        Func<IWfpSession> openSession,
        INetworkFilterEventSink sink,
        TimeProvider? time = null,
        Func<LockoutProbe>? lockoutProbe = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(openSession);
        ArgumentNullException.ThrowIfNull(sink);

        _configurationError = options.Validate();
        _options = _configurationError is null
            ? options with { AllowList = [.. options.AllowList], Blocks = [.. options.Blocks] }
            : new NetworkFilterOptions();
        _openSession = openSession;
        _sink = sink;
        _time = time ?? TimeProvider.System;
        _lockoutProbe = lockoutProbe ?? LockoutProbe.ReadFromHost;
        Blocks = new BlockSet(_options.AllowList, _options.MaximumBlocks, _time);
    }

    internal BlockSet Blocks { get; }

    public StartOutcome Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                throw new InvalidOperationException("The network filter can only be started once.");
            }

            _started = true;
            if (_configurationError is not null)
            {
                return Refuse(_configurationError);
            }

            if (_options.Mode == NetworkFilterMode.Block)
            {
                var probe = ReadLockoutProbe();
                if (probe is null)
                {
                    return Refuse("Block mode could not read the RDP port and established connections.");
                }

                var guard = LockoutGuard.Evaluate(probe.RdpPort, probe.Connections, _options.AllowList);
                if (!guard.MayBlock)
                {
                    return Refuse(guard.Refusal ?? "Block mode refused by the RDP lockout guard.");
                }

                try
                {
                    _session = _openSession();
                    var report = NetworkFilterSelfTest.Run(_session, _options.AllowList);
                    if (!report.Passed)
                    {
                        return Refuse(report.Detail);
                    }

                    foreach (var range in _options.Blocks)
                    {
                        _ = Blocks.TryAdd(range, "operator", lifetime: null);
                    }

                    ApplyBlocks();
                    _timer = _time.CreateTimer(_ => Maintain(), null, MaintenanceInterval, MaintenanceInterval);
                }
                catch (WfpException exception)
                {
                    return Refuse(exception.Message);
                }
                catch
                {
                    CloseSession();
                    throw;
                }
            }

            _running = true;
            Emit(NetworkFilterEventLevel.Information, "Network filter started.", new()
            {
                ["action"] = NetworkFilterActions.Started,
                ["mode"] = _options.Mode.ToString(),
                ["allow_list_entries"] = _options.AllowList.Count,
                ["operator_blocks"] = _options.Blocks.Count,
            });

            foreach (var range in _options.Mode == NetworkFilterMode.Monitor ? _options.Blocks.Distinct() : _filters.Keys)
            {
                ReportBlock(range, "operator", lifetime: null);
            }

            return new StartOutcome(true, null);
        }
    }

    /// <summary>Accepts an address confirmed by a TCP handshake in a trusted log source.</summary>
    public BlockAddOutcome? RequestBlock(IPAddress address, string ruleId)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);

        lock (_gate)
        {
            if (!_running)
            {
                return null;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            var source = address.ToString();
            var report = _throttle.ShouldReport(ruleId, source, _time.GetUtcNow());
            if (!IpRange.TryParseBlock(source, out var range, out _) || range is null)
            {
                ReportRefusal(report, NetworkFilterActions.RefusedUnblockable, "The address cannot be blocked.", ruleId, source);
                return null;
            }

            if (Blocks.IsAllowListed(address))
            {
                ReportRefusal(report, NetworkFilterActions.RefusedAllowListed, "The address is allow-listed.", ruleId, source);
                return BlockAddOutcome.RefusedAllowListed;
            }

            if (_options.Mode == NetworkFilterMode.Monitor)
            {
                if (report)
                {
                    ReportBlock(range, ruleId, _options.DynamicBlockLifetime);
                }

                return null;
            }

            if (!Blocks.IsBlocked(address) && MayBeRdpClient(address))
            {
                ReportRefusal(report, NetworkFilterActions.RefusedRdpClient,
                    "The address has an RDP connection or the connection list could not be verified.", ruleId, source);
                return null;
            }

            var outcome = Blocks.TryAdd(range, ruleId, _options.DynamicBlockLifetime);
            if (outcome == BlockAddOutcome.RefusedFull)
            {
                ReportRefusal(report, NetworkFilterActions.RefusedFull, "The block set is full.", ruleId, source);
            }
            else if (outcome == BlockAddOutcome.Added)
            {
                if (!TryApplyBlocks())
                {
                    return null;
                }

                ReportBlock(range, ruleId, _options.DynamicBlockLifetime);
            }

            return outcome;
        }
    }

    internal void Maintain()
    {
        lock (_gate)
        {
            if (!_running)
            {
                return;
            }

            var expired = Blocks.RemoveExpired();
            if (expired.Count == 0 || !TryApplyBlocks())
            {
                return;
            }

            foreach (var entry in expired)
            {
                Emit(NetworkFilterEventLevel.Information, "Block expired.",
                    DescribeBlock(NetworkFilterActions.Expired, entry.Source, entry.Range.ToString()));
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _started = true;
            if (!_running)
            {
                return;
            }

            CloseSession();
            Emit(NetworkFilterEventLevel.Information, "Network filter stopped.", new()
            {
                ["action"] = NetworkFilterActions.Stopped,
            });
        }
    }

    private void ApplyBlocks()
    {
        var session = _session!;
        var desired = WfpFilterBuilder.SelectBlocks(Blocks.Snapshot().Select(entry => entry.Range), _options.AllowList).ToHashSet();
        var removals = _filters.Keys.Except(desired).ToArray();
        var additions = desired.Except(_filters.Keys).ToArray();
        if (removals.Length == 0 && additions.Length == 0)
        {
            return;
        }

        var next = new Dictionary<IpRange, ulong>(_filters);
        session.Update(() =>
        {
            foreach (var range in removals)
            {
                session.Delete(next[range]);
                _ = next.Remove(range);
            }

            foreach (var range in additions)
            {
                next.Add(range, session.Add(range));
            }
        });
        _filters = next;
    }

    private bool TryApplyBlocks()
    {
        try
        {
            ApplyBlocks();
            return true;
        }
        catch (WfpException exception)
        {
            CloseSession();
            Emit(NetworkFilterEventLevel.Error, "A WFP update failed and the dynamic session was closed.", new()
            {
                ["action"] = NetworkFilterActions.EnforcementFailed,
                ["reason"] = exception.Message,
            });
            return false;
        }
    }

    private void CloseSession()
    {
        _running = false;
        _timer?.Dispose();
        _timer = null;
        _session?.Dispose();
        _session = null;
        _filters.Clear();
    }

    private StartOutcome Refuse(string reason)
    {
        CloseSession();
        Emit(NetworkFilterEventLevel.Error, "Network filter did not start.", new()
        {
            ["action"] = NetworkFilterActions.Stopped,
            ["reason"] = reason,
        });
        return new StartOutcome(false, reason);
    }

    private LockoutProbe? ReadLockoutProbe()
    {
        try
        {
            return _lockoutProbe();
        }
        catch (Exception exception) when (exception is NetworkInformationException or UnauthorizedAccessException or SecurityException or IOException)
        {
            return null;
        }
    }

    private bool MayBeRdpClient(IPAddress address)
    {
        var probe = ReadLockoutProbe();
        return probe is null || probe.Connections.Any(connection => connection.Local.Port == probe.RdpPort &&
            (connection.Remote.Address.IsIPv4MappedToIPv6 ? connection.Remote.Address.MapToIPv4() : connection.Remote.Address).Equals(address));
    }

    private void ReportBlock(IpRange range, string requestedBy, TimeSpan? lifetime)
    {
        var monitor = _options.Mode == NetworkFilterMode.Monitor;
        var state = DescribeBlock(monitor ? NetworkFilterActions.WouldBlock : NetworkFilterActions.Blocked, requestedBy, range.ToString());
        state["lifetime_minutes"] = (int)(lifetime?.TotalMinutes ?? 0);
        Emit(monitor ? NetworkFilterEventLevel.Information : NetworkFilterEventLevel.Warning,
            monitor ? "Would block (Monitor mode)." : "Blocked by WFP.", state);
    }

    private void ReportRefusal(bool report, string action, string message, string ruleId, string source)
    {
        if (report)
        {
            Emit(NetworkFilterEventLevel.Warning, message, new()
            {
                ["action"] = action,
                ["rule_id"] = ruleId,
                ["source_ip"] = source,
            });
        }
    }

    private static Dictionary<string, object> DescribeBlock(string action, string requestedBy, string source) => new()
    {
        ["action"] = action,
        ["rule_id"] = NetworkFilterRuleIds.BlockList,
        ["requested_by"] = requestedBy,
        ["source_ip"] = source,
    };

    private void Emit(NetworkFilterEventLevel level, string message, Dictionary<string, object> state)
    {
        try
        {
            _sink.Write(new NetworkFilterEvent(_time.GetUtcNow(), level, message, state));
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
            // The event sink may become unavailable independently of the filtering session.
        }
    }
}
