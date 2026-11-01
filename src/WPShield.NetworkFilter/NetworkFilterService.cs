using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using WPShield.Abstractions;
using WPShield.NetworkFilter.Native;
using WPShield.NetworkFilter.Rules;

namespace WPShield.NetworkFilter;

/// <summary>How much an address in a finding can be trusted to be the sender's own.</summary>
public enum EvidenceGrade
{
    /// <summary>The operator named it.</summary>
    Operator,

    /// <summary>A logon failed after a completed TCP handshake, so the address answered packets.</summary>
    Authenticated,

    /// <summary>A connection attempt: a SYN, whose source address anyone can forge.</summary>
    ConnectionAttempt,
}

/// <summary>Reads what the lockout guard needs. Replaceable so the guard can be tested.</summary>
public sealed record LockoutProbe(int RdpPort, IReadOnlyList<TcpConnectionSnapshot> Connections)
{
    public static LockoutProbe ReadFromHost() => new(LockoutGuard.ReadRdpPort(), LockoutGuard.ReadEstablishedConnections());
}

public sealed record StartOutcome(bool Started, string? Refusal, SelfTestReport? SelfTest);

/// <summary>
/// The network filter: the observer, the block set, and - in Block mode only - the enforcer.
/// </summary>
/// <remarks>
/// Start refuses rather than degrades. In Block mode it runs the WinDivert self-test, then the lockout
/// guard, then opens the DROP handles for the operator's blocks, then the observer; any failure stops
/// it with the reason and leaves nothing open. Stopping closes every handle, which lifts every block.
/// </remarks>
public sealed class NetworkFilterService : IDisposable
{
    private const int StateNew = 0;
    private const int StateRunning = 1;
    private const int StateStopped = 2;

    private readonly NetworkFilterOptions _options;
    private readonly IDivertDriver _driver;
    private readonly INetworkFilterEventSink _sink;
    private readonly TimeProvider _time;
    private readonly Func<LockoutProbe> _lockoutProbe;
    private readonly IReadOnlyList<INetworkInspectionRule> _rules;
    private readonly FindingThrottle _throttle;
    private readonly object _maintenanceGate = new();
    private NetworkEnforcer? _enforcer;
    private IDivertHandle? _observer;
    private Thread? _observerThread;
    private ITimer? _timer;
    private long _appliedVersion = -1;
    private int _state = StateNew;

    public NetworkFilterService(
        NetworkFilterOptions options,
        IDivertDriver driver,
        INetworkFilterEventSink sink,
        TimeProvider? time = null,
        Func<LockoutProbe>? lockoutProbe = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(driver);
        ArgumentNullException.ThrowIfNull(sink);

        _options = options;
        _driver = driver;
        _sink = sink;
        _time = time ?? TimeProvider.System;
        _lockoutProbe = lockoutProbe ?? LockoutProbe.ReadFromHost;
        Blocks = new BlockSet(options.AllowList, Math.Clamp(options.MaximumBlocks, 1, BlockSet.MaximumCapacity), _time);
        _rules =
        [
            new RateLimitRule(Math.Max(1, options.MaxConnectionsPerMinute), Math.Max(1, options.MaximumTrackedSources)),
            new PortScanRule(Math.Max(1, options.MaxDistinctPortsPerMinute), Math.Max(1, options.MaximumTrackedSources)),
        ];
        _throttle = new FindingThrottle(Math.Max(1, options.MaximumTrackedSources));
    }

    public BlockSet Blocks { get; }

    public NetworkFilterMode Mode => _options.Mode;

    /// <summary>True only in Block mode, while DROP handles may exist.</summary>
    public bool IsEnforcing
    {
        get
        {
            lock (_maintenanceGate)
            {
                return _enforcer is not null;
            }
        }
    }

    public StartOutcome Start()
    {
        if (Interlocked.CompareExchange(ref _state, StateRunning, StateNew) != StateNew)
        {
            throw new InvalidOperationException("The network filter has already been started.");
        }

        var invalid = _options.Validate();
        if (invalid is not null)
        {
            return Refuse(invalid, null);
        }

        SelfTestReport report;
        try
        {
            report = NetworkFilterSelfTest.Run(_driver, _options.AllowList, _options.Blocks);
        }
        catch (DivertDriverException exception)
        {
            return Refuse(exception.Message, null);
        }

        if (!report.Passed)
        {
            var failures = string.Join("; ", report.Failures.Select(failure =>
                failure.Detail is null ? failure.Name : $"{failure.Name} ({failure.Detail})"));
            if (_options.Mode == NetworkFilterMode.Block)
            {
                return Refuse(
                    $"The WinDivert self-test failed: {failures}. Block mode does not start on filters the library does not evaluate as expected.",
                    report);
            }

            Emit(NetworkFilterEventLevel.Warning, "The WinDivert self-test failed; Block mode would refuse to start.", new()
            {
                ["action"] = NetworkFilterActions.SelfTestFailed,
                ["failures"] = failures,
            });
        }

        if (_options.Mode == NetworkFilterMode.Block)
        {
            var probe = _lockoutProbe();
            var guard = LockoutGuard.Evaluate(probe.RdpPort, probe.Connections, _options.AllowList);
            if (!guard.MayBlock)
            {
                return Refuse(guard.Refusal ?? "Block mode refused by the lockout guard.", report);
            }
        }

        foreach (var block in _options.Blocks)
        {
            _ = Blocks.TryAdd(block, "operator", lifetime: null);
        }

        try
        {
            if (_options.Mode == NetworkFilterMode.Block)
            {
                lock (_maintenanceGate)
                {
                    _enforcer = new NetworkEnforcer(_driver, _options.EnforcerPriority);
                    var applied = ApplyBlocks();
                    if (applied.Status == EnforcementStatus.Failed)
                    {
                        _enforcer.Dispose();
                        _enforcer = null;
                        return Refuse(applied.Error ?? "The DROP filters could not be applied.", report);
                    }
                }
            }

            _observer = _driver.Open(DivertFilterBuilder.ObserverFilter, DivertHandleKind.Observe, _options.ObserverPriority);
        }
        catch (DivertDriverException exception)
        {
            lock (_maintenanceGate)
            {
                _enforcer?.Dispose();
                _enforcer = null;
            }

            return Refuse(exception.Message, report);
        }

        _observerThread = new Thread(ObserveLoop) { IsBackground = true, Name = "WPShield network observer" };
        _observerThread.Start();
        _timer = _time.CreateTimer(_ => Maintain(), null, _options.MaintenanceInterval, _options.MaintenanceInterval);

        Emit(NetworkFilterEventLevel.Information, "Network filter started.", new()
        {
            ["action"] = NetworkFilterActions.Started,
            ["mode"] = _options.Mode.ToString(),
            ["allow_list_entries"] = _options.AllowList.Count,
            ["operator_blocks"] = _options.Blocks.Count,
            ["syn_rules_may_block"] = _options.SynRulesMayBlock,
        });

        return new StartOutcome(true, null, report);
    }

    /// <summary>
    /// Asks for an address to be blocked. Whether it is depends on the mode, the allow-list, the
    /// evidence grade and the block set's capacity; every refusal is logged with its reason.
    /// </summary>
    public BlockAddOutcome? RequestBlock(IPAddress address, string ruleId, EvidenceGrade grade)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var source = address.ToString();
        var now = _time.GetUtcNow();
        var report = grade == EvidenceGrade.Operator || _throttle.ShouldReport("block:" + ruleId, source, 100, now);

        if (!IpRange.TryParseBlock(source, out var range, out _))
        {
            if (report)
            {
                Emit(NetworkFilterEventLevel.Warning, "Not blocked: the address can never be blocked.", Describe(NetworkFilterActions.RefusedUnblockable, ruleId, source));
            }

            return null;
        }

        if (Blocks.IsAllowListed(address))
        {
            if (report)
            {
                Emit(NetworkFilterEventLevel.Warning, "Not blocked: the address is on the allow-list.", Describe(NetworkFilterActions.RefusedAllowListed, ruleId, source));
            }

            return BlockAddOutcome.RefusedAllowListed;
        }

        if (_options.Mode == NetworkFilterMode.Monitor)
        {
            if (report)
            {
                Emit(NetworkFilterEventLevel.Information, "Would block (Monitor mode).", Describe(NetworkFilterActions.WouldBlock, ruleId, source));
            }

            return null;
        }

        if (grade == EvidenceGrade.ConnectionAttempt && !_options.SynRulesMayBlock)
        {
            if (report)
            {
                Emit(
                    NetworkFilterEventLevel.Information,
                    "Not blocked: the evidence is a connection attempt, whose source address can be forged. --syn-rules-may-block allows it.",
                    Describe(NetworkFilterActions.NotBlockedSpoofable, ruleId, source));
            }

            return null;
        }

        if (grade != EvidenceGrade.Operator && !Blocks.IsBlocked(address) && MayBeTheOperatorsSession(address))
        {
            if (report)
            {
                Emit(
                    NetworkFilterEventLevel.Warning,
                    "Not blocked: the address holds a connection to the RDP port right now. Add it to --allow if it is yours.",
                    Describe(NetworkFilterActions.RefusedRdpClient, ruleId, source));
            }

            return null;
        }

        var outcome = Blocks.TryAdd(range!, ruleId, grade == EvidenceGrade.Operator ? null : _options.DynamicBlockLifetime);
        switch (outcome)
        {
            case BlockAddOutcome.Added:
                var state = DescribeBlock(NetworkFilterActions.Blocked, ruleId, source);
                state["lifetime_minutes"] = grade == EvidenceGrade.Operator ? 0 : (int)_options.DynamicBlockLifetime.TotalMinutes;
                Emit(NetworkFilterEventLevel.Warning, "Blocked.", state);
                break;
            case BlockAddOutcome.RefusedFull when report:
                Emit(NetworkFilterEventLevel.Warning, "Not blocked: the block set is full.", Describe(NetworkFilterActions.RefusedFull, ruleId, source));
                break;
            case BlockAddOutcome.RefusedAllowListed when report:
                Emit(NetworkFilterEventLevel.Warning, "Not blocked: the address is on the allow-list.", Describe(NetworkFilterActions.RefusedAllowListed, ruleId, source));
                break;
        }

        return outcome;
    }

    /// <summary>Removes expired blocks and, in Block mode, rebuilds the DROP filters if the set changed.</summary>
    public void Maintain()
    {
        lock (_maintenanceGate)
        {
            if (Volatile.Read(ref _state) != StateRunning)
            {
                return;
            }

            foreach (var expired in Blocks.RemoveExpired())
            {
                Emit(NetworkFilterEventLevel.Information, "Block expired.", DescribeBlock(NetworkFilterActions.Expired, expired.Source, expired.Range.ToString()));
            }

            if (_enforcer is not null && Blocks.Version != _appliedVersion)
            {
                _ = ApplyBlocks();
            }
        }
    }

    /// <summary>Stops observing and closes every DROP handle, lifting every block.</summary>
    public void Stop()
    {
        if (Interlocked.Exchange(ref _state, StateStopped) != StateRunning)
        {
            return;
        }

        _timer?.Dispose();
        _observer?.Shutdown();
        _observerThread?.Join(TimeSpan.FromSeconds(5));
        _observer?.Dispose();

        lock (_maintenanceGate)
        {
            _enforcer?.Dispose();
            _enforcer = null;
        }

        Emit(NetworkFilterEventLevel.Information, "Network filter stopped; every block was lifted with its handle.", new()
        {
            ["action"] = NetworkFilterActions.Stopped,
        });
    }

    public void Dispose() => Stop();

    /// <summary>One packet from the observer. Internal so tests can drive it without a thread.</summary>
    internal void InspectPacket(ReadOnlySpan<byte> packet)
    {
        if (!PacketHeaderParser.TryParse(packet, out var headers) || !headers.Syn || headers.Ack)
        {
            return;
        }

        var source = headers.Source.IsIPv4MappedToIPv6 ? headers.Source.MapToIPv4() : headers.Source;
        if (Blocks.IsAllowListed(source))
        {
            return;
        }

        var context = new NetworkInspectionContext
        {
            SourceIp = source.ToString(),
            DestinationIp = headers.Destination.ToString(),
            SourcePort = headers.SourcePort,
            DestinationPort = headers.DestinationPort,
            Protocol = "TCP",
            Timestamp = _time.GetUtcNow(),
            PacketSize = packet.Length,
        };

        foreach (var rule in _rules)
        {
            var result = rule.Inspect(context);
            if (result.Score == 0)
            {
                continue;
            }

            if (_throttle.ShouldReport(result.RuleId, context.SourceIp, result.Score, context.Timestamp))
            {
                var state = Describe(NetworkFilterActions.Observed, result.RuleId, context.SourceIp);
                state["score"] = result.Score;
                state["destination_port"] = context.DestinationPort;
                foreach (var (key, value) in result.Evidence)
                {
                    if (value is int)
                    {
                        state[key] = value;
                    }
                }

                Emit(NetworkFilterEventLevel.Information, "Connection pattern observed.", state);
            }

            if (result.Action == NetworkInspectionAction.Block)
            {
                _ = RequestBlock(source, result.RuleId, EvidenceGrade.ConnectionAttempt);
            }
        }
    }

    private void ObserveLoop()
    {
        var buffer = new byte[WinDivertNative.MtuMax];
        try
        {
            while (true)
            {
                var length = _observer!.Receive(buffer);
                if (length <= 0)
                {
                    return;
                }

                InspectPacket(buffer.AsSpan(0, length));
            }
        }
        catch (DivertDriverException exception)
        {
            Emit(NetworkFilterEventLevel.Error, "The observer stopped receiving packets. Blocks already in force stay in force.", new()
            {
                ["action"] = NetworkFilterActions.ObserverFailed,
                ["win32_error"] = exception.Win32Error,
            });
        }
        catch (ObjectDisposedException)
        {
            // Stop() closed the handle while a receive was pending.
        }
    }

    private EnforcementResult ApplyBlocks()
    {
        var version = Blocks.Version;
        var snapshot = Blocks.Snapshot();
        var plan = DivertFilterBuilder.BuildDropFilters(snapshot.Select(entry => entry.Range), _options.AllowList);
        if (plan.Excluded.Count > 0)
        {
            Emit(NetworkFilterEventLevel.Error, "Allow-listed entries reached the block set and were left out of enforcement.", new()
            {
                ["action"] = NetworkFilterActions.EnforcementFailed,
                ["excluded"] = string.Join(",", plan.Excluded),
            });
        }

        var result = _enforcer!.Apply(plan);
        switch (result.Status)
        {
            case EnforcementStatus.Applied:
                _appliedVersion = version;
                Emit(NetworkFilterEventLevel.Information, "Enforcement updated.", new()
                {
                    ["action"] = NetworkFilterActions.EnforcementUpdated,
                    ["blocks"] = snapshot.Count,
                    ["drop_handles"] = result.HandleCount,
                });
                break;
            case EnforcementStatus.Unchanged:
                _appliedVersion = version;
                break;
            default:
                Emit(NetworkFilterEventLevel.Error, "Enforcement update failed; the previous blocks stay in force.", new()
                {
                    ["action"] = NetworkFilterActions.EnforcementFailed,
                    ["reason"] = result.Error ?? "unknown",
                });
                break;
        }

        return result;
    }

    private StartOutcome Refuse(string reason, SelfTestReport? report)
    {
        Volatile.Write(ref _state, StateStopped);
        Emit(NetworkFilterEventLevel.Error, "Network filter did not start.", new()
        {
            ["action"] = NetworkFilterActions.Stopped,
            ["reason"] = reason,
        });
        return new StartOutcome(false, reason, report);
    }

    private static Dictionary<string, object> Describe(string action, string ruleId, string source) => new()
    {
        ["action"] = action,
        ["rule_id"] = ruleId,
        ["source_ip"] = source,
    };

    /// <summary>A block-list event: the rule is WP-NET-001, and the finding that asked is named separately.</summary>
    private static Dictionary<string, object> DescribeBlock(string action, string requestedBy, string source) => new()
    {
        ["action"] = action,
        ["rule_id"] = NetworkFilterRuleIds.BlockList,
        ["requested_by"] = requestedBy,
        ["source_ip"] = source,
    };

    /// <summary>
    /// The lockout guard runs at start; this is its live half. The operator may reconnect from a new
    /// address mid-run, so a dynamic block for an address that holds an RDP connection right now is
    /// refused. When the connections cannot be read, the answer is "maybe", which refuses: "nobody
    /// could look" is not "nobody is there".
    /// </summary>
    private bool MayBeTheOperatorsSession(IPAddress address)
    {
        try
        {
            var probe = _lockoutProbe();
            return probe.Connections.Any(connection =>
                connection.Local.Port == probe.RdpPort &&
                (connection.Remote.Address.IsIPv4MappedToIPv6 ? connection.Remote.Address.MapToIPv4() : connection.Remote.Address).Equals(address));
        }
        catch (Exception exception) when (exception is NetworkInformationException or UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return true;
        }
    }

    private void Emit(NetworkFilterEventLevel level, string message, Dictionary<string, object> state)
    {
        try
        {
            _sink.Write(new NetworkFilterEvent(_time.GetUtcNow(), level, message, state));
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException or UnauthorizedAccessException)
        {
            // A failing log must not stop the observer or leave a half-applied enforcement update.
            Console.Error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"WPShield network filter: could not write an event ({exception.GetType().Name})."));
        }
    }
}
