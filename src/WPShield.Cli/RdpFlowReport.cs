using System.Net;
using WPShield.NetworkSensor;
using WPShield.SecurityMonitor;

namespace WPShield.Cli;

internal sealed record LogonEvidence(int EventId, long RecordId, DateTimeOffset Timestamp);

internal sealed record RdpFlowEvidence(string Local, string Remote, IReadOnlyList<LogonEvidence> Events)
{
    public string Outcome => (Events.Any(e => e.EventId == 4624), Events.Any(e => e.EventId == 4625)) switch
    {
        (true, true) => "mixed",
        (true, false) => "success",
        (false, true) => "failure",
        _ => "unknown"
    };
}

internal sealed record RdpFlowReport(int LocalPort, string AuditStatus, IReadOnlyList<RdpFlowEvidence> Flows)
{
    public string Channel => "Security";
    public DateTimeOffset? WindowStart { get; init; }
    public DateTimeOffset? WindowEnd { get; init; }
    public string? UnavailableReason { get; init; }

    internal static RdpFlowReport Create(FlowSnapshot snapshot, int port, RdpAuditWindow audit)
    {
        var rows = new List<RdpFlowEvidence>();
        var candidates = new Dictionary<IPEndPoint, List<(FlowRow Flow, List<LogonEvidence> Evidence)>>();
        foreach (var flow in snapshot.Flows)
        {
            if (flow.Protocol != "TCP" || !IPEndPoint.TryParse(flow.Local, out var local) || local.Port != port ||
                !IPEndPoint.TryParse(flow.Remote, out var remote)) continue;
            var evidence = new List<LogonEvidence>();
            rows.Add(new(flow.Local, flow.Remote, evidence));
            if (flow.Initiator == "local") continue;
            if (remote.Address.IsIPv4MappedToIPv6) remote = new(remote.Address.MapToIPv4(), remote.Port);
            if (!candidates.TryGetValue(remote, out var group)) candidates.Add(remote, group = []);
            group.Add((flow, evidence));
        }

        foreach (var logon in audit.Events)
        {
            if (!candidates.TryGetValue(logon.Source, out var group)) continue;
            // Windows records the source endpoint but omits the destination address and port.
            // Include midstream candidates when checking ambiguity, even though they cannot prove direction.
            var matches = group.Where(item => item.Flow.FirstSeen <= logon.Timestamp && logon.Timestamp <= item.Flow.LastSeen)
                .Take(2).ToArray();
            if (matches.Length == 1 && matches[0].Flow.Initiator == "remote")
                matches[0].Evidence.Add(new(logon.EventId, logon.RecordId, logon.Timestamp));
        }
        return new(port, audit.Status, rows)
        {
            WindowStart = audit.WindowStart,
            WindowEnd = audit.WindowEnd,
            UnavailableReason = audit.UnavailableReason
        };
    }
}
