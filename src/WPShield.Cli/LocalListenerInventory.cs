using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WPShield.Cli;

internal static class LocalListenerInventory
{
    internal const int MaxEndpoints = 4096;

    private sealed record Endpoint(string Address, int Port, string Family, string Binding)
    {
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public ListenerOwner? Owner { get; init; }
    }
    private sealed record Table(string Protocol, DateTimeOffset ObservedAtUtc, string Status, string? Reason,
        IReadOnlyList<Endpoint> Endpoints)
    {
        [JsonIgnore]
        internal bool OwnerReadFailed { get; init; }
    }

    internal static int Run(CliOptions arguments, TextWriter output, Func<IPEndPoint[]> readTcp, Func<IPEndPoint[]> readUdp,
        Func<string, AddressFamily, IReadOnlySet<IPEndPoint>, ListenerOwners.Sample>? readOwners = null)
    {
        arguments.RejectUnknown("--listeners", "--ports", "--json", "--owners");
        arguments.RejectRepeated();
        if (arguments.Get("--listeners") is not null || arguments.Get("--json") is not null || arguments.Get("--owners") is not null)
            throw new CliArgumentException("--listeners, --owners and --json take no value.");
        var requested = arguments.IntegerList("--ports", []);
        if (arguments.Has("--ports") && (requested.Count is < 1 or > 64 || requested.Any(p => p is < 1 or > 65535)))
            throw new CliArgumentException("--ports requires 1..64 local ports in 1..65535.");
        var ports = requested.ToHashSet();
        var scope = ports.Order().ToArray();
        var lookup = arguments.Has("--owners") ? readOwners ?? ListenerOwners.Read : null;
        Table[] tables = [Read("TCP", readTcp, ports, lookup), Read("UDP", readUdp, ports, lookup)];
        if (arguments.Has("--json"))
            output.WriteLine(JsonSerializer.Serialize(new { Ports = scope, Tables = tables }));
        else
        {
            output.WriteLine($"Local socket tables | Ports: {(scope.Length == 0 ? "all" : string.Join(",", scope))}");
            foreach (var table in tables)
            {
                var reason = table.Reason is null ? "" : $" ({table.Reason})";
                output.WriteLine($"{table.ObservedAtUtc:u}  {table.Protocol}  {table.Status}{reason}  Endpoints shown: {table.Endpoints.Count}");
                foreach (var row in table.Endpoints)
                {
                    output.Write($"  {row.Family}  {row.Address}  port {row.Port}  {row.Binding}");
                    if (row.Owner is { } owner)
                    {
                        var label = owner.ProcessId?.ToString() ?? $"unknown ({owner.Reason})";
                        output.Write($"  PID {label} at {owner.ObservedAtUtc:u}");
                    }
                    output.WriteLine();
                }
            }
        }
        if (tables.All(t => t.Status == "read" && !t.OwnerReadFailed)) return 0;
        return tables.All(t => t.Status == "unavailable") ? 1 : 2;
    }

    private static Table Read(string protocol, Func<IPEndPoint[]> read, IReadOnlySet<int> ports,
        Func<string, AddressFamily, IReadOnlySet<IPEndPoint>, ListenerOwners.Sample>? lookup)
    {
        var observed = DateTimeOffset.UtcNow;
        IPEndPoint[] sockets;
        try
        {
            sockets = read();
        }
        catch (Exception ex) when (ex is NetworkInformationException or UnauthorizedAccessException
            or System.Security.SecurityException or PlatformNotSupportedException)
        {
            var denied = ex is UnauthorizedAccessException or System.Security.SecurityException or NetworkInformationException { ErrorCode: 5 };
            return new(protocol, observed, "unavailable", denied ? "access-denied" : "query-failed", []);
        }

        var endpoints = sockets.Where(e => ports.Count == 0 || ports.Contains(e.Port))
            .Distinct().Take(MaxEndpoints + 1).ToArray();
        var retained = endpoints.Take(MaxEndpoints);
        var samples = lookup is null ? null : retained.GroupBy(e => e.AddressFamily)
            .ToDictionary(g => g.Key, g => lookup(protocol, g.Key, g.ToHashSet()));
        var rows = retained.Select(e => new Endpoint(e.Address.ToString(), e.Port,
            e.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6", Binding(e.Address))
        { Owner = samples?[e.AddressFamily].For(e) })
            .OrderBy(e => e.Port).ThenBy(e => e.Family, StringComparer.Ordinal)
            .ThenBy(e => e.Address, StringComparer.Ordinal).ToArray();
        var limited = endpoints.Length > MaxEndpoints;
        return new(protocol, observed, limited ? "limited" : "read", limited ? "row-limit" : null, rows)
        { OwnerReadFailed = samples?.Values.Any(s => s.Error is not null) == true };
    }

    private static string Binding(IPAddress address)
    {
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return "wildcard";
        return IPAddress.IsLoopback(address) ? "loopback" : "specific";
    }
}
