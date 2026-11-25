using WPShield.Cli.Audit;
using WPShield.Evidence;
using WPShield.SecurityMonitor;

namespace WPShield.Cli.Host;

/// <summary>
/// The real host-fact source (ADR 0013): the CLI's readers for IIS, the firewall and the inventory, and the
/// security monitor's for health, restarts and sessions. Everything reads; nothing changes the host.
/// </summary>
internal sealed class CliHostFactSource : IHostFactSource
{
    private readonly HostInventoryReader inventory = new(new Authenticode());

    public HostFactReading ReadHealth(string? storePath, CancellationToken cancellationToken) =>
        WindowsHostReaders.ReadHealth(storePath, LogDirectory(), cancellationToken);

    public HostRestartReading ReadRestarts(DateTimeOffset since, CancellationToken cancellationToken) =>
        WindowsHostReaders.ReadRestarts(since, cancellationToken);

    public HostFactReading ReadSites(CancellationToken cancellationToken) =>
        HostIisFacts.ReadSites(AuditFactsReader.Read(), Logs());

    public HostFactReading ReadPosture(CancellationToken cancellationToken)
    {
        var facts = AuditFactsReader.Read();
        return HostIisFacts.Posture(new AuditRunner(facts).Run(), facts, "collector", DateTimeOffset.UtcNow);
    }

    public HostFactReading ReadPorts(CancellationToken cancellationToken) => HostPortsReader.Read(cancellationToken);

    public HostFactReading ReadSessions(DateTimeOffset since, CancellationToken cancellationToken) =>
        WindowsHostReaders.ReadSessions(since, cancellationToken);

    public HostInventoryReading ReadInventory(string kind, CancellationToken cancellationToken) => inventory.Read(kind, cancellationToken);

    private static WebEvidence.IisLogConfiguration? Logs()
    {
        try
        {
            return Web.IisLogSiteReader.Read();
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Runtime.InteropServices.COMException
            or InvalidOperationException or FileNotFoundException)
        {
            return null;
        }
    }

    private static string? LogDirectory() => Logs()?.Sites.Select(s => s.LogDirectory).FirstOrDefault(d => !string.IsNullOrWhiteSpace(d));
}
