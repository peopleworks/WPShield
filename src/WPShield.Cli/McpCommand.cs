using System.Reflection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using WPShield.Cli.Mcp;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield mcp</c> - a read-only Model Context Protocol server over the evidence store (ADR 0008).
/// </summary>
/// <remarks>
/// <para>
/// <b>stdio only.</b> The assistant starts this as a local process and speaks MCP on its stdin and
/// stdout. There is no listener, so the loopback-only rule for management interfaces holds without a
/// configuration that could widen it.
/// </para>
/// <para>
/// <b>stdout belongs to the protocol.</b> The SDK's stdio transport writes to the raw standard output
/// stream; <see cref="Console.Out"/> is pointed at stderr for the lifetime of the server, so a stray
/// <c>Console.WriteLine</c> anywhere becomes a diagnostic line instead of a corrupt protocol frame.
/// The server is created directly rather than through a generic host, whose default console logger
/// writes to stdout.
/// </para>
/// </remarks>
internal static class McpCommand
{
    internal const string Help = """
        wpshield mcp [--store <path>]

        A read-only Model Context Protocol server over the local evidence store (ADR 0008). An
        assistant such as Claude Desktop or Claude Code starts it as a local process and talks to it
        on stdin and stdout; its own messages go to stderr. It opens no network port.

        Tools: attacks_summary, top_sources, source_history, attack_timeline, coverage, decisions,
        evidence_kinds, evidence_events, list_settings, address_labels, web_summary,
        web_top_sources, web_findings, address_report, host_health, iis_sites, iis_posture,
        listening_ports, rdp_sessions, host_inventory. None of them blocks, unblocks or changes a
        setting, and none reads the host: the host tools answer from the collector's snapshots.

          --store <path>   The evidence store to read.
                           Default: %ProgramData%\WPShield\evidence\wpshield-evidence.db

        The store's folder is readable only by Administrators, SYSTEM and the WPShield service, so
        the process that starts this server must itself run elevated. If the store cannot be
        opened, the server still starts and every tool answers with the reason.

        Answers travel to the assistant's model provider. They are aggregated unless the
        mcp.detailed_records setting is true, and this host's own names (sites, accounts,
        services, tasks, paths, RDP source addresses) are withheld unless mcp.host_details is
        true. Both are read when the server starts.

        Exit 0 when the client disconnects. 1 when an argument is wrong.
        """;

    internal const string Instructions =
        "WPShield evidence for this Windows server, read-only: failed Windows logons (summary, top sources, one address's history, a timeline), " +
        "what was and was not recorded (coverage), the audit trail of block decisions, other evidence events, settings and address labels, " +
        "the IIS log evidence of the sites, and the host facts (health and unexpected restarts, IIS sites and posture, listening ports, Remote Desktop sessions, accounts, services and tasks) from the collector's snapshots. " +
        "No tool can block, unblock or change anything; if the user wants an action, say it must be done by the operator outside this conversation. " +
        "Every answer has a coverage section: a gap is a period nothing was recorded, never evidence of a quiet period. " +
        "An answer with an error means nothing was read, not that nothing happened. " +
        EvidenceTools.UntrustedNote;

    internal static int Run(CliOptions options) => RunAsync(options, Console.Error).GetAwaiter().GetResult();

    internal static async Task<int> RunAsync(CliOptions options, TextWriter diagnostics, CancellationToken token = default)
    {
        options.RejectUnknown("--store");
        options.RejectRepeated();
        if (options.Has("--store") && string.IsNullOrWhiteSpace(options.Get("--store")))
            throw new CliArgumentException("--store needs a path.");
        var path = Path.GetFullPath(options.Get("--store", EvidenceStore.DefaultPath));

        var stdout = Console.Out;
        Console.SetOut(diagnostics);
        try
        {
            using var access = new McpEvidenceAccess(path);
            var problem = access.TryOpenNow();
            diagnostics.WriteLine(problem is null
                ? $"wpshield mcp: evidence store opened read-only. Detailed records: {(access.DetailedRecords ? "on" : "off")}. Host details: {(access.HostDetails ? "on" : "off")}. Path: {path}"
                : $"wpshield mcp: evidence store unavailable ({problem.Reason}); every tool will say so until it opens. Path: {path}");

            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            void Cancel(object? sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                cancellation.Cancel();
            }
            Console.CancelKeyPress += Cancel;
            try
            {
                using var logging = new StderrLoggerFactory(diagnostics, LogLevel.Warning);
                await using var transport = new StdioServerTransport("wpshield", logging);
                await using var server = McpServer.Create(transport, Options(new EvidenceTools(access)), logging);
                await server.RunAsync(cancellation.Token);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
            }
            finally
            {
                Console.CancelKeyPress -= Cancel;
            }
            return 0;
        }
        finally
        {
            Console.SetOut(stdout);
        }
    }

    /// <summary>The server's identity, instructions and tools. Shared with the tests' in-process round trip.</summary>
    internal static McpServerOptions Options(EvidenceTools tools) => new()
    {
        ServerInfo = new Implementation { Name = "wpshield", Title = "WPShield evidence (read-only)", Version = Version() },
        ServerInstructions = Instructions,
        ToolCollection = WPShieldMcpTools.Collection(tools)
    };

    private static string Version() =>
        typeof(McpCommand).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";
}
