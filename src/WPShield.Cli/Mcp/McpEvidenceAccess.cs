using System.Security.Principal;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;

namespace WPShield.Cli.Mcp;

/// <summary>Why the store could not be read, in words an operator and an assistant can both act on.</summary>
/// <param name="Reason"><c>missing</c>, <c>needs-elevation</c>, <c>schema-mismatch</c> or <c>unreadable</c>.</param>
internal sealed record StoreProblem(string Reason, string Message, string Remedy, bool Elevated);

/// <summary>
/// The read-only store behind <c>wpshield mcp</c>, opened on first use and retried until it opens, so a
/// server started before the WPShield service has written anything starts answering once it has.
/// </summary>
/// <remarks>
/// <para>
/// Every call is serialised: an MCP server may run tool calls concurrently and a SQLite connection is
/// not safe to share between threads. The queries are bounded, so a caller waits milliseconds, not minutes.
/// </para>
/// <para>
/// <c>mcp.detailed_records</c> takes effect at the next start (<see cref="SettingEffect.NextStart"/>), so it
/// is read once, when the store first opens, and frozen. A change made while the server runs is reported
/// by <c>list_settings</c> as waiting for a restart, never applied silently.
/// </para>
/// </remarks>
internal sealed class McpEvidenceAccess : IDisposable
{
    private readonly object gate = new();
    private readonly Func<string, EvidenceStore> open;
    private readonly Func<bool> isElevated;
    private EvidenceStore? store;
    private bool disposed;

    public McpEvidenceAccess(string path, Func<string, EvidenceStore>? open = null, Func<bool>? isElevated = null)
    {
        Path = path;
        this.open = open ?? EvidenceStore.OpenReadOnly;
        this.isElevated = isElevated ?? IsProcessElevated;
    }

    public string Path { get; }

    /// <summary>The value of <c>mcp.detailed_records</c> when the store first opened; false until then.</summary>
    public bool DetailedRecords { get; private set; }

    /// <summary>The last reason the store could not be opened, or null once it is open.</summary>
    public StoreProblem? Problem { get; private set; }

    /// <summary>
    /// Runs <paramref name="query"/> against the open store, opening it first if needed. Returns the
    /// problem instead when it cannot be opened, so a caller can never mistake "unreadable" for "empty".
    /// </summary>
    public (T? Value, StoreProblem? Problem) Use<T>(Func<EvidenceStore, T> query)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (store is null && TryOpen() is { } problem) return (default, problem);
            return (query(store!), null);
        }
    }

    /// <summary>Tries to open the store now. Used at start, so stderr can say what the server will answer from.</summary>
    public StoreProblem? TryOpenNow()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return store is null ? TryOpen() : null;
        }
    }

    private StoreProblem? TryOpen()
    {
        try
        {
            var opened = open(Path);
            try
            {
                DetailedRecords = new EvidenceSettings(opened).Get<bool>("mcp.detailed_records");
            }
            catch
            {
                opened.Dispose();
                throw;
            }
            store = opened;
            Problem = null;
            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException
            or SqliteException or InvalidOperationException or FormatException or System.Text.Json.JsonException)
        {
            Problem = Classify(exception, isElevated());
            return Problem;
        }
    }

    /// <summary>
    /// Names the failure. Without elevation, Windows reports a file the process may not read as a file
    /// that does not exist, and SQLite reports a refused open as a generic open error; so when the
    /// process is not elevated, "missing" and "denied" cannot be told apart, and the honest answer is
    /// that elevation is needed before anything else can be known.
    /// </summary>
    internal static StoreProblem Classify(Exception exception, bool elevated)
    {
        if (exception is InvalidDataException)
            return new("schema-mismatch", Clean(exception.Message),
                "Run the wpshield.exe from the same release as the WPShield service that writes the store.", elevated);
        if (!elevated)
            return new("needs-elevation",
                "The evidence store could not be opened from an unelevated process. Its folder is readable only by Administrators, SYSTEM and the WPShield service, so this may mean the store exists and is protected, or that it does not exist; only an elevated process can tell.",
                "Start the assistant that runs 'wpshield mcp' from an elevated session (Run as administrator), or run it on the server from an elevated session.",
                elevated);
        return exception switch
        {
            FileNotFoundException or DirectoryNotFoundException => new("missing",
                "The evidence store does not exist yet. The WPShield service creates and fills it; nothing has been recorded.",
                "Check that the WPShield service is installed and running ('wpshield status'). The server retries on every call.", elevated),
            _ => new("unreadable", $"The evidence store could not be opened: {Clean(exception.Message)}",
                "Check the file with 'wpshield status' and the service log; a damaged store is not repaired by this read-only server.",
                elevated)
        };
    }

    private static string Clean(string message) => EvidenceText.Clean(message, 300);

    private static bool IsProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public void Dispose()
    {
        lock (gate)
        {
            disposed = true;
            store?.Dispose();
            store = null;
        }
    }
}
