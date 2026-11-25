using System.Globalization;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using WPShield.Cli.Install;
using WPShield.Evidence;
using WPShield.SecurityMonitor;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield evidence collect</c>: the service's evidence collector, in the foreground, until Ctrl+C.
/// </summary>
/// <remarks>
/// It exists to validate collection on a host before the service is trusted with it: the same
/// <see cref="EvidenceCollector"/>, the same store, the same coverage rules. It refuses to run beside
/// the service, because the service is the evidence writer (ADR 0007, section 1), and it refuses
/// without elevation, because both the Security log and the store's directory need it.
/// </remarks>
internal static class EvidenceCommand
{
    public const string Help = """
        wpshield evidence collect - record failed Windows logons into the evidence store, in the
        foreground, until Ctrl+C. The WPShield service does the same thing continuously; this is for
        validating it on a host first.

        Usage: wpshield evidence collect [--store <file>]

          --store <file>   The evidence database. Default
                           %ProgramData%\WPShield\evidence\wpshield-evidence.db.
                           Its directory must already exist: 'wpshield install' creates it with
                           replaced permissions (SYSTEM, Administrators, the service), and this
                           command never creates it.

        It catches up from the Security and Remote Desktop logs since the last stored Security
        record, then follows them live, and records which periods it could and could not read.

        It also reads the IIS W3C log of every site (ADR 0011): the request-path rules and the
        observations run on each logged request, and findings and hourly counts are stored. It reads
        the IIS configuration and the log files only; it never reads the query string, the referer
        or the user name of a request. At start it reads the last 15 minutes of each log as history.
        A site whose log cannot be read is recorded as not covered, with the reason and the remedy.
        'wpshield web' shows what it found. Web evidence is never fed to a decision.

        It refuses to run:
          - without elevation, because the Security log and the store's directory both need it;
          - while the WPShield service is running, because the service is the evidence writer.
            Stop it first, or let the service collect.

        It records history and nothing else: it blocks nothing, and nothing it records is fed to a
        decision.

        Exit codes:
          0   stopped with Ctrl+C
          1   an argument was wrong, a guard refused, or the store's directory does not exist
        """;

    private const string Usage = "Usage: wpshield evidence collect [--store <file>]. Run 'wpshield evidence --help' for details.";

    /// <summary>The facts and the collector, behind delegates so the guards can be tested.</summary>
    internal sealed record Facts(
        Func<bool> IsElevated,
        Func<string?> ServiceState,
        Func<string, bool> DirectoryExists,
        Func<string, TextWriter, CancellationToken, Task<EvidenceCollectorExit>> Collect);

    public static int Run(CliOptions arguments, TextWriter output, string action) =>
        Run(arguments, output, action, RealFacts(), WaitForCtrlC);

    internal static int Run(CliOptions arguments, TextWriter output, string action, Facts facts,
        Func<CancellationTokenSource, IDisposable> cancelOn)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(facts);
        ArgumentNullException.ThrowIfNull(cancelOn);

        if (arguments.Has("--help"))
        {
            output.WriteLine(Help);
            return 0;
        }

        if (!string.Equals(action, "collect", StringComparison.OrdinalIgnoreCase))
        {
            throw new CliArgumentException(Usage);
        }

        arguments.RejectUnknown("--store");
        arguments.RejectRepeated();

        var store = arguments.Get("--store", EvidenceStore.DefaultPath);
        if (!Path.IsPathFullyQualified(store) || string.IsNullOrEmpty(Path.GetFileName(store)))
        {
            throw new CliArgumentException("--store must be an absolute path to the database file.");
        }

        if (!facts.IsElevated())
        {
            throw new CliArgumentException(
                "This must run from an elevated prompt: the Security log and the evidence directory both need it. Nothing was recorded.");
        }

        if (facts.ServiceState() is { } state && !string.Equals(state, "Stopped", StringComparison.OrdinalIgnoreCase))
        {
            throw new CliArgumentException(
                $"The {Installer.ServiceName} service is {state}. It is the evidence writer, and one writer is the rule: " +
                $"stop it first (Stop-Service {Installer.ServiceName}) or let it collect. Nothing was recorded.");
        }

        var directory = Path.GetDirectoryName(store)!;
        if (!facts.DirectoryExists(directory))
        {
            throw new CliArgumentException(
                $"The evidence directory {directory} does not exist. 'wpshield install' creates it with replaced " +
                "permissions; this command never creates it, because a directory it created would inherit " +
                "ProgramData's and let every local user read the evidence. Nothing was recorded.");
        }

        output.WriteLine();
        output.WriteLine($"WPShield evidence collect - {store}");
        output.WriteLine("Recording failed logons and IIS log evidence until Ctrl+C. Nothing is blocked.");
        output.WriteLine();

        using var cancellation = new CancellationTokenSource();
        using (cancelOn(cancellation))
        {
            var exit = facts.Collect(store, output, cancellation.Token).GetAwaiter().GetResult();
            return exit == EvidenceCollectorExit.Stopped ? 0 : 1;
        }
    }

    private static Facts RealFacts() => new(
        IsElevated: () =>
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        },
        ServiceState: () =>
        {
            try
            {
                using var controller = new ServiceController(Installer.ServiceName);
                return controller.Status.ToString();
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        },
        DirectoryExists: Directory.Exists,
        Collect: (store, output, token) => new EvidenceCollector(store, new ConsoleLogger(output), Web.IisLogSiteReader.Read).RunAsync(token));

    private static IDisposable WaitForCtrlC(CancellationTokenSource cancellation)
    {
        ConsoleCancelEventHandler handler = (_, args) =>
        {
            // Stop gracefully: the collector writes what it has buffered and closes its interval.
            args.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += handler;
        return new Unsubscribe(() => Console.CancelKeyPress -= handler);
    }

    private sealed class Unsubscribe(Action action) : IDisposable
    {
        public void Dispose() => action();
    }

    /// <summary>One line per message, Information and above. The collector logs counts and codes only.</summary>
    private sealed class ConsoleLogger(TextWriter output) : ILogger
    {
        private readonly object gate = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information && logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var level = logLevel switch
            {
                LogLevel.Warning => "WARN ",
                LogLevel.Error or LogLevel.Critical => "ERROR",
                _ => "INFO "
            };
            var line = $"{DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture)} {level} {formatter(state, exception)}";
            if (exception is not null) line += $" ({exception.GetType().Name}: {exception.Message})";
            lock (gate) output.WriteLine(line);
        }
    }
}
