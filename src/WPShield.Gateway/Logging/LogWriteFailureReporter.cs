using Microsoft.Extensions.Logging;

namespace WPShield.Gateway.Logging;

/// <summary>
/// Carries a log-write failure from the file destination to the log destinations that still work.
/// </summary>
/// <remarks>
/// <para>
/// The file writer cannot report its own failure through itself, and until this existed it reported
/// to <c>Console.Error</c> instead. That is correct for a console run and useless for the deployment
/// this project actually targets: a Windows service has no console attached, so the one notice
/// saying the evidence log had stopped being written went to a stream nobody could read.
/// </para>
/// <para>
/// The indirection is here because of ordering rather than taste. The provider is constructed by the
/// container while the logging pipeline is still being assembled, so no <see cref="ILogger"/> exists
/// to hand it; asking the container for one at that point is circular. The reporter is registered
/// early, handed to the provider as a callback, and given its logger once the host is built - after
/// which failures reach the Windows Event Log, which under a service is the destination that matters.
/// </para>
/// <para>
/// Reporting through <see cref="ILogger"/> means the notice also fans out to the file destination
/// that is broken. That is harmless: the writer sets its failure flag before calling this, so the
/// returning entry is queued, fails, and reports nothing further.
/// </para>
/// </remarks>
internal sealed class LogWriteFailureReporter
{
    private ILogger? _logger;

    /// <summary>Directs later reports at the assembled logging pipeline.</summary>
    public void Attach(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    /// <summary>
    /// Announces one failure. Never throws: it is called from the writer's drain loop, which has no
    /// caller to propagate to and must survive to retry the next batch.
    /// </summary>
    public void Report(string message)
    {
        try
        {
            var logger = _logger;
            if (logger is null)
            {
                // Before the host is built there is nothing else. A failure this early is a console
                // run or a test, where stderr is read by someone.
                Console.Error.WriteLine(message);
                return;
            }

            // The message is the argument rather than the template, so a directory containing braces
            // cannot be mistaken for a placeholder.
            logger.LogError("{FileLogFailure}", message);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // A logging pipeline that throws while reporting that logging is broken must not also
            // take down the drain loop, which is the only thing that will retry the write.
        }
    }
}
