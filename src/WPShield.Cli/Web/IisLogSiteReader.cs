using System.Runtime.InteropServices;
using Microsoft.Web.Administration;
using WPShield.WebEvidence;

namespace WPShield.Cli.Web;

/// <summary>
/// Reads which IIS sites exist and how each logs, for the IIS log sensor (ADR 0011, section 2). Read-only,
/// like the readers behind <c>wpshield audit</c> and <c>preflight</c>: it opens the configuration, reads, and
/// writes nothing.
/// </summary>
/// <remarks>
/// "Nobody could look" is never "there is nothing": an unreadable configuration comes back as a problem,
/// which the sensor records as a coverage gap, never as an empty site list.
/// </remarks>
internal static class IisLogSiteReader
{
    public static IisLogConfiguration Read()
    {
        try
        {
            using var manager = new ServerManager();
            return new IisLogConfiguration([.. manager.Sites.Select(ReadSite)], null, CentralMode(manager));
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or COMException or FileNotFoundException
                or InvalidOperationException or TypeInitializationException or DllNotFoundException)
        {
            return IisLogConfiguration.Unreadable(exception.GetType().Name);
        }
    }

    private static IisLogSite ReadSite(Site site)
    {
        string? directory = null;
        var enabled = false;
        var format = "unknown";
        try
        {
            var log = site.LogFile;
            directory = string.IsNullOrWhiteSpace(log.Directory) ? null : Environment.ExpandEnvironmentVariables(log.Directory);
            enabled = log.Enabled;
            format = log.LogFormat == LogFormat.W3c ? "W3C" : log.LogFormat.ToString();
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
            // Left as unknown: the sensor reports this site as not read, with the reason.
        }

        var http = false;
        try
        {
            http = site.Bindings.Any(binding =>
                string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
        }

        return new IisLogSite(site.Id, site.Name, directory, enabled, format, http);
    }

    /// <summary>
    /// <c>CentralW3C</c> or <c>CentralBinary</c> when IIS writes one file for all sites, or <see langword="null"/>
    /// for the default, one file per site.
    /// </summary>
    private static string? CentralMode(ServerManager manager)
    {
        try
        {
            var mode = manager.GetApplicationHostConfiguration().GetSection("system.applicationHost/log")["centralLogFileMode"];
            return mode switch
            {
                int value when value == 1 => "CentralBinary",
                int value when value == 2 => "CentralW3C",
                string text when text.StartsWith("Central", StringComparison.OrdinalIgnoreCase) => text,
                _ => null
            };
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or FileNotFoundException)
        {
            return null;
        }
    }
}
