namespace WPShield.Cli;

internal static class NetworkFilterCommand
{
    internal const string Unavailable = "Host-wide packet blocking is unavailable in this preview. "
        + "See https://github.com/peopleworks/WPShield/pull/86 for the replacement design.";

    internal const string Help = "wpshield network-filter — " + Unavailable
        + "\nRunning this command exits with code 1. Use 'wpshield network-monitor --listeners' to list local ports.";
}
