// The whole assembly reads Windows event logs. Declaring it here, rather than targeting
// net10.0-windows, lets the net10.0 gateway reference it while the platform analyzer still refuses
// every unguarded call from portable code. See WPShield.SecurityMonitor.csproj.
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]
