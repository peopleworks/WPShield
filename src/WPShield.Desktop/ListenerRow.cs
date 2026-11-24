using System.Globalization;

namespace WPShield.Desktop;

internal sealed record ListenerRow(string Protocol, string Address, int Port, string Family, string Hint,
    uint? ProcessId, string Owner, string OwnerDetail, string ProcessName = "")
{
    internal (string, string, int) Key => (Protocol, Address, Port);

    internal bool Matches(string? protocol, string query) =>
        (protocol is null || protocol == Protocol) &&
        (query.Length == 0 || Address.Contains(query, StringComparison.OrdinalIgnoreCase) ||
         Port.ToString(CultureInfo.InvariantCulture).Equals(query, StringComparison.Ordinal) ||
         ProcessId?.ToString(CultureInfo.InvariantCulture) == query ||
         Hint.Contains(query, StringComparison.OrdinalIgnoreCase) ||
         (ProcessName.Length > 0 && ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase)));
}
