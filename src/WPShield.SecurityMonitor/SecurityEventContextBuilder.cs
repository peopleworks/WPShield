using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;

namespace WPShield.SecurityMonitor;

/// <summary>
/// Builds a <see cref="WPShield.Abstractions.SecurityInspectionContext"/> from a Windows
/// Security event log record.
///
/// Property names in the Security event log vary by Windows version, so extraction is
/// defensive: absent fields fall back to empty strings rather than throwing. The
/// <see cref="EventProperty.Name"/> member is accessed through reflection because the
/// Windows ref assembly does not expose it at compile time, but it exists at runtime.
/// </summary>
internal static class SecurityEventContextBuilder
{
    private static readonly PropertyInfo? NameProperty =
        typeof(EventProperty).GetProperty("Name", BindingFlags.Public | BindingFlags.Instance);

    public static WPShield.Abstractions.SecurityInspectionContext Build(EventLogRecord record)
    {
        string? sourceIp = null;
        string? userName = null;
        string? logonType = null;
        string? processName = null;
        string? computerName = null;

        foreach (var property in record.Properties)
        {
            var value = property.Value?.ToString() ?? string.Empty;
            var name = (NameProperty?.GetValue(property) as string) ?? string.Empty;

            switch (name.ToLowerInvariant())
            {
                case "ipaddress":
                    sourceIp = value;
                    break;
                case "targetusername":
                    userName = value;
                    break;
                case "logontype":
                    logonType = value;
                    break;
                case "processname":
                    processName = value;
                    break;
                case "computername":
                    computerName = value;
                    break;
            }
        }

        // Normalize "-" or whitespace to empty for source IP.
        if (string.IsNullOrWhiteSpace(sourceIp) || sourceIp == "-")
        {
            sourceIp = string.Empty;
        }

        var timeCreated = record.TimeCreated;
        var timeOffset = timeCreated.HasValue
            ? new DateTimeOffset(timeCreated.Value)
            : DateTimeOffset.UtcNow;

        return new WPShield.Abstractions.SecurityInspectionContext
        {
            EventId = record.Id,
            SourceIp = sourceIp ?? string.Empty,
            UserName = userName ?? string.Empty,
            LogonType = logonType ?? string.Empty,
            ProcessName = processName ?? string.Empty,
            ComputerName = computerName ?? string.Empty,
            TimeCreated = timeOffset,
            Message = record.FormatDescription()
        };
    }
}
