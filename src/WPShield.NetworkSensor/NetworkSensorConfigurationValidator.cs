namespace WPShield.NetworkSensor;

/// <summary>
/// Validates <see cref="NetworkSensorConfiguration"/>. The sensor fails closed: any invalid
/// configuration throws before a single packet is captured.
/// </summary>
public static class NetworkSensorConfigurationValidator
{
    /// <summary>
    /// Validates the configuration and throws <see cref="InvalidOperationException"/> with a
    /// clear, actionable message on the first problem found.
    /// </summary>
    public static void Validate(NetworkSensorConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (!configuration.Enabled)
        {
            // Disabled is a valid state: capture nothing.
            return;
        }

        if (configuration.Ports is null || configuration.Ports.Count == 0)
        {
            throw new InvalidOperationException(
                "NetworkSensor is enabled but no Ports are configured. " +
                "Set NetworkSensor:Ports to at least one port (for example 80, 443), or disable the sensor.");
        }

        foreach (var port in configuration.Ports)
        {
            if (port < 1 || port > 65535)
            {
                throw new InvalidOperationException(
                    $"NetworkSensor port {port} is outside the valid range 1-65535.");
            }
        }

        if (string.IsNullOrWhiteSpace(configuration.OutputPath))
        {
            throw new InvalidOperationException(
                "NetworkSensor is enabled but OutputPath is not configured. " +
                "Set NetworkSensor:OutputPath to a writable log file path.");
        }

        if (configuration.MaxEventsPerSecond < 1)
        {
            throw new InvalidOperationException(
                $"NetworkSensor:MaxEventsPerSecond must be at least 1, was {configuration.MaxEventsPerSecond}.");
        }

        if (configuration.MaxEventsPerSecond > 100_000)
        {
            throw new InvalidOperationException(
                $"NetworkSensor:MaxEventsPerSecond must not exceed 100000, was {configuration.MaxEventsPerSecond}.");
        }

        if (configuration.Rotation.MaxFileSizeBytes < 1_048_576) // 1 MiB
        {
            throw new InvalidOperationException(
                $"NetworkSensor:Rotation:MaxFileSizeBytes must be at least 1 MiB, was {configuration.Rotation.MaxFileSizeBytes}.");
        }

        if (configuration.Rotation.RetentionDays < 1)
        {
            throw new InvalidOperationException(
                $"NetworkSensor:Rotation:RetentionDays must be at least 1, was {configuration.Rotation.RetentionDays}.");
        }
    }
}
