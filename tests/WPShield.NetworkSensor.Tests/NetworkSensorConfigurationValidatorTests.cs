using Xunit;

namespace WPShield.NetworkSensor.Tests;

public class NetworkSensorConfigurationValidatorTests
{
    [Fact]
    public void DisabledConfigurationIsValid()
    {
        var config = new NetworkSensorConfiguration { Enabled = false };
        NetworkSensorConfigurationValidator.Validate(config);
    }

    [Fact]
    public void EnabledWithNoPortsThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [],
            OutputPath = "C:\\temp\\network.ndjson",
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void EnabledWithValidPortsIsValid()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [80, 443],
            OutputPath = "C:\\temp\\network.ndjson",
        };
        NetworkSensorConfigurationValidator.Validate(config);
    }

    [Fact]
    public void PortBelowRangeThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [0],
            OutputPath = "C:\\temp\\network.ndjson",
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void PortAboveRangeThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [65536],
            OutputPath = "C:\\temp\\network.ndjson",
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void EmptyOutputPathThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [80],
            OutputPath = string.Empty,
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void MaxEventsPerSecondBelowOneThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [80],
            OutputPath = "C:\\temp\\network.ndjson",
            MaxEventsPerSecond = 0,
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void MaxEventsPerSecondAboveCeilingThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [80],
            OutputPath = "C:\\temp\\network.ndjson",
            MaxEventsPerSecond = 100_001,
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void MaxFileSizeBelowOneMiBThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [80],
            OutputPath = "C:\\temp\\network.ndjson",
            Rotation = new RotationConfiguration { MaxFileSizeBytes = 1_048_575 },
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }

    [Fact]
    public void RetentionDaysBelowOneThrows()
    {
        var config = new NetworkSensorConfiguration
        {
            Enabled = true,
            Ports = [80],
            OutputPath = "C:\\temp\\network.ndjson",
            Rotation = new RotationConfiguration { RetentionDays = 0 },
        };
        Assert.Throws<InvalidOperationException>(() =>
            NetworkSensorConfigurationValidator.Validate(config));
    }
}
