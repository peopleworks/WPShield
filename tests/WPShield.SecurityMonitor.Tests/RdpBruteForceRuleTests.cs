namespace WPShield.SecurityMonitor.Tests;

public class RdpBruteForceRuleTests
{
    [Fact]
    public void Non_rdp_failure_returns_allow_with_zero_score()
    {
        var rule = new RdpBruteForceRule(maxFailuresPerWindow: 5, windowMinutes: 5);

        // Event 4624 (success) should be ignored
        var success = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4624,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "services.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account was successfully logged on."
        });

        Assert.Equal(0, success.Score);
        Assert.Equal(NetworkInspectionAction.Allow, success.Action);
        Assert.Equal("not_rdp_failure", success.Evidence["reason"]);

        // Event 4625 with non-RDP logon type should be ignored
        var network = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "3",
            ProcessName = "services.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account failed to log on."
        });

        Assert.Equal(0, network.Score);
        Assert.Equal(NetworkInspectionAction.Allow, network.Action);
    }

    [Fact]
    public void Rdp_failures_accumulate_and_block_at_threshold()
    {
        var rule = new RdpBruteForceRule(maxFailuresPerWindow: 5, windowMinutes: 5);
        var now = DateTimeOffset.UtcNow;

        // 4 failures -> score 40 (Observe)
        for (int i = 0; i < 4; i++)
        {
            var r = rule.Inspect(new SecurityInspectionContext
            {
                EventId = 4625,
                SourceIp = "10.0.0.1",
                UserName = "Administrator",
                LogonType = "10",
                ProcessName = "svchost.exe",
                ComputerName = "SERVER01",
                TimeCreated = now,
                Message = "An account failed to log on."
            });
        }

        var observe = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        Assert.Equal(80, observe.Score);
        Assert.Equal(NetworkInspectionAction.Block, observe.Action);
        Assert.Equal(5, (int)observe.Evidence["failed_logons_last_minutes"]);
    }

    [Fact]
    public void Many_failures_return_score_100()
    {
        var rule = new RdpBruteForceRule(maxFailuresPerWindow: 5, windowMinutes: 5);
        var now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 10; i++)
        {
            rule.Inspect(new SecurityInspectionContext
            {
                EventId = 4625,
                SourceIp = "10.0.0.1",
                UserName = "Administrator",
                LogonType = "10",
                ProcessName = "svchost.exe",
                ComputerName = "SERVER01",
                TimeCreated = now,
                Message = "An account failed to log on."
            });
        }

        var result = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        Assert.Equal(100, result.Score);
        Assert.Equal(NetworkInspectionAction.Block, result.Action);
    }

    [Fact]
    public void Different_ips_are_tracked_separately()
    {
        var rule = new RdpBruteForceRule(maxFailuresPerWindow: 1, windowMinutes: 5);
        var now = DateTimeOffset.UtcNow;

        var ip1 = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        var ip2 = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.2",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        Assert.Equal(NetworkInspectionAction.Block, ip1.Action);
        Assert.Equal(NetworkInspectionAction.Block, ip2.Action);
    }

    [Fact]
    public void Clear_ip_removes_history()
    {
        var rule = new RdpBruteForceRule(maxFailuresPerWindow: 5, windowMinutes: 5);
        var now = DateTimeOffset.UtcNow;

        // 5 failures -> score 80 (Block)
        for (int i = 0; i < 5; i++)
        {
            rule.Inspect(new SecurityInspectionContext
            {
                EventId = 4625,
                SourceIp = "10.0.0.1",
                UserName = "Administrator",
                LogonType = "10",
                ProcessName = "svchost.exe",
                ComputerName = "SERVER01",
                TimeCreated = now,
                Message = "An account failed to log on."
            });
        }

        var blocked = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });
        Assert.Equal(NetworkInspectionAction.Block, blocked.Action);

        rule.ClearIp("10.0.0.1");

        // After clearing, a single failure is back to score 0 (Allow), not Block
        var observe = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "10",
            ProcessName = "svchost.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });
        Assert.Equal(NetworkInspectionAction.Allow, observe.Action);
        Assert.Equal(0, observe.Score);
    }
}
