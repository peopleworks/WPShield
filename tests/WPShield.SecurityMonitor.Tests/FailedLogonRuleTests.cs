namespace WPShield.SecurityMonitor.Tests;

public class FailedLogonRuleTests
{
    [Fact]
    public void Non_failure_event_is_ignored()
    {
        var rule = new FailedLogonRule(maxFailuresPerWindow: 10, windowMinutes: 10);

        var success = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4624,
            SourceIp = "10.0.0.1",
            UserName = "Administrator",
            LogonType = "2",
            ProcessName = "services.exe",
            ComputerName = "SERVER01",
            TimeCreated = DateTimeOffset.UtcNow,
            Message = "An account was successfully logged on."
        });

        Assert.Equal(0, success.Score);
        Assert.Equal(NetworkInspectionAction.Allow, success.Action);
        Assert.Equal("not_failed_logon", success.Evidence["reason"]);
    }

    [Fact]
    public void Failures_accumulate_and_block_at_threshold()
    {
        var rule = new FailedLogonRule(maxFailuresPerWindow: 10, windowMinutes: 10);
        var now = DateTimeOffset.UtcNow;

        // 9 failures -> score 30 (Observe). The 10th inspection makes count = 10.
        for (int i = 0; i < 8; i++)
        {
            rule.Inspect(new SecurityInspectionContext
            {
                EventId = 4625,
                SourceIp = "10.0.0.1",
                UserName = "testuser",
                LogonType = "3",
                ProcessName = "lsass.exe",
                ComputerName = "SERVER01",
                TimeCreated = now,
                Message = "An account failed to log on."
            });
        }

        var observe = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "testuser",
            LogonType = "3",
            ProcessName = "lsass.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        // count = 9, which is >= 5 but < 10, so score 30 (Observe)
        Assert.Equal(30, observe.Score);
        Assert.Equal(NetworkInspectionAction.Observe, observe.Action);

        // 10th failure -> count = 10, score 70 (Block)
        var block = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "testuser",
            LogonType = "3",
            ProcessName = "lsass.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        Assert.Equal(70, block.Score);
        Assert.Equal(NetworkInspectionAction.Block, block.Action);
    }

    [Fact]
    public void Many_failures_return_score_100()
    {
        var rule = new FailedLogonRule(maxFailuresPerWindow: 10, windowMinutes: 10);
        var now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 20; i++)
        {
            rule.Inspect(new SecurityInspectionContext
            {
                EventId = 4625,
                SourceIp = "10.0.0.1",
                UserName = "testuser",
                LogonType = "3",
                ProcessName = "lsass.exe",
                ComputerName = "SERVER01",
                TimeCreated = now,
                Message = "An account failed to log on."
            });
        }

        var result = rule.Inspect(new SecurityInspectionContext
        {
            EventId = 4625,
            SourceIp = "10.0.0.1",
            UserName = "testuser",
            LogonType = "3",
            ProcessName = "lsass.exe",
            ComputerName = "SERVER01",
            TimeCreated = now,
            Message = "An account failed to log on."
        });

        Assert.Equal(100, result.Score);
        Assert.Equal(NetworkInspectionAction.Block, result.Action);
    }
}
