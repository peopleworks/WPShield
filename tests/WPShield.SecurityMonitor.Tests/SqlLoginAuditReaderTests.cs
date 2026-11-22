using Xunit;

namespace WPShield.SecurityMonitor.Tests;

public sealed class SqlLoginAuditReaderTests
{
    [Theory]
    [InlineData("mssqlserver", "MSSQLSERVER")]
    [InlineData("Example_2", "MSSQL$Example_2")]
    [InlineData("Prueba$2", "MSSQL$Prueba$2")]
    [InlineData("MSSQL$", "MSSQL$MSSQL$")]
    public void SelectsOneLocalDatabaseEngineProvider(string instance, string expected) =>
        Assert.Equal(expected, SqlLoginAuditReader.ProviderFor(instance));

    [Theory]
    [InlineData("")]
    [InlineData("A2345678901234567")]
    [InlineData("SQL' or '1'='1")]
    [InlineData("Example\n")]
    public void InvalidInstanceSyntaxCannotWidenTheQuery(string instance) =>
        Assert.Throws<ArgumentException>(() => SqlLoginAuditReader.ProviderFor(instance));

    [Theory]
    [InlineData(18453, "success")]
    [InlineData(18454, "success")]
    [InlineData(18455, "success")]
    [InlineData(18456, "failure")]
    public void RetainsOnlyTheAuditedResultAndRecordReference(int eventId, string expected)
    {
        var time = DateTime.UnixEpoch;
        var result = SqlLoginAuditReader.Project("MSSQL$First", "MSSQL$First", eventId, 7, time);
        Assert.Equal(new SqlLoginEvidence(eventId, 7, DateTimeOffset.UnixEpoch, expected), result);
        Assert.Null(SqlLoginAuditReader.Project("MSSQL$Second", "MSSQL$First", eventId, 7, time));
        Assert.Null(SqlLoginAuditReader.Project("MSSQLSERVER", "SQLSERVERAGENT", eventId, 7, time));
    }

    [Fact]
    public void EmptyWindowRemainsUnknownAndMixedRecordsKeepBothOutcomes()
    {
        var window = new SqlLoginAuditWindow("MSSQLSERVER", DateTimeOffset.UnixEpoch, "read", []);
        Assert.Equal("unknown", window.ObservedOutcome);
        Assert.Equal(window.WindowEnd.AddMinutes(-1), window.WindowStart);
        window = window with { Events = [new(18453, 1, window.WindowStart, "success"), new(18456, 2, window.WindowEnd, "failure")] };
        Assert.Equal("mixed", window.ObservedOutcome);
        Assert.Equal("unknown", window.FlowAttribution);
    }

    [Fact]
    public void OtherEventIdsOrMissingRecordReferencesProvideNoLoginEvidence()
    {
        Assert.Null(SqlLoginAuditReader.Project("MSSQLSERVER", "MSSQLSERVER", 18458, 1, DateTime.UnixEpoch));
        Assert.Null(SqlLoginAuditReader.Project("MSSQLSERVER", "MSSQLSERVER", 18456, null, DateTime.UnixEpoch));
        Assert.Null(SqlLoginAuditReader.Project("MSSQLSERVER", "MSSQLSERVER", 18456, 1, null));
    }
}
