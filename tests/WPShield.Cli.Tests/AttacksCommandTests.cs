using System.Text.Json;
using Microsoft.Data.Sqlite;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Cli.Tests;

/// <summary>
/// <c>wpshield attacks</c> reads the evidence store and says what its answer is made of. The tests
/// that matter most are the ones where the honest answer is not a number: a store nobody could open,
/// a range nobody recorded, a period whose detail is gone.
/// </summary>
public sealed class AttacksCommandTests : IDisposable
{
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly EvidenceTestStore store = new();

    public void Dispose() => store.Dispose();

    private (int Exit, string Output, string Error) Run(bool elevated, params string[] args)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exit = AttacksCommand.Run(CliOptions.Parse(args), output, error, store.Path, () => elevated, () => Now);
        return (exit, output.ToString(), error.ToString());
    }

    private (int Exit, string Output, string Error) Run(params string[] args) => Run(true, args);

    private EvidenceTestStore Attacked() => store
        .Covered(Now.AddDays(-2), Now)
        .Append(store.Failure(50, "203.0.113.10", "admin"), store.Failure(40, "203.0.113.10", "admin"),
            store.Failure(30, "203.0.113.10", "sa", "unknown-account"), store.Failure(20, "203.0.113.11", "backup"),
            store.Failure(10, "198.51.100.7", "pedro"), store.Failure(5, null, type: 3));

    [Fact]
    public void ElevatedWithNoStore_SaysThereIsNoStoreAndThatItIsNotTheSameAsNoAttacks()
    {
        var (exit, output, error) = Run();

        Assert.Equal(3, exit);
        Assert.Empty(output);
        Assert.Contains("no evidence store", error, StringComparison.Ordinal);
        Assert.Contains("not the same as no attacks", error, StringComparison.Ordinal);
    }

    /// <summary>
    /// File.Exists answers false on access denied, so without elevation "missing" is the likelier lie.
    /// The command must say it could not look.
    /// </summary>
    [Fact]
    public void NotElevated_SaysItCouldNotLookRatherThanThatNothingExists()
    {
        var (exit, output, error) = Run(elevated: false);

        Assert.Equal(1, exit);
        Assert.Empty(output);
        Assert.Contains("not elevated", error, StringComparison.Ordinal);
        Assert.DoesNotContain("no evidence store", error, StringComparison.Ordinal);
    }

    [Fact]
    public void AStoreOfAnotherSchema_IsRefusedWithItsVersion()
    {
        store.Write(_ => { });
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = store.Path, Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version = 99;";
            command.ExecuteNonQuery();
        }

        var (exit, output, error) = Run();

        Assert.Equal(2, exit);
        Assert.Empty(output);
        Assert.Contains("schema 99", error, StringComparison.Ordinal);
    }

    [Fact]
    public void AFileThatIsNotADatabase_IsUnreadableNotEmpty()
    {
        File.WriteAllText(store.Path, "this is not a SQLite database, only synthetic text for a test");

        var (exit, output, error) = Run();

        Assert.Equal(2, exit);
        Assert.Empty(output);
        Assert.Contains("could not be read", error, StringComparison.Ordinal);
    }

    [Fact]
    public void ARangeNobodyRecorded_IsNoDataNeverZero()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("--range", "24h");

        Assert.Equal(2, exit);
        Assert.Contains("Failed attempts       no data", output, StringComparison.Ordinal);
        Assert.Contains("Coverage         none", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Failed attempts       0", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ARangeNobodyRecorded_IsNullInJson()
    {
        store.Write(_ => { });

        var (exit, output, _) = Run("--json");

        Assert.Equal(2, exit);
        using var json = JsonDocument.Parse(output);
        Assert.Equal("none", json.RootElement.GetProperty("coverage").GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("summary").GetProperty("attempts").ValueKind);
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("sources").ValueKind);
    }

    [Fact]
    public void TopSources_ShowTheAnswerWithNetworksNeighboursAndLabels()
    {
        Attacked().Setting("labels.addresses", """{"198.51.100.7":"My office","203.0.113.0/24":"Scanner network"}""");

        var (exit, output, error) = Run("--range", "24h");

        Assert.Equal(0, exit);
        Assert.Empty(error);
        Assert.Contains("Records          detailed", output, StringComparison.Ordinal);
        Assert.Contains("Coverage         recorded for the whole range", output, StringComparison.Ordinal);
        Assert.Contains("Failed attempts       6  (1 without a source address)", output, StringComparison.Ordinal);
        Assert.Contains("Source addresses      3", output, StringComparison.Ordinal);
        Assert.Contains("Most tried account    admin", output, StringComparison.Ordinal);
        var lines = output.Split(Environment.NewLine);
        var top = Assert.Single(lines, l => l.StartsWith("203.0.113.10", StringComparison.Ordinal));
        Assert.Contains("203.0.113.0/24", top, StringComparison.Ordinal);
        Assert.Contains("33%", top, StringComparison.Ordinal);
        Assert.EndsWith("Scanner network", top, StringComparison.Ordinal);
        Assert.EndsWith("My office", Assert.Single(lines, l => l.StartsWith("198.51.100.7", StringComparison.Ordinal)), StringComparison.Ordinal);
    }

    [Fact]
    public void TopSources_InJson()
    {
        Attacked().Setting("labels.addresses", """{"198.51.100.7":"My office"}""");

        var (exit, output, _) = Run("--range", "24h", "--json", "--top", "2");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        var root = json.RootElement;
        Assert.True(root.GetProperty("detailed").GetBoolean());
        Assert.Equal("full", root.GetProperty("coverage").GetProperty("state").GetString());
        Assert.Equal(6, root.GetProperty("summary").GetProperty("attempts").GetInt64());
        var sources = root.GetProperty("sources");
        Assert.Equal(2, sources.GetArrayLength());
        Assert.Equal("203.0.113.10", sources[0].GetProperty("address").GetString());
        Assert.Equal(2, sources[0].GetProperty("accounts").GetInt64());
        Assert.Equal(1, sources[0].GetProperty("neighbors").GetInt64());
        Assert.Equal(JsonValueKind.Null, sources[0].GetProperty("label").ValueKind);
    }

    [Fact]
    public void AGapInCoverage_IsListedAsNoDataWithItsReason()
    {
        store.Covered(Now.AddHours(-30), Now.AddHours(-10))
            .Covered(Now.AddHours(-10), Now.AddHours(-6), "service-stopped", "service not running")
            .Covered(Now.AddHours(-6), Now)
            .Append(store.Failure(60, "203.0.113.10"));

        var (exit, output, _) = Run("--range", "24h");

        Assert.Equal(0, exit);
        Assert.Contains("Coverage         gaps", output, StringComparison.Ordinal);
        Assert.Contains("2026-11-24 02:00 to 2026-11-24 06:00 UTC  (service-stopped: service not running)", output, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOldPeriod_IsAnsweredFromAggregatesAndSaysWhatIsGone()
    {
        store.Covered(Now.AddDays(-31), Now)
            .Append(store.Failure(60 * 24 * 20, "203.0.113.10", "admin"), store.Failure(60 * 24 * 20 - 1, "203.0.113.10", "sa"),
                store.Failure(10, "203.0.113.10"))
            .Write(s => new EvidenceWriter(s).Prune(Now, new EvidenceLimits()));

        var (exit, output, _) = Run("--range", "30d");

        Assert.Equal(0, exit);
        Assert.Contains("Records          hourly aggregates", output, StringComparison.Ordinal);
        Assert.Contains("(detailed records are kept 14 days)", output, StringComparison.Ordinal);
        Assert.Contains("Most tried account    not kept for this period", output, StringComparison.Ordinal);
        Assert.Contains("Failed attempts       3", output, StringComparison.Ordinal);
        var row = Assert.Single(output.Split(Environment.NewLine), l => l.StartsWith("203.0.113.10", StringComparison.Ordinal));
        Assert.Contains(" - ", row, StringComparison.Ordinal);
        Assert.Contains("account names are no longer kept", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ASourcesHistory_ListsAccountsLatestAttemptsAndItsLabel()
    {
        Attacked().Setting("labels.addresses", """{"203.0.113.0/24":"Scanner network"}""");

        var (exit, output, _) = Run("--source", "203.0.113.10", "--range", "24h");

        Assert.Equal(0, exit);
        Assert.Contains("Source           203.0.113.10  [Scanner network]", output, StringComparison.Ordinal);
        Assert.Contains("In this range    3 attempt(s), 33% on nonexistent accounts", output, StringComparison.Ordinal);
        Assert.Contains("Accounts tried   admin (2), sa (1)", output, StringComparison.Ordinal);
        Assert.Contains("Latest attempts (UTC)", output, StringComparison.Ordinal);
        Assert.Contains("2026-11-24 11:30:00  sa  unknown-account  logon type 10", output, StringComparison.Ordinal);
    }

    [Fact]
    public void ASourcesHistory_InJsonKeepsAccountsAsAList()
    {
        Attacked();

        var (exit, output, _) = Run("--source", "203.0.113.10", "--json");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        var source = json.RootElement.GetProperty("source");
        Assert.Equal(3, source.GetProperty("attempts").GetInt64());
        Assert.Equal("admin", source.GetProperty("accounts")[0].GetProperty("account").GetString());
        Assert.Equal(2, source.GetProperty("accounts")[0].GetProperty("count").GetInt64());
        Assert.Equal(3, source.GetProperty("recent").GetArrayLength());
        Assert.True(source.GetProperty("timeline").GetArrayLength() > 0);
    }

    [Fact]
    public void AnAddressNeverSeen_SaysSoWithinACoveredRange()
    {
        Attacked();

        var (exit, output, _) = Run("--source", "192.0.2.200");

        Assert.Equal(0, exit);
        Assert.Contains("First seen       never", output, StringComparison.Ordinal);
        Assert.Contains("In this range    0 attempt(s)", output, StringComparison.Ordinal);
    }

    /// <summary>The attacker chose the account name; it must not reach a terminal or a JSON consumer raw.</summary>
    [Fact]
    public void AttackerChosenAccountNames_AreCleanedForTheTerminalAndEscapedInJson()
    {
        store.Covered(Now.AddDays(-1), Now).Write(s => new EvidenceWriter(s).Append([
            new AuthFailure(Now.AddMinutes(-5), AttemptPairing.SecurityChannel, System.Net.IPAddress.Parse("203.0.113.66"), null,
                "adm\u001b[31min‮", "bad-password", 10, 900)]));

        var text = Run("--source", "203.0.113.66").Output;
        var json = Run("--source", "203.0.113.66", "--json").Output;

        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('‮', text);
        Assert.DoesNotContain('\u001b', json);
        Assert.DoesNotContain('‮', json);
        using var document = JsonDocument.Parse(json);
        Assert.StartsWith("adm", document.RootElement.GetProperty("source").GetProperty("recent")[0].GetProperty("account").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheDefaultRangeComesFromTheSetting()
    {
        Attacked().Setting("attacks.default_range", "\"7d\"");

        var (exit, output, _) = Run();

        Assert.Equal(0, exit);
        Assert.Contains("Range            last 7 days: 2026-11-17 12:00 to 2026-11-24 12:00 UTC", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--range", "2d")]
    [InlineData("--top", "0")]
    [InlineData("--top", "1001")]
    [InlineData("--source", "not-an-address")]
    [InlineData("--json", "yes")]
    [InlineData("--store", "")]
    [InlineData("--since", "7d")]
    public void ArgumentsTheCommandDoesNotUnderstand_AreRefused(string name, string value)
    {
        Attacked();

        Assert.Throws<CliArgumentException>(() => Run(name, value));
    }

    [Fact]
    public void RangesFromADayUpStartOnAWholeHourOrDayAndAreNeverShorterThanTheirName()
    {
        var now = new DateTimeOffset(2026, 11, 24, 12, 34, 56, TimeSpan.Zero);

        var day = EvidenceRanges.Window("24h", now);
        var month = EvidenceRanges.Window("30d", now);

        Assert.Equal(new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.Zero), day.From);
        Assert.Equal(new DateTimeOffset(2026, 10, 25, 0, 0, 0, TimeSpan.Zero), month.From);
        Assert.True(now - day.From >= TimeSpan.FromHours(24));
        Assert.Equal(now.AddHours(-1), EvidenceRanges.Window("1h", now).From);
    }
}
