namespace WPShield.Cli.Tests;

/// <summary>
/// The argument parser, which is hand-written rather than a package — see the remarks on
/// <see cref="CliOptions"/> and ADR 0003. Hand-written means tested rather than trusted.
/// </summary>
public sealed class CliOptionsTests
{
    [Fact]
    public void ASeparateValue_IsRead()
    {
        Assert.Equal("C:\\logs", CliOptions.Parse(["--log-path", "C:\\logs"]).Get("--log-path"));
    }

    [Fact]
    public void AnEqualsValue_IsRead()
    {
        Assert.Equal("C:\\logs", CliOptions.Parse(["--log-path=C:\\logs"]).Get("--log-path"));
    }

    [Fact]
    public void OptionNamesAreCaseInsensitive()
    {
        Assert.Equal("x", CliOptions.Parse(["--Log-Path", "x"]).Get("--log-path"));
    }

    [Fact]
    public void ABareOption_IsAFlag()
    {
        var options = CliOptions.Parse(["--dry-run"]);

        Assert.True(options.Flag("--dry-run"));
        Assert.True(options.Has("--dry-run"));
    }

    [Fact]
    public void AnAbsentFlag_IsFalse()
    {
        Assert.False(CliOptions.Parse([]).Flag("--dry-run"));
    }

    /// <summary>
    /// A flag followed by another option must not swallow it. <c>--dry-run --output x</c> is two
    /// options, and reading it as one would run the real thing while the operator believed they were
    /// previewing it.
    /// </summary>
    [Fact]
    public void AFlagDoesNotSwallowTheNextOption()
    {
        var options = CliOptions.Parse(["--dry-run", "--output", "report.jsonl"]);

        Assert.True(options.Flag("--dry-run"));
        Assert.Equal("report.jsonl", options.Get("--output"));
    }

    [Fact]
    public void ExplicitFalse_TurnsAFlagOff()
    {
        Assert.False(CliOptions.Parse(["--dry-run", "false"]).Flag("--dry-run"));
    }

    [Fact]
    public void AListIsCommaSeparatedAndTrimmed()
    {
        Assert.Equal(["one", "two"], CliOptions.Parse(["--site", " one , two "]).List("--site"));
    }

    [Fact]
    public void AnAbsentList_IsEmpty()
    {
        Assert.Empty(CliOptions.Parse([]).List("--site"));
    }

    [Fact]
    public void AnIntegerListFallsBackWhenAbsent()
    {
        Assert.Equal([8081, 8082], CliOptions.Parse([]).IntegerList("--private-port", [8081, 8082]));
    }

    [Fact]
    public void AnIntegerListIsParsed()
    {
        Assert.Equal([9001, 9002], CliOptions.Parse(["--private-port", "9001,9002"]).IntegerList("--private-port", []));
    }

    /// <summary>
    /// An operator who typed <c>--gateway-port 1000O</c> has not asked for the default. Falling back
    /// silently would run the whole check against a port they never named.
    /// </summary>
    [Fact]
    public void ANumberThatIsNotANumber_IsAnErrorRatherThanTheFallback()
    {
        var exception = Assert.Throws<CliArgumentException>(
            () => CliOptions.Parse(["--gateway-port", "1000O"]).Integer("--gateway-port", 10000));

        Assert.Contains("must be a number", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAbsentNumber_UsesTheFallback()
    {
        Assert.Equal(10000, CliOptions.Parse([]).Integer("--gateway-port", 10000));
    }

    /// <summary>
    /// The reason this exists: a misspelled option that is silently ignored would let
    /// <c>--dry-runn</c> run the real thing.
    /// </summary>
    [Fact]
    public void AnUnknownOption_IsRefusedAndTheKnownOnesAreListed()
    {
        var exception = Assert.Throws<CliArgumentException>(
            () => CliOptions.Parse(["--dry-runn"]).RejectUnknown("--dry-run", "--output"));

        Assert.Contains("--dry-runn", exception.Message, StringComparison.Ordinal);
        Assert.Contains("--dry-run", exception.Message, StringComparison.Ordinal);
        Assert.Contains("--output", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void KnownOptions_AreAccepted()
    {
        CliOptions.Parse(["--output", "x"]).RejectUnknown("--output");
    }

    [Fact]
    public void AVerbWithNoOptions_RefusesAnyOption()
    {
        Assert.Throws<CliArgumentException>(() => CliOptions.Parse(["--anything"]).RejectUnknown());
    }

    /// <summary>Positional tokens are ignored rather than misread as values of nothing.</summary>
    [Fact]
    public void LooseTokensBeforeAnyOption_AreIgnored()
    {
        var options = CliOptions.Parse(["stray", "--output", "x"]);

        Assert.Equal("x", options.Get("--output"));
        Assert.False(options.Has("stray"));
    }
}
