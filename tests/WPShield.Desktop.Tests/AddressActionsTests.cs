using System.Text.Json.Nodes;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>Label and Allow, decided without a window. Synthetic RFC 5737 and RFC 3849 addresses only.</summary>
public sealed class AddressActionsTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

    private static DecisionRecord Decision(string action, string target, DateTimeOffset? expires) =>
        new(Now.AddMinutes(-5), action, target, DecisionRules.RepeatedFailures, DecisionActions.MonitorMode, "10 failed logons", "security-4625", expires);

    private static ActiveDecisions Active(params DecisionRecord[] decisions) => new(Now, Now.AddHours(-1), Now, true, decisions, false);

    [Theory]
    [InlineData("203.0.113.45", "203.0.113.45")]
    [InlineData(" 2001:DB8::5 ", "2001:db8::5")]
    [InlineData("::ffff:203.0.113.45", "203.0.113.45")]
    [InlineData("203.0.113.0/24", null)]
    [InlineData("not an address", null)]
    [InlineData(null, null)]
    public void OnlyASingleAddressIsActedOnInTheFormTheStoreKeeps(string? text, string? expected) =>
        Assert.Equal(expected, AddressActions.Canonical(text));

    [Fact]
    public void ALabelSetsOrReplacesOnlyTheAddresssOwnEntry()
    {
        var stored = JsonNode.Parse("""{"203.0.113.0/24":"Scanner network","192.0.2.7":"Office","203.0.113.45":"Old"}""");

        var changed = Assert.IsType<JsonObject>(AddressActions.WithLabel(stored, "203.0.113.45", "  Partner  "));

        Assert.Equal("Partner", changed["203.0.113.45"]!.GetValue<string>());
        Assert.Equal("Scanner network", changed["203.0.113.0/24"]!.GetValue<string>());
        Assert.Equal("Office", changed["192.0.2.7"]!.GetValue<string>());
        Assert.Equal(3, changed.Count);
        // The stored value is not touched: the change is a copy, compared with the stamp on save.
        Assert.Equal("Old", stored!["203.0.113.45"]!.GetValue<string>());
        Assert.Null(AddressActions.Check(AddressAction.Label, changed));
    }

    [Fact]
    public void ANetworksLabelIsNotTheAddresssOwnAndTheCatalogBoundsTheText()
    {
        var stored = JsonNode.Parse("""{"203.0.113.0/24":"Scanner network"}""");
        Assert.Null(AddressActions.OwnLabel(stored, "203.0.113.45"));
        Assert.Equal("Scanner network", AddressActions.OwnLabel(stored, "203.0.113.0/24"));

        var tooLong = AddressActions.WithLabel(stored, "203.0.113.45", new string('x', 65))!;
        Assert.Contains("1 to 64 characters", AddressActions.Check(AddressAction.Label, tooLong), StringComparison.Ordinal);
        // A value of another shape is left for the Settings window rather than overwritten.
        Assert.Null(AddressActions.WithLabel(JsonNode.Parse("[]"), "203.0.113.45", "x"));
    }

    [Fact]
    public void AllowAddsExactlyTheAddressAndNeverItsNetwork()
    {
        var stored = JsonNode.Parse("""["192.0.2.7"]""");

        var changed = Assert.IsType<JsonArray>(AddressActions.WithAllowed(stored, "203.0.113.45"));

        var entries = changed.Select(e => e!.GetValue<string>()).ToArray();
        Assert.Equal(["192.0.2.7", "203.0.113.45"], entries);
        Assert.DoesNotContain(entries, e => e.Contains('/', StringComparison.Ordinal));
        Assert.Null(AddressActions.Check(AddressAction.Allow, changed));
        Assert.Equal(["203.0.113.45"], AddressActions.WithAllowed(new JsonArray(), "203.0.113.45")!.Select(e => e!.GetValue<string>()));
        Assert.Null(AddressActions.WithAllowed(JsonNode.Parse("{}"), "203.0.113.45"));
    }

    [Fact]
    public void AnAddressTheListAlreadyCoversIsSaidRatherThanAddedAgain()
    {
        var stored = JsonNode.Parse("""["198.51.100.7", "203.0.113.0/24", "2001:db8:5::/48"]""");

        Assert.Equal("198.51.100.7", AddressActions.AllowedBy(stored, "198.51.100.7"));
        Assert.Equal("203.0.113.0/24", AddressActions.AllowedBy(stored, "203.0.113.45"));
        Assert.Equal("2001:db8:5::/48", AddressActions.AllowedBy(stored, "2001:db8:5::17"));
        Assert.Null(AddressActions.AllowedBy(stored, "192.0.2.10"));
        Assert.Null(AddressActions.AllowedBy(stored, "2001:db8:6::1"));
    }

    [Fact]
    public void WouldBlockInForceCountsTheAddressAndItsNetworkOnlyWhileUnexpired()
    {
        var decisions = Active(
            Decision(DecisionActions.WouldBlock, "203.0.113.45", Now.AddMinutes(30)),
            Decision(DecisionActions.WouldBlock, "203.0.113.0/24", Now.AddMinutes(30)),
            Decision(DecisionActions.WouldBlock, "203.0.113.46", Now.AddMinutes(30)),
            Decision(DecisionActions.Protected, "198.51.100.7", Now.AddMinutes(30)),
            Decision(DecisionActions.WouldBlock, "198.51.100.0/24", Now.AddMinutes(-1)));

        Assert.Equal(2, AddressActions.WouldBlockInForce(decisions, "203.0.113.45", Now));
        Assert.Equal(0, AddressActions.WouldBlockInForce(decisions, "198.51.100.7", Now));
        // Nobody could look is not zero.
        Assert.Null(AddressActions.WouldBlockInForce(null, "203.0.113.45", Now));
    }

    [Theory]
    [InlineData("ReadOnly", false, "administrator")]
    [InlineData("CouldNotLook", false, "administrator")]
    [InlineData("CouldNotLook", true, "administrador")]
    [InlineData("NoStore", false, "'wpshield install'")]
    [InlineData("NoDirectory", false, "'wpshield install'")]
    [InlineData("Schema", false, "another version")]
    [InlineData("Unreadable", false, "could not be read")]
    public void WithoutElevationOrAReadableStoreBothActionsSayWhy(string access, bool spanish, string words)
    {
        var why = AddressActions.Unavailable(new SettingsSnapshot(Enum.Parse<SettingsAccess>(access), [], "synthetic"), spanish);
        Assert.Contains(words, why, StringComparison.OrdinalIgnoreCase);
        Assert.Null(AddressActions.Unavailable(new SettingsSnapshot(SettingsAccess.Writable, [], null), spanish));
        Assert.NotNull(AddressActions.Unavailable(null, spanish));
    }

    [Theory]
    [InlineData(false, "the decision engine will never decide against this address")]
    [InlineData(true, "el motor de decisiones nunca decidirá contra esta dirección")]
    public void TheConfirmationSaysPlainlyWhatAllowGivesUp(bool spanish, string words)
    {
        var text = AddressActions.AllowConfirmation("203.0.113.45", spanish);
        Assert.Contains(words, text, StringComparison.Ordinal);
        // Allowing one address also stops the network rule for its /24: said, not left to be discovered.
        Assert.Contains("203.0.113.0/24 (HOST-AUTH-003)", text, StringComparison.Ordinal);
        Assert.Contains(spanish ? "nunca su red" : "never its network", text, StringComparison.Ordinal);
    }

    [Fact]
    public void TheWarningGivesTheCountsOfGuessedNamesAndDecisionsInForce()
    {
        var source = new AttackSource("203.0.113.45", 40, Now.AddHours(-2), Now, 6, "admin", 37 / 40d, "3", "203.0.113.0/24", 1,
            UnknownAttempts: 37);

        var both = AddressActions.AllowWarning(source, 1, "the last 24 hours", spanish: false);
        Assert.Contains("in the last 24 hours 37 of its 40 attempts named accounts that do not exist", both, StringComparison.Ordinal);
        Assert.Contains("1 would-block decision is in force", both, StringComparison.Ordinal);

        Assert.Contains("2 decisiones «bloquearía» vigentes", AddressActions.AllowWarning(null, 2, "las últimas 24 horas", spanish: true),
            StringComparison.Ordinal);
        Assert.Contains("could not be read", AddressActions.AllowWarning(null, null, "the last hour", spanish: false), StringComparison.Ordinal);
        Assert.Null(AddressActions.AllowWarning(source with { UnknownAttempts = 0 }, 0, "the last 24 hours", spanish: false));
    }

    [Fact]
    public void AConflictSaysWhoChangedTheValueAndThatTheTextStays()
    {
        var now = new SettingValue(AddressLabels.SettingKey, new JsonObject(), false, 3, Now, @"WPSHIELD-LAB\cli", SettingEffect.NextUse, "labels");

        var message = AddressActions.Failure(new SettingConflictException(now), AddressLabels.SettingKey, spanish: false);

        Assert.StartsWith("Not saved: ", message, StringComparison.Ordinal);
        Assert.Contains(@"WPSHIELD-LAB\cli changed labels.addresses at 2026-11-24 12:00 UTC", message, StringComparison.Ordinal);
        Assert.Contains("Your text is still here", message, StringComparison.Ordinal);
    }
}
