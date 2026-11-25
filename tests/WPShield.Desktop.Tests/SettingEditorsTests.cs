using System.Text.Json.Nodes;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Desktop.Tests;

/// <summary>
/// The settings editors without a window: which editor a catalog default gets, how the table and the
/// list become JSON and back, and that the catalog - not the desktop - decides what is valid.
/// Synthetic RFC 5737 and RFC 3849 addresses only.
/// </summary>
public sealed class SettingEditorsTests
{
    private static SettingDefinition Definition(string key, JsonNode value, Func<JsonNode, string?>? validate = null) =>
        new(key, "A setting from a newer catalog.", value, SettingEffect.NextStart, validate ?? (_ => null));

    [Theory]
    [InlineData("true", nameof(SettingEditorKind.Toggle))]
    [InlineData("false", nameof(SettingEditorKind.Toggle))]
    [InlineData("14", nameof(SettingEditorKind.Number))]
    [InlineData("\"24h\"", nameof(SettingEditorKind.Text))]
    [InlineData("{}", nameof(SettingEditorKind.AddressTable))]
    [InlineData("""{"192.0.2.0/24":"Lab"}""", nameof(SettingEditorKind.AddressTable))]
    [InlineData("[]", nameof(SettingEditorKind.StringList))]
    [InlineData("""["192.0.2.7","2001:db8::/32"]""", nameof(SettingEditorKind.StringList))]
    [InlineData("""{"rule":5}""", nameof(SettingEditorKind.Json))]
    [InlineData("[1,2]", nameof(SettingEditorKind.Json))]
    [InlineData("""{"a":{"b":"c"}}""", nameof(SettingEditorKind.Json))]
    public void TheEditorFollowsTheShapeOfTheDefault(string json, string expected) =>
        Assert.Equal(Enum.Parse<SettingEditorKind>(expected), SettingEditors.KindFor(JsonNode.Parse(json)!));

    [Fact]
    public void AStoredValueWithoutItsDefaultsShapeIsEditedAsJsonRatherThanMisread()
    {
        Assert.Equal(SettingEditorKind.Json, SettingEditors.KindFor(JsonNode.Parse("{}")!, JsonNode.Parse("""{"192.0.2.7":1}""")));
        Assert.Equal(SettingEditorKind.Json, SettingEditors.KindFor(JsonValue.Create(14), JsonValue.Create("fourteen")));
        Assert.Equal(SettingEditorKind.StringList, SettingEditors.KindFor(JsonNode.Parse("[]")!, JsonNode.Parse("""["198.51.100.1"]""")));
    }

    [Fact]
    public void TheShippedSettingsGetTheEditorsOfTheirShapes()
    {
        Assert.Equal(SettingEditorKind.Number, SettingEditors.KindFor(SettingCatalog.All["retention.raw_days"].Default));
        Assert.Equal(SettingEditorKind.Text, SettingEditors.KindFor(SettingCatalog.All["attacks.default_range"].Default));
        Assert.Equal(SettingEditorKind.AddressTable, SettingEditors.KindFor(SettingCatalog.All[AddressLabels.SettingKey].Default));
        Assert.Equal(SettingEditorKind.Toggle, SettingEditors.KindFor(SettingCatalog.All["mcp.detailed_records"].Default));
    }

    [Fact]
    public void AKeyTheDesktopHasNoTranslationForUsesItsKeyAndTheCatalogsOwnDescription()
    {
        const string key = "example.future_list";
        Assert.False(SettingNames.IsKnown(key));
        Assert.Equal(key, SettingNames.Name(key, spanish: true));
        Assert.Equal("Addresses a future engine never blocks.", SettingNames.Description(key, "Addresses a future engine never blocks.", spanish: true));
        Assert.Equal("Etiquetas de direcciones", SettingNames.Name(AddressLabels.SettingKey, spanish: true));
        foreach (var known in new[] { "retention.raw_days", "retention.aggregate_days", "retention.event_days", "retention.max_megabytes",
                     "attacks.default_range", AddressLabels.SettingKey, "mcp.detailed_records" })
            Assert.True(SettingNames.IsKnown(known), known);
    }

    [Fact]
    public void AnEmptyDefaultWhoseEntriesAreNotTextCanStillBeEnteredAsJson()
    {
        // "{}" says nothing about its entries; this one wants a whole number per rule.
        var definition = Definition("example.rule_limits", new JsonObject(),
            node => node is JsonObject map && map.All(p => p.Value is JsonValue v && v.TryGetValue<int>(out _)) ? null : "a whole number per rule");
        var edit = new SettingEdit(definition, new JsonObject(), spanish: false) { Reason = "limits" };
        Assert.Equal(SettingEditorKind.AddressTable, edit.Kind);
        Assert.True(edit.CanSwitchToJson);
        edit.AddAddress("rule-a");
        edit.Addresses[0].Label = "5";
        Assert.Equal("Expected a whole number per rule.", edit.Proposed().Problem);

        Assert.True(edit.TrySetJson(true));
        Assert.Equal(SettingEditorKind.Json, edit.Kind);
        Assert.Equal("""{"rule-a":"5"}""", JsonNode.Parse(edit.Text)!.ToJsonString());
        edit.Text = """{ "rule-a": 5 }""";
        Assert.Equal(("""{"rule-a":5}""", (string?)null), edit.Proposed());
        Assert.True(edit.CanSave(writable: true));

        // Back to the table only when the JSON fits it, so nothing typed is dropped.
        Assert.False(edit.TrySetJson(false));
        Assert.Equal(SettingEditorKind.Json, edit.Kind);
        edit.Text = """{"rule-b":"x"}""";
        Assert.True(edit.TrySetJson(false));
        Assert.Equal(SettingEditorKind.AddressTable, edit.Kind);
        Assert.Equal("rule-b", Assert.Single(edit.Addresses).Address);
        Assert.Equal("x", edit.Addresses[0].Label);
    }

    [Fact]
    public void AValueAlreadyEditedAsJsonHasNoShapedEditorToSwitchTo()
    {
        var edit = new SettingEdit(SettingCatalog.All["retention.raw_days"], JsonValue.Create("fourteen"), spanish: false);
        Assert.Equal(SettingEditorKind.Json, edit.Kind);
        Assert.False(edit.CanSwitchToJson);
        Assert.True(edit.TrySetJson(true));
        Assert.False(edit.TrySetJson(false));
    }

    [Fact]
    public void TheLabelTableBecomesAnObjectInRowOrderAndComesBack()
    {
        var rows = new[]
        {
            new AddressLabelRow(" 203.0.113.0/24 ", "Scanner network "), new AddressLabelRow("", "  "),
            new AddressLabelRow("192.0.2.7", "My office"), new AddressLabelRow("2001:db8::/32", "Lab")
        };

        var (value, duplicate) = SettingEditors.Table(rows);

        Assert.Null(duplicate);
        Assert.Equal("""{"203.0.113.0/24":"Scanner network","192.0.2.7":"My office","2001:db8::/32":"Lab"}""", value!.ToJsonString());
        Assert.Null(SettingCatalog.All[AddressLabels.SettingKey].Validate(value));
        var back = SettingEditors.Rows((JsonObject)JsonNode.Parse(value.ToJsonString())!);
        Assert.Equal(["203.0.113.0/24", "192.0.2.7", "2001:db8::/32"], back.Select(r => r.Address));
        Assert.Equal(["Scanner network", "My office", "Lab"], back.Select(r => r.Label));
    }

    [Fact]
    public void ARepeatedAddressIsReportedNotSilentlyDroppedAndAHalfRowGoesToTheCatalog()
    {
        var (value, duplicate) = SettingEditors.Table([new("192.0.2.7", "One"), new("192.0.2.8", "Two"), new(" 192.0.2.7", "Three")]);
        Assert.Null(value);
        Assert.Equal("192.0.2.7", duplicate);

        // A row with only an address is kept, so the catalog can say the label is missing.
        var (half, _) = SettingEditors.Table([new("192.0.2.7", "")]);
        Assert.Equal("""{"192.0.2.7":""}""", half!.ToJsonString());
        Assert.NotNull(SettingCatalog.All[AddressLabels.SettingKey].Validate(half));
    }

    [Fact]
    public void TheListBecomesAnArrayInRowOrderAndComesBack()
    {
        var list = SettingEditors.List([new(" 198.51.100.7 "), new(""), new("203.0.113.0/24"), new("2001:db8:5::/64")]);

        Assert.Equal("""["198.51.100.7","203.0.113.0/24","2001:db8:5::/64"]""", list.ToJsonString());
        var back = SettingEditors.Items((JsonArray)JsonNode.Parse(list.ToJsonString())!);
        Assert.Equal(["198.51.100.7", "203.0.113.0/24", "2001:db8:5::/64"], back.Select(r => r.Value));
    }

    [Fact]
    public void TheCatalogsOwnMessageIsWhatTheEditorShows()
    {
        var definition = Definition("example.threshold", JsonValue.Create(5),
            node => node is JsonValue v && v.TryGetValue<int>(out var n) && n == 5 ? null : "sentinel words from the catalog");
        var edit = new SettingEdit(definition, JsonValue.Create(5), spanish: false) { Text = "6" };

        var (json, problem) = edit.Proposed();

        Assert.Equal("6", json);
        Assert.Equal("Expected sentinel words from the catalog.", problem);
        // Text that is not a number reaches the catalog too, rather than a message of the desktop's own.
        edit.Text = "six";
        Assert.Equal("Expected sentinel words from the catalog.", edit.Proposed().Problem);
        edit.Text = "5";
        Assert.Null(edit.Proposed().Problem);
    }

    [Fact]
    public void ShippedRulesAreReportedInTheCatalogsWords()
    {
        var days = new SettingEdit(SettingCatalog.All["retention.raw_days"], JsonValue.Create(14), spanish: true) { Text = "500" };
        Assert.Equal("Se espera: a whole number from 1 to 90.", days.Proposed().Problem);

        var labels = new SettingEdit(SettingCatalog.All[AddressLabels.SettingKey], new JsonObject(), spanish: false);
        labels.AddAddress("192.0.2.300");
        labels.Addresses[0].Label = "Office";
        Assert.Equal("Expected '192.0.2.300' is not an IP address or network.", labels.Proposed().Problem);
    }

    [Fact]
    public void SavingNeedsAValidChangedValueAndAReason()
    {
        var edit = new SettingEdit(SettingCatalog.All["attacks.default_range"], JsonValue.Create("24h"), spanish: false);
        Assert.False(edit.CanSave(writable: true));
        edit.Text = "7d";
        Assert.True(edit.Changed);
        Assert.False(edit.CanSave(writable: true));
        edit.Reason = "   ";
        Assert.False(edit.CanSave(writable: true));
        edit.Reason = "a week by default";
        Assert.True(edit.CanSave(writable: true));
        Assert.False(edit.CanSave(writable: false));
        edit.Text = "8d";
        Assert.False(edit.CanSave(writable: true));
        edit.Text = "24h";
        Assert.False(edit.CanSave(writable: true));
    }

    [Fact]
    public void ResettingNeedsAStoredValueAndAReason()
    {
        var edit = new SettingEdit(SettingCatalog.All["retention.raw_days"], JsonValue.Create(30), spanish: false);
        Assert.False(edit.CanReset(writable: true, isDefault: false));
        edit.Reason = "back to the default";
        Assert.True(edit.CanReset(writable: true, isDefault: false));
        Assert.False(edit.CanReset(writable: true, isDefault: true));
        Assert.False(edit.CanReset(writable: false, isDefault: false));
    }

    [Fact]
    public void NothingReadMeansNothingToSave()
    {
        var edit = new SettingEdit(SettingCatalog.All["attacks.default_range"], null, spanish: false) { Text = "7d", Reason = "why" };
        Assert.False(edit.CanSave(writable: true));
        Assert.False(edit.CanReset(writable: true, isDefault: false));
    }

    [Fact]
    public void EditsRaiseOneNotificationPerChangeIncludingRows()
    {
        var edit = new SettingEdit(SettingCatalog.All[AddressLabels.SettingKey], JsonNode.Parse("""{"192.0.2.7":"Office"}"""), spanish: false);
        var count = 0;
        edit.Edited += (_, _) => count++;
        edit.Addresses[0].Label = "Home";
        edit.AddAddress("198.51.100.1");
        edit.Addresses[1].Label = "Provider";
        edit.Addresses.RemoveAt(0);
        edit.Reason = "names";
        Assert.Equal(5, count);
        Assert.Equal("""{"198.51.100.1":"Provider"}""", edit.Proposed().Json);
    }
}
