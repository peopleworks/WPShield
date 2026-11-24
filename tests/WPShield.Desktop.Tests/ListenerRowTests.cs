using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class ListenerRowTests
{
    private static readonly ListenerRow Row = new("TCP", "fe80::1%2", 1433, "IPv6", "ms-sql-s", 42, "42", "");

    [Theory]
    [InlineData(null, "", true)]
    [InlineData("UDP", "", false)]
    [InlineData("TCP", "FE80::1%2", true)]
    [InlineData("TCP", "SQL", true)]
    [InlineData("TCP", "1433", true)]
    [InlineData("TCP", "143", false)]
    [InlineData("TCP", "42", true)]
    public void FiltersObservedRows(string? protocol, string query, bool expected) =>
        Assert.Equal(expected, Row.Matches(protocol, query));

    [Fact]
    public void FindsARowByProcessName()
    {
        var named = Row with { ProcessName = "sqlservr" };
        Assert.True(named.Matches(null, "SQLSERVR"));
        Assert.True(named.Matches("TCP", "sqlserv"));
        Assert.False(Row.Matches(null, "sqlservr"));
    }

    [Theory]
    [InlineData("access-denied", "acceso denegado", "access denied")]
    [InlineData("not-observed", "no aparece en la tabla de propietarios", "not in the owner table")]
    [InlineData("ambiguous", "propietario ambiguo", "ambiguous owner")]
    [InlineData("pid-unavailable", "PID no disponible", "PID unavailable")]
    [InlineData("query-failed", "la consulta falló", "query failed")]
    [InlineData("invalid-table", "tabla no válida", "invalid table")]
    [InlineData("table-limit", "tabla demasiado grande", "table too large")]
    [InlineData("name-lookup-limit", "límite de consultas de nombres", "name lookup limit reached")]
    [InlineData("name-unavailable", "terminó o no se pudo leer", "ended or unreadable")]
    [InlineData("start-not-before-sample", "inicio no anterior a la lectura del PID", "start time at or after PID observation")]
    public void ReasonCodesAreTranslated(string code, string spanish, string english)
    {
        Assert.Equal(spanish, ListenerWindow.Reason(code, spanish: true));
        Assert.Equal(english, ListenerWindow.Reason(code, spanish: false));
    }

    [Fact]
    public void AnUnknownReasonCodeIsShownCleaned() =>
        Assert.Equal("new�code", ListenerWindow.Reason("new\u001bcode", spanish: true));

    [Fact]
    public void SelectionFollowsTheBindingAcrossOwnerChanges()
    {
        var unknownOwner = Row with { ProcessId = null, Owner = "—" };
        Assert.False(unknownOwner.Matches(null, "42"));
        Assert.Equal(Row.Key, unknownOwner.Key);
        Assert.NotEqual(Row.Key, (Row with { Protocol = "UDP" }).Key);
        Assert.NotEqual(Row.Key, (Row with { Address = "fe80::1%3" }).Key);
    }
}
