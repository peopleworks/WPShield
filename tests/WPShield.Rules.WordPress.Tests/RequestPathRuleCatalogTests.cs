using WPShield.Abstractions;
using WPShield.Rules.Windows;
using WPShield.Rules.WordPress;

namespace WPShield.Rules.WordPress.Tests;

/// <summary>
/// The catalog the gateway registers and the IIS log sensor evaluates holds every shipped path rule,
/// once. A rule added to a package but not to the catalog would be run by neither.
/// </summary>
public sealed class RequestPathRuleCatalogTests
{
    [Fact]
    public void TheCatalogHoldsEveryShippedRequestPathRuleExactlyOnce()
    {
        var shipped = new[] { typeof(UnsafeRequestPathRule).Assembly, typeof(ExecutableRequestUnderUploadsRule).Assembly }
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => type is { IsClass: true, IsAbstract: false } && typeof(IRequestPathRule).IsAssignableFrom(type))
            .Select(type => type.FullName)
            .Order(StringComparer.Ordinal);

        var catalog = RequestPathRuleCatalog.Create().Select(rule => rule.GetType().FullName).ToArray();

        Assert.Equal(catalog.Length, catalog.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(shipped, catalog.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void EveryRuleIdIsDistinct()
    {
        var ids = RequestPathRuleCatalog.Create().Select(rule => rule.Id).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void EachCallReturnsNewInstances()
    {
        Assert.NotSame(RequestPathRuleCatalog.Create()[0], RequestPathRuleCatalog.Create()[0]);
    }
}
