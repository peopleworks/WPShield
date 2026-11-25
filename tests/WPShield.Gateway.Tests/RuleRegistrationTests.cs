using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Rules.Windows;
using WPShield.Rules.WordPress;

namespace WPShield.Gateway.Tests;

/// <summary>
/// Every rule the two packages ship is a rule the gateway runs.
/// </summary>
/// <remarks>
/// <para>
/// A rule is written in one project and registered in another, by hand, in
/// <c>GatewayApplication.RegisterInspection</c>. Forgetting the second step leaves a rule that is
/// tested, documented, listed in the changelog - and never evaluated against a single request. Nothing
/// else would notice: its own tests call it directly.
/// </para>
/// <para>
/// So the set the gateway actually resolves is compared with the set that exists, found by reflection.
/// A rule added without a registration fails here; so does a registration left behind by a rule that
/// was removed.
/// </para>
/// </remarks>
public sealed class RuleRegistrationTests
{
    [Fact]
    public async Task EveryShippedRequestPathRule_IsInTheGatewaysPathEngine()
    {
        await using var application = Build();

        var registered = application.Services.GetRequiredService<RequestPathEngine>().Rules
            .Select(rule => rule.GetType())
            .ToHashSet();

        var shipped = Shipped<IRequestPathRule>();

        Assert.NotEmpty(shipped);
        Assert.Equal(shipped.OrderBy(Name), registered.OrderBy(Name));
    }

    [Fact]
    public async Task EveryShippedUploadRule_IsRegisteredForTheUploadPass()
    {
        await using var application = Build();

        var registered = application.Services.GetServices<IInspectionRule>()
            .Select(rule => rule.GetType())
            .ToHashSet();

        var shipped = Shipped<IInspectionRule>();

        Assert.NotEmpty(shipped);
        Assert.Equal(shipped.OrderBy(Name), registered.OrderBy(Name));
    }

    /// <summary>
    /// The two passes stay apart. A path rule in the upload pass would be evaluated once per uploaded
    /// file and add its score several times for one path.
    /// </summary>
    [Fact]
    public void NoRuleIsBothAPathRuleAndAnUploadRule()
    {
        var both = Shipped<IRequestPathRule>().Intersect(Shipped<IInspectionRule>()).ToArray();

        Assert.Empty(both);
    }

    private static HashSet<Type> Shipped<TRule>() =>
    [
        .. new[] { typeof(UnsafeRequestPathRule).Assembly, typeof(ExecutableRequestUnderUploadsRule).Assembly }
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => type is { IsClass: true, IsAbstract: false } && typeof(TRule).IsAssignableFrom(type))
    ];

    private static string Name(Type type) => type.FullName ?? type.Name;

    private static WebApplication Build()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Gateway:Urls:0"] = "http://127.0.0.1:0",
            ["Sites:0:Id"] = "registration-site",
            ["Sites:0:Hosts:0"] = "registration.test",
            ["Sites:0:Destination"] = "http://127.0.0.1:51001",
            ["Sites:0:Mode"] = "Monitor"
        });

        return GatewayApplication.Build(builder);
    }
}
