using Microsoft.Extensions.Options;

namespace WPShield.Gateway;

/// <summary>All default options readers see the policy used by requests, including readers first
/// resolved after a configuration edit. Named options keep their normal framework behavior.</summary>
internal sealed class StartupGatewayOptionsFactory(GatewayOptions active, OptionsFactory<GatewayOptions> namedOptions)
    : IOptionsFactory<GatewayOptions>
{
    public GatewayOptions Create(string name) => name == Options.DefaultName ? active : namedOptions.Create(name);
}
