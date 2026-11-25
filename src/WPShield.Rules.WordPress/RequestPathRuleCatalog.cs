using WPShield.Abstractions;
using WPShield.Rules.Windows;

namespace WPShield.Rules.WordPress;

/// <summary>
/// Every request-path rule WPShield ships, in evaluation order: the one list the gateway registers and
/// the IIS log sensor evaluates (ADR 0011).
/// </summary>
/// <remarks>
/// <para>
/// <b>One list, two consumers.</b> The gateway judges live requests and the log sensor judges the
/// requests IIS wrote down. If each kept its own list, a rule added to one would be silently missing
/// from the other, and the two answers about the same request would disagree. The gateway's
/// registration test and this package's test compare both against the rules the packages contain.
/// </para>
/// <para>
/// It lives here because this is the layer that sees both rule packages: <c>Rules.WordPress</c>
/// references <c>Rules.Windows</c>, never the reverse (ADR 0004, exit condition 1).
/// </para>
/// <para>
/// The order is the gateway's evaluation order. It does not change an outcome, because findings are
/// summed rather than the first one taken; it is grouped for a reader: the WordPress path rules, the
/// IIS path-shape rule, then the exposure family, which was chosen against a week of real IIS logs
/// and matches shapes, never a scanner's list of paths.
/// </para>
/// </remarks>
public static class RequestPathRuleCatalog
{
    /// <summary>New instances of every shipped request-path rule. The rules hold no state.</summary>
    public static IReadOnlyList<IRequestPathRule> Create() =>
    [
        new ExecutableRequestUnderUploadsRule(),
        new ExecutableRequestInAssetDirectoryRule(),
        new UnsafeRequestPathRule(),
        new DotEnvRequestRule(),
        new VersionControlRequestRule(),
        new CredentialStoreRequestRule(),
        new BackupCopyRequestRule(),
        new DatabaseDumpRequestRule(),
        new IisConfigurationRequestRule(),
        new AppSettingsRequestRule(),
        new PhpUnitRequestRule(),
        new PhpInfoRequestRule()
    ];
}
