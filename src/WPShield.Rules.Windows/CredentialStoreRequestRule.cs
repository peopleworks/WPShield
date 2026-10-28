using System.Collections.Frozen;
using WPShield.Abstractions;

namespace WPShield.Rules.Windows;

/// <summary>
/// <c>EXPOSE-PATH-003</c> - a request for a credential store or a developer tool's state.
/// </summary>
/// <remarks>
/// <para>
/// These are the files that live in a developer's home or project folder and grant access to
/// something else: cloud keys (<c>.aws/credentials</c>, <c>.config/gcloud</c>, <c>.azure</c>), cluster
/// and registry logins (<c>.kube/config</c>, <c>.docker/config.json</c>), SSH private keys, package
/// registry tokens (<c>.npmrc</c>, <c>.pypirc</c>), stored Git credentials, and the state of the tools
/// that deploy from a workstation - <c>.vscode/sftp.json</c> holds an FTP password,
/// <c>.terraform</c> holds state with secrets in it, and the folders AI coding assistants keep their
/// credentials in are probed by name too. They reach a web root when a project folder is copied up
/// whole. A week of logs from a shared Windows host carried about 7,500 requests for them across 50
/// sites.
/// </para>
/// <para>
/// <b>Exact names, in any position</b>, drawn from what those logs actually requested, and the SSH key
/// family by name: <c>id_rsa</c>, <c>id_dsa</c>, <c>id_ecdsa</c>, <c>id_ed25519</c>, alone or with a
/// suffix such as <c>.pub</c> or <c>.bak</c>. <c>.github</c> and <c>.gitlab-ci.yml</c> are
/// deliberately absent: a CI definition names its secrets rather than holding them.
/// </para>
/// <para>
/// <b>Score 100.</b> None of these has a legitimate HTTP caller on a web server.
/// </para>
/// </remarks>
public sealed class CredentialStoreRequestRule : IRequestPathRule
{
    internal const int Score = 100;

    /// <summary>Folders that hold credentials or a tool's state, never content.</summary>
    private static readonly FrozenSet<string> Folders = new[]
    {
        ".aws", ".azure", ".config", ".docker", ".gcloud", ".kube", ".ssh",
        ".claude", ".codex", ".idea", ".terraform", ".vscode"
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>Single files that hold a credential.</summary>
    private static readonly FrozenSet<string> Files = new[]
    {
        ".git-credentials", ".gitconfig", ".netrc", ".npmrc", ".pypirc", ".pgpass", ".my.cnf",
        ".s3cfg", ".boto", ".dockercfg", ".htpasswd", ".msmtprc", ".esmtprc"
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly string[] PrivateKeys = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"];

    public string Id => "EXPOSE-PATH-003";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var match = context.NormalizedPath.FirstAcrossViews(view => PathSegments.Any(view, Classify));

        return ValueTask.FromResult(match is null
            ? null
            : PathSegments.Finding(Id, Score, "Findings.CredentialStoreRequest", match, "kind"));
    }

    internal static string? Classify(string segment)
    {
        if (Folders.Contains(segment))
        {
            return "folder";
        }

        if (Files.Contains(segment))
        {
            return "file";
        }

        foreach (var key in PrivateKeys)
        {
            if (segment == key ||
                (segment.Length > key.Length && segment.StartsWith(key, StringComparison.Ordinal) && segment[key.Length] == '.'))
            {
                return "privateKey";
            }
        }

        return null;
    }
}
