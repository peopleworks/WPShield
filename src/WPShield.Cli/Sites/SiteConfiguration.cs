using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WPShield.Cli.Sites;

/// <summary>One site as the operator declared it, and as the gateway will read it.</summary>
internal sealed record SiteEntry
{
    public required string Id { get; init; }
    public required IReadOnlyList<string> Hosts { get; init; }
    public required int DestinationPort { get; init; }
    public string Mode { get; init; } = "Monitor";
    public int ObserveThreshold { get; init; } = 30;
    public int BlockThreshold { get; init; } = 80;

    public string Destination => FormattableString.Invariant($"http://127.0.0.1:{DestinationPort}");
}

/// <summary>
/// Reads and writes the gateway's site table, so that no operator ever hand-authors JSON again.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the piece that was missing.</b> Nine verbs existed and none of them could configure a
/// site; the operator had to invent <c>appsettings.Local.json</c> from an example, and a deployment
/// that skipped it produced a gateway resolving nothing, a blank <c>watch</c>, and — before the guard
/// added alongside this — an <c>enable</c> that would have pointed a live site at a 421.
/// </para>
/// <para>
/// <b>It also neutralises the shipped placeholders, and that is not tidiness.</b> JSON configuration
/// merges arrays element by element, including the nested <c>Hosts</c> array, so an overlay declaring
/// one site leaves the surplus <c>.example</c> entries from <c>appsettings.json</c> live and
/// routable. The gateway refuses to start on exactly that mixture — real hostnames beside
/// documentation placeholders — so writing only the overlay would produce a service that will not
/// start, which is a worse outcome than the one being fixed. Emptying the shipped <c>Sites</c> array
/// in the <i>installed</i> copy makes the overlay authoritative and removes the whole class of
/// merge-by-position confusion. The file is backed up first, and a re-publish restores it.
/// </para>
/// </remarks>
internal sealed class SiteConfiguration
{
    public const string OverlayFileName = "appsettings.Local.json";
    public const string ShippedFileName = "appsettings.json";

    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        WriteIndented = true
    };

    private static readonly JsonDocumentOptions ReadOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private readonly string _directory;

    public SiteConfiguration(string installDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installDirectory);
        _directory = installDirectory;
    }

    public string OverlayPath => Path.Combine(_directory, OverlayFileName);

    public string ShippedPath => Path.Combine(_directory, ShippedFileName);

    /// <summary>The sites the overlay declares, which after <see cref="Save"/> is the whole table.</summary>
    public IReadOnlyList<SiteEntry> Read()
    {
        if (!File.Exists(OverlayPath))
        {
            return [];
        }

        try
        {
            var root = JsonNode.Parse(File.ReadAllText(OverlayPath), documentOptions: ReadOptions);
            if (root?["Sites"] is not JsonArray sites)
            {
                return [];
            }

            return [.. sites.OfType<JsonObject>().Select(FromJson).OfType<SiteEntry>()];
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new CliArgumentException(
                $"{OverlayPath} could not be read as JSON: {exception.Message}. Fix or remove it and run this again.");
        }
    }

    /// <summary>
    /// Writes the whole table into the overlay and neutralises the shipped placeholder sites.
    /// </summary>
    /// <returns>True when the shipped file was changed, so the caller can report it.</returns>
    public bool Save(IReadOnlyList<SiteEntry> sites)
    {
        ArgumentNullException.ThrowIfNull(sites);

        WriteOverlay(sites);
        return NeutraliseShippedSites();
    }

    private void WriteOverlay(IReadOnlyList<SiteEntry> sites)
    {
        // Preserve anything else the operator put in the overlay - a Logging override, a rate limit
        // rule. Only the Sites array is ours to own.
        JsonObject root;
        if (File.Exists(OverlayPath))
        {
            Backup(OverlayPath);
            root = JsonNode.Parse(File.ReadAllText(OverlayPath), documentOptions: ReadOptions) as JsonObject
                ?? new JsonObject();
        }
        else
        {
            root = new JsonObject();
        }

        root["Sites"] = new JsonArray([.. sites.Select(ToJson)]);
        Write(OverlayPath, root);
    }

    /// <summary>
    /// Empties <c>Sites</c> in the installed <c>appsettings.json</c> so the overlay is the only source
    /// of the site table. See the remarks on this type for why this is necessary rather than tidy.
    /// </summary>
    private bool NeutraliseShippedSites()
    {
        if (!File.Exists(ShippedPath))
        {
            return false;
        }

        try
        {
            if (JsonNode.Parse(File.ReadAllText(ShippedPath), documentOptions: ReadOptions) is not JsonObject root)
            {
                return false;
            }

            if (root["Sites"] is not JsonArray shipped || shipped.Count == 0)
            {
                return false;
            }

            Backup(ShippedPath);
            root["Sites"] = new JsonArray();
            Write(ShippedPath, root);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new CliArgumentException(
                $"{ShippedPath} could not be rewritten: {exception.Message}. The site was not saved.");
        }
    }

    private static void Backup(string path)
    {
        var backup = path + ".bak";
        try
        {
            File.Copy(path, backup, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A backup that cannot be written must not stop the change, but it must not be claimed
            // either - nothing here reports having made one.
        }
    }

    private static void Write(string path, JsonObject root)
    {
        try
        {
            File.WriteAllText(path, root.ToJsonString(WriteOptions) + Environment.NewLine, new UTF8Encoding(false));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CliArgumentException(
                $"{path} could not be written: {exception.Message}. Run from an elevated prompt.");
        }
    }

    private static JsonObject ToJson(SiteEntry site) => new()
    {
        ["Id"] = site.Id,
        ["Hosts"] = new JsonArray([.. site.Hosts.Select(host => JsonValue.Create(host))]),
        ["Destination"] = site.Destination,
        ["Mode"] = site.Mode,
        ["ObserveThreshold"] = site.ObserveThreshold,
        ["BlockThreshold"] = site.BlockThreshold
    };

    private static SiteEntry? FromJson(JsonObject site)
    {
        var id = site["Id"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        var hosts = site["Hosts"] is JsonArray array
            ? array.Select(node => node?.GetValue<string>()).OfType<string>().Where(host => !string.IsNullOrWhiteSpace(host)).ToArray()
            : [];

        var port = 0;
        if (site["Destination"]?.GetValue<string>() is { } destination &&
            Uri.TryCreate(destination, UriKind.Absolute, out var uri))
        {
            port = uri.Port;
        }

        return new SiteEntry
        {
            Id = id,
            Hosts = hosts,
            DestinationPort = port,
            Mode = site["Mode"]?.GetValue<string>() ?? "Monitor",
            ObserveThreshold = TryInt(site["ObserveThreshold"]) ?? 30,
            BlockThreshold = TryInt(site["BlockThreshold"]) ?? 80
        };
    }

    private static int? TryInt(JsonNode? node)
    {
        try
        {
            return node?.GetValue<int>();
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            return null;
        }
    }
}
