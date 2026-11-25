using System.Text.Json;
using Microsoft.Data.Sqlite;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

/// <summary>What the settings window may do with the store, and why not when it may not.</summary>
internal enum SettingsAccess
{
    /// <summary>Elevated, and the store was read: values can be changed.</summary>
    Writable,
    /// <summary>The store was read, but this process is not elevated, so nothing can be changed.</summary>
    ReadOnly,
    /// <summary>Not elevated, and the store could not be opened: nobody looked. Not the same as "missing".</summary>
    CouldNotLook,
    /// <summary>Elevated, and the evidence directory does not exist: the service was never installed.</summary>
    NoDirectory,
    /// <summary>Elevated, the directory exists, the store file does not: the service has not written yet.</summary>
    NoStore,
    /// <summary>Elevated, and still refused by the folder's permissions.</summary>
    AccessDenied,
    /// <summary>Another build of WPShield wrote the store.</summary>
    Schema,
    /// <summary>SQLite could not read it.</summary>
    Unreadable
}

/// <summary>One read of the settings. <see cref="Values"/> is empty unless the store was read.</summary>
internal sealed record SettingsSnapshot(SettingsAccess Access, IReadOnlyList<SettingValue> Values, string? Problem)
{
    internal bool Read => Access is SettingsAccess.Writable or SettingsAccess.ReadOnly;
}

/// <summary>A change made elsewhere since the window read the value. Saving now would undo it.</summary>
internal sealed class SettingConflictException(SettingValue now) : Exception($"{now.Key} changed after it was read.")
{
    /// <summary>The value as it is in the store now.</summary>
    public SettingValue Now { get; } = now;
}

/// <summary>
/// The evidence store, as the settings window asks it. Every call opens the store and closes it
/// again, so the window never holds the file open, and the service keeps writing in between.
/// </summary>
internal interface ISettingsStore
{
    string Path { get; }

    /// <summary>The settings this build accepts; the window lists and edits exactly these.</summary>
    IReadOnlyDictionary<string, SettingDefinition> Catalog { get; }

    SettingsSnapshot Read();

    IReadOnlyList<SettingChange> History(string key);

    /// <summary>Stores a value. <paramref name="loaded"/> is the value's stamp when the window read it.</summary>
    SettingChange Save(string key, string json, string reason, SettingStamp loaded);

    SettingChange Reset(string key, string reason, SettingStamp loaded);
}

/// <summary>Which version of a value the window read: a change made elsewhere since then changes it.</summary>
internal readonly record struct SettingStamp(long Version, DateTimeOffset? UpdatedAt)
{
    internal static SettingStamp Of(SettingValue value) => new(value.Version, value.UpdatedAt);
}

/// <summary>
/// Reads through <see cref="EvidenceAccess.OpenReadOnly"/> and writes through
/// <see cref="EvidenceAccess.OpenForSettings"/>, the same two doors as <c>wpshield settings</c>.
/// </summary>
/// <remarks>
/// <para>
/// Writing never creates anything. <see cref="EvidenceAccess.OpenForSettings"/> first opens the store
/// read-only, which fails when the file or its directory is missing or has another schema; only then
/// does it open it for writing. <see cref="EvidenceStore.OpenForWriting"/> alone would create a
/// missing file in an existing directory, and the service owns that file.
/// </para>
/// <para>
/// The store is opened for writing only for the length of one change. The service may be writing at
/// the same moment; SQLite's WAL and the store's busy timeout serialise the two, and a change that
/// still cannot get the lock fails with the reason instead of waiting forever.
/// </para>
/// <para>
/// Before writing, the value's version is compared with the one the window read. A change made
/// elsewhere in between (the CLI, another window) is refused rather than overwritten, because a
/// value is replaced whole: saving a label table read before someone else added a label would
/// remove it. This is best effort - the comparison and the change are two transactions - and it
/// narrows the race to milliseconds; it does not close it.
/// </para>
/// </remarks>
internal sealed class EvidenceSettingsStore(string path, Func<bool> elevated, Func<string> user) : ISettingsStore
{
    public string Path => path;

    public IReadOnlyDictionary<string, SettingDefinition> Catalog => SettingCatalog.All;

    public SettingsSnapshot Read()
    {
        var isElevated = elevated();
        try
        {
            using var store = EvidenceAccess.OpenReadOnly(path, isElevated);
            var values = new EvidenceSettings(store).List();
            return new(isElevated ? SettingsAccess.Writable : SettingsAccess.ReadOnly, values, null);
        }
        catch (EvidenceAccessException ex)
        {
            var access = ex.Problem switch
            {
                EvidenceProblem.Missing => System.IO.Directory.Exists(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path)))
                    ? SettingsAccess.NoStore : SettingsAccess.NoDirectory,
                EvidenceProblem.NotElevated => SettingsAccess.CouldNotLook,
                EvidenceProblem.AccessDenied => SettingsAccess.AccessDenied,
                EvidenceProblem.Schema => SettingsAccess.Schema,
                _ => SettingsAccess.Unreadable
            };
            return new(access, [], DisplayText.Clean(ex.Message, 400));
        }
        catch (Exception ex) when (ex is SqliteException or InvalidOperationException or InvalidCastException or JsonException)
        {
            return new(SettingsAccess.Unreadable, [], DisplayText.Clean(ex.Message, 400));
        }
    }

    public IReadOnlyList<SettingChange> History(string key)
    {
        using var store = EvidenceAccess.OpenReadOnly(path, elevated());
        return new EvidenceSettings(store).History(key, 50);
    }

    public SettingChange Save(string key, string json, string reason, SettingStamp loaded) =>
        Change(key, loaded, settings => settings.Set(key, json, user(), reason));

    public SettingChange Reset(string key, string reason, SettingStamp loaded) =>
        Change(key, loaded, settings => settings.Reset(key, user(), reason));

    private SettingChange Change(string key, SettingStamp loaded, Func<EvidenceSettings, SettingChange> change)
    {
        if (!elevated()) throw new InvalidOperationException("Changing a setting needs administrator rights.");
        using var store = EvidenceAccess.OpenForSettings(path, elevated: true);
        var settings = new EvidenceSettings(store);
        var now = settings.List().Single(v => v.Key == key);
        if (SettingStamp.Of(now) != loaded) throw new SettingConflictException(now);
        return change(settings);
    }
}
