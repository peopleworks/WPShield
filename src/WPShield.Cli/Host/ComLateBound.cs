using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;

namespace WPShield.Cli.Host;

/// <summary>
/// Late-bound, read-only calls on a COM automation object (the firewall policy, the Task Scheduler), through
/// <see cref="Type.InvokeMember(string, BindingFlags, Binder?, object?, object?[]?, CultureInfo?)"/> rather than
/// <c>dynamic</c>: every value comes back as <see cref="object"/> and is checked and cast by the caller, so a
/// member that is missing or of an unexpected type fails as a typed error instead of a binder surprise.
/// </summary>
/// <remarks>
/// Only reads go through here: a property get, a method that returns data, and enumerating a collection. The
/// callers never set a property, and the method names they pass are literals.
/// </remarks>
internal static class ComLateBound
{
    /// <summary>Creates the COM object registered under <paramref name="progId"/>, or <see langword="null"/> when none is.</summary>
    public static object? Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId);
        return type is null ? null : Activator.CreateInstance(type);
    }

    /// <summary>Calls a method and returns what it returns.</summary>
    public static object? Invoke(object target, string method, params object?[] arguments)
    {
        ArgumentNullException.ThrowIfNull(target);
        return Unwrap(() => target.GetType().InvokeMember(method, BindingFlags.InvokeMethod, null, target, arguments, CultureInfo.InvariantCulture));
    }

    /// <summary>Reads a property, with an index for a parameterised one such as <c>FirewallEnabled[profile]</c>.</summary>
    public static object? Get(object target, string property, params object?[] index)
    {
        ArgumentNullException.ThrowIfNull(target);
        return Unwrap(() => target.GetType().InvokeMember(property, BindingFlags.GetProperty, null, target,
            index.Length == 0 ? null : index, CultureInfo.InvariantCulture));
    }

    /// <summary>A property that must be an object, such as a definition or a collection.</summary>
    public static object GetObject(object target, string property) =>
        Get(target, property) ?? throw new InvalidCastException($"The COM property {property} was empty.");

    public static string? GetString(object target, string property) => Get(target, property) as string;

    public static int GetInt(object target, string property, params object?[] index) =>
        Get(target, property, index) is { } value ? Convert.ToInt32(value, CultureInfo.InvariantCulture)
            : throw new InvalidCastException($"The COM property {property} was empty.");

    public static bool GetBool(object target, string property, params object?[] index) =>
        Get(target, property, index) is bool value ? value : throw new InvalidCastException($"The COM property {property} is not a boolean.");

    public static DateTime? GetDate(object target, string property) => Get(target, property) is DateTime value ? value : null;

    /// <summary>The items of a COM collection (one that exposes <c>_NewEnum</c>), skipping empty ones.</summary>
    public static IEnumerable<object> Items(object? collection)
    {
        if (collection is not IEnumerable items) yield break;
        foreach (var item in items)
            if (item is not null) yield return item;
    }

    /// <summary>
    /// <see cref="Type.InvokeMember(string, BindingFlags, Binder?, object?, object?[]?, CultureInfo?)"/> wraps what
    /// the COM object threw; the callers handle <see cref="COMException"/> and <see cref="UnauthorizedAccessException"/>.
    /// </summary>
    private static object? Unwrap(Func<object?> call)
    {
        try
        {
            return call();
        }
        catch (TargetInvocationException exception) when (exception.InnerException is { } inner)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw();
            throw;
        }
    }
}
