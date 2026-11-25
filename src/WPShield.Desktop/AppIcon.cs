using System.IO.Packaging;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace WPShield.Desktop;

/// <summary>
/// The WPShield icon (the sidebar's badge: a dark shield with a check on mint) for every window's title bar
/// and taskbar button. The executable carries the same file as its <c>ApplicationIcon</c>.
/// </summary>
/// <remarks>
/// Set once for the class rather than in each window's XAML, so a window added later gets it without
/// anyone remembering to. A window that sets its own icon keeps it.
/// </remarks>
internal static class AppIcon
{
    /// <summary>
    /// The icon inside this assembly. Naming <see cref="PackUriHelper.UriSchemePack"/> registers the
    /// <c>pack</c> scheme, which no Application object has done yet in a test or before startup.
    /// </summary>
    internal static readonly Uri Location =
        new($"{PackUriHelper.UriSchemePack}://application:,,,/WPShield.Desktop;component/Assets/wpshield.ico", UriKind.Absolute);

    private static ImageSource? icon;

    /// <summary>The icon, decoded once. Every size the file carries stays available to Windows.</summary>
    internal static ImageSource Image => icon ??= Load();

    /// <summary>Gives every window that has no icon of its own the WPShield icon when it initializes.</summary>
    internal static void ApplyToEveryWindow() =>
        EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent, new RoutedEventHandler(OnLoaded));

    internal static void Apply(Window window)
    {
        if (window.Icon is null) window.Icon = Image;
    }

    private static void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is Window window) Apply(window);
    }

    private static BitmapFrame Load()
    {
        var frame = BitmapFrame.Create(Location, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
        frame.Freeze();
        return frame;
    }
}
