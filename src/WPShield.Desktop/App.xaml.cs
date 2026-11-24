using System.Globalization;
using System.Windows;
using System.Windows.Threading;

namespace WPShield.Desktop;

public partial class App : Application
{
    private bool reporting;

    protected override void OnStartup(StartupEventArgs e)
    {
        // A read that fails in a way nobody anticipated must not close the monitor. The operator is
        // usually looking at it because the server is having a bad day; losing the window then is the
        // worst outcome. The views that know how to fail say so themselves; this is the backstop.
        DispatcherUnhandledException += OnUnhandled;
        TaskScheduler.UnobservedTaskException += (_, args) => args.SetObserved();
        base.OnStartup(e);
    }

    internal static bool Spanish()
    {
        var args = Environment.GetCommandLineArgs();
        return args.Contains("--es") || (!args.Contains("--en") && CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "es");
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        // One message at a time: an automatic refresh that keeps failing must not stack dialogs.
        if (reporting) return;
        reporting = true;
        try
        {
            var spanish = Spanish();
            MessageBox.Show(
                (spanish ? "Una lectura falló de forma inesperada. La ventana sigue abierta.\n\n"
                         : "A read failed unexpectedly. The window stays open.\n\n") +
                DisplayText.Clean(e.Exception.GetType().Name + ": " + e.Exception.Message, 400),
                "WPShield", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            reporting = false;
        }
    }
}
