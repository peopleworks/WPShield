using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;

namespace WPShield.Desktop.Demo;

internal static class Screenshots
{
    private const int Width = 1440;
    private const int Height = 900;
    private const int Dpi = 96;
    private static readonly string[] Languages = ["en", "es"];
    private static readonly string[] Views = ["command-center", "attacks", "web", "protection", "settings", "audit-references"];
    private static readonly TimeProvider Clock = new DemoClock();

    internal static readonly IReadOnlyList<string> Filenames =
        Languages.SelectMany(language => Views.Select(view => $"{view}-{language}.png")).ToArray();

    internal static async Task RenderAsync(DemoWorkspace workspace, string store, string audit)
    {
        foreach (var language in Languages)
        {
            var spanish = language == "es";
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(spanish ? "es-ES" : "en-US");
            CultureInfo.CurrentUICulture = CultureInfo.CurrentCulture;
            string Output(string view) => workspace.FilePath($"{view}-{language}.png");

            var settings = new DemoSettings(store);
            var center = new CommandCenterView(spanish, new CommandCenterStore(store, () => true).Read, Clock.GetUtcNow);
            await Capture(new ListenerWindow(spanish, center), Output("command-center"), async () =>
            {
                await center.LoadAsync();
                RequireContent(center.ProblemBox.Visibility == Visibility.Collapsed && center.Tiles.Items.Count == 8, "Command center");
            });

            AttacksWindow Attacks() => new(spanish, DemoData.RecentLogons, (_, _) => new NoWatch(),
                new EvidenceAttackStore(store, () => true), settings, new EvidenceWebStore(store, () => true, Clock.GetUtcNow), Clock);
            var attacks = Attacks();
            await Capture(attacks, Output("attacks"), async () =>
            {
                await attacks.LoadAsync();
                RequireContent(attacks.Rows.HasItems, "Attacks");
            });
            var web = Attacks();
            await Capture(web, Output("web"), async () =>
            {
                await web.LoadAsync();
                web.OpenWebView();
                await web.LoadWebAsync();
                RequireContent(web.WebRows.HasItems, "Web");
            });

            var protection = new ProtectionWindow(spanish, new EvidenceProtectionStore(store, () => true),
                () => new ServiceReading(ServiceState.Running), () => { }, () => { }, Clock);
            await Capture(protection, Output("protection"), async () =>
            {
                await protection.LoadAsync();
                RequireContent(protection.Rows.HasItems, "Protection");
            });

            var configuration = new SettingsWindow(spanish, settings,
                () => new OwnConnection("203.0.113.27", OwnConnection.ThisSession, ["203.0.113.27"],
                    "203.0.113.27", null, null, DemoData.Now), DefenseSettings.Allow, Clock);
            await Capture(configuration, Output("settings"), async () =>
            {
                await configuration.LoadAsync();
                RequireContent(configuration.Snapshot?.Read == true, "Settings");
            });

            var references = new AuditReferenceWindow(spanish, _ => { });
            await Capture(references, Output("audit-references"), async () =>
            {
                await references.LoadSnapshotAsync(audit);
                RequireContent(references.Entries.HasItems, "Audit references");
            });
        }
    }

    private static async Task Capture(Window window, string path, Func<Task> load)
    {
        // Render the root visual only. A transparent, non-activating window gives WPF its normal
        // Loaded events and templates without capturing any pixels or chrome from the desktop.
        var content = (FrameworkElement)window.Content;
        window.Content = null;
        var surface = new Border
        {
            Child = content,
            Background = window.Background,
            Language = XmlLanguage.GetLanguage(CultureInfo.CurrentUICulture.Name)
        };
        TextOptions.SetTextRenderingMode(surface, TextRenderingMode.Grayscale);
        window.Content = surface;
        window.Width = Width;
        window.Height = Height;
        window.WindowStyle = WindowStyle.None;
        window.ResizeMode = ResizeMode.NoResize;
        window.ShowActivated = false;
        window.ShowInTaskbar = false;
        window.Opacity = 0;
        try
        {
            window.Show();
            await load();
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);

            // The work area may be smaller than the design size. Detach the initialized surface
            // before arranging it, so another window layout pass cannot resize it to the monitor.
            window.Content = null;
            surface.Measure(new Size(Width, Height));
            surface.Arrange(new Rect(0, 0, Width, Height));
            surface.UpdateLayout();
            var bitmap = new RenderTargetBitmap(Width, Height, Dpi, Dpi, PixelFormats.Pbgra32);
            bitmap.Render(surface);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(new FormatConvertedBitmap(bitmap, PixelFormats.Bgr24, null, 0)));
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            encoder.Save(output);
        }
        finally { window.Close(); }
    }

    private static void RequireContent(bool loaded, string view)
    {
        if (!loaded) throw new InvalidOperationException($"{view} did not load the synthetic evidence.");
    }

    private sealed class DemoClock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DemoData.Now;
    }

    private sealed class NoWatch : IDisposable
    {
        public void Dispose() { }
    }

    // The actual temporary directory may contain a user's name. The Settings subtitle reads
    // Path, while queries still open the private synthetic database through the normal reader.
    private sealed class DemoSettings(string path) : ISettingsStore
    {
        private readonly EvidenceSettingsStore inner = new(path, () => true, () => "demo-operator");

        public string Path => "demo-evidence.db";
        public IReadOnlyDictionary<string, SettingDefinition> Catalog => inner.Catalog;
        public SettingsSnapshot Read() => inner.Read();
        public IReadOnlyList<SettingChange> History(string key) => inner.History(key);
        public SettingChange Save(string key, string json, string reason, SettingStamp loaded) => throw new NotSupportedException();
        public SettingChange Reset(string key, string reason, SettingStamp loaded) => throw new NotSupportedException();
    }
}
