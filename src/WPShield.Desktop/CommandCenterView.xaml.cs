using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

public partial class CommandCenterView : UserControl
{
    internal static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);
    private readonly DispatcherTimer timer = new() { Interval = RefreshInterval };
    private readonly bool spanish;
    private readonly Func<DateTimeOffset, CommandCenterRead> read;
    private readonly Func<DateTimeOffset> now;
    private readonly CommandCenterTiles presentation;
    private Window? owner;
    private Task? loading;

    public CommandCenterView() : this(App.Spanish(),
        new CommandCenterStore(EvidenceStore.DefaultPath, EvidenceAccess.IsElevated).Read, () => DateTimeOffset.UtcNow)
    {
    }

    internal CommandCenterView(bool spanish, Func<DateTimeOffset, CommandCenterRead> read, Func<DateTimeOffset> now)
    {
        this.spanish = spanish;
        this.read = read;
        this.now = now;
        presentation = new CommandCenterTiles(spanish);
        InitializeComponent();
        Heading.Text = L("Command center", "Centro de mando");
        RefreshButton.Content = L("Refresh", "Actualizar");
        ReadingTime.Text = L("Reading the evidence store…", "Leyendo el almacén de evidencia…");
        Tiles.ItemsSource = presentation.Build(null);
        timer.Tick += async (_, _) => await LoadAsync();
    }

    internal Action<CommandTile>? OpenTile { get; set; }
    internal bool Live => timer.IsEnabled;

    private string L(string en, string es) => spanish ? es : en;

    internal Task LoadAsync() => loading is { IsCompleted: false } ? loading : loading = LoadCoreAsync();

    private async Task LoadCoreAsync()
    {
        if (!IsLoaded || !IsVisible || owner?.WindowState == WindowState.Minimized) return;
        RefreshButton.IsEnabled = false;
        try
        {
            var at = now();
            var snapshot = await Task.Run(() => read(at));
            if (!IsLoaded) return;
            Tiles.ItemsSource = presentation.Build(snapshot);
            ProblemBox.Visibility = Visibility.Collapsed;
            var time = at.UtcDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
            ReadingTime.Text = L($"Evidence store read at {time} UTC", $"Almacén leído a las {time} UTC");
        }
        catch (EvidenceAccessException error)
        {
            ShowProblem(ProtectionStatus.StoreRemedy(error.Problem, error.Message, spanish));
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            ShowProblem(ProtectionStatus.StoreRemedy(EvidenceProblem.Unreadable, error.GetType().Name, spanish));
        }
        finally { RefreshButton.IsEnabled = true; }
    }

    private void ShowProblem(string text)
    {
        if (!IsLoaded) return;
        Tiles.ItemsSource = presentation.Build(null);
        ReadingTime.Text = L("No data", "Sin datos");
        Problem.Text = text;
        ProblemBox.Visibility = Visibility.Visible;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        owner = Window.GetWindow(this);
        if (owner is not null) owner.StateChanged += OnWindowState;
        UpdateTimer();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (owner is not null) owner.StateChanged -= OnWindowState;
        owner = null;
        timer.Stop();
    }

    private void OnWindowState(object? sender, EventArgs e) => UpdateTimer();
    private void OnVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e) => UpdateTimer();

    private void UpdateTimer()
    {
        var active = IsLoaded && IsVisible && owner?.WindowState != WindowState.Minimized;
        if (active == timer.IsEnabled) return;
        timer.IsEnabled = active;
        if (active) _ = LoadAsync();
    }

    private void OnDashboardSize(object sender, SizeChangedEventArgs e)
    {
        var width = Math.Max(1, DashboardScroll.ActualWidth - SystemParameters.VerticalScrollBarWidth);
        var columns = width >= 935 ? 3 : width >= 550 ? 2 : 1;
        Tiles.Tag = Math.Max(1, Math.Floor(width / columns) - 8);
    }

    private async void OnRefresh(object sender, RoutedEventArgs e) => await LoadAsync();

    private void OnTile(object sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: CommandTile tile }) OpenTile?.Invoke(tile);
    }

    internal void ShowDetails(CommandTile tile, Action? openPorts = null)
    {
        var detail = new Window
        {
            Title = "WPShield | " + tile.Title,
            Owner = owner,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Width = 620,
            Height = 500,
            MinWidth = 410,
            MinHeight = 260,
            ShowInTaskbar = false,
            Background = Brushes.White
        };
        var rows = new ItemsControl { ItemsSource = tile.Details ?? tile.Metrics, ItemTemplate = (DataTemplate)FindResource("CommandMetric") };
        var layout = new DockPanel { Margin = new Thickness(18) };
        var heading = new TextBlock { Text = tile.Status, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 14) };
        DockPanel.SetDock(heading, Dock.Top);
        layout.Children.Add(heading);
        if (openPorts is not null)
        {
            var ports = new Button
            {
                Content = L("Open local ports", "Abrir puertos locales"),
                HorizontalAlignment = HorizontalAlignment.Right,
                Padding = new Thickness(10, 4, 10, 4),
                Margin = new Thickness(0, 10, 0, 0)
            };
            ports.Click += (_, _) =>
            {
                detail.Close();
                openPorts();
            };
            DockPanel.SetDock(ports, Dock.Bottom);
            layout.Children.Add(ports);
        }
        layout.Children.Add(new ScrollViewer { Content = rows, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        detail.Content = layout;
        detail.Show();
    }
}
