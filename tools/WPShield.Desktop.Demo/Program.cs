using System.IO;
using System.Windows.Threading;
using WPShield.Evidence;

namespace WPShield.Desktop.Demo;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args is ["--store", var requested])
            {
                Console.WriteLine($"Created synthetic evidence at {CreateStore(requested)}.");
                return 0;
            }
            if (args.Length != 0)
            {
                Console.Error.WriteLine("Usage: WPShield.Desktop.Demo [--store <new database file>]");
                return 2;
            }

            var root = Directory.GetCurrentDirectory();
            if (!File.Exists(Path.Combine(root, "WPShield.slnx")))
                throw new InvalidOperationException("Run the screenshot command from the repository root.");
            var output = Path.Combine(root, "docs", "assets", "screenshots");
            DemoPaths.RequireSafeDirectory(output, mayBeMissing: true);
            using var workspace = new DemoWorkspace();
            var store = workspace.FilePath(EvidenceStore.FileName);
            var audit = workspace.FilePath("demo-audit.json");
            DemoData.WriteStore(store);
            DemoData.WriteAudit(audit);
            Render(workspace, store, audit);

            Directory.CreateDirectory(output);
            DemoPaths.RequireSafeDirectory(output);
            foreach (var file in Screenshots.Filenames)
                File.Move(workspace.FilePath(file), Path.Combine(output, file), overwrite: true);
            Console.WriteLine($"Rendered {Screenshots.Filenames.Count} synthetic screenshots to docs/assets/screenshots.");
            return 0;
        }
        catch (Exception error) when (error is ArgumentException or IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static void Render(DemoWorkspace workspace, string store, string audit)
    {
        var dispatcher = Dispatcher.CurrentDispatcher;
        var rendering = dispatcher.InvokeAsync(() => Screenshots.RenderAsync(workspace, store, audit)).Task.Unwrap();
        _ = rendering.ContinueWith(_ => dispatcher.BeginInvokeShutdown(DispatcherPriority.Background),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        Dispatcher.Run();
        rendering.GetAwaiter().GetResult();
    }

    internal static string CreateStore(string requested)
    {
        var destination = DemoPaths.NewStorePath(requested);
        using var workspace = new DemoWorkspace();
        var staged = workspace.FilePath(EvidenceStore.FileName);
        DemoData.WriteStore(staged);

        // SQLite only ever opens the private staging file for writes. A destination created while
        // the store was being seeded still cannot be overwritten by the final move.
        DemoPaths.NewStorePath(destination);
        File.Move(staged, destination, overwrite: false);
        return destination;
    }
}
