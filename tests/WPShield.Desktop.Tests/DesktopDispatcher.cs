using System.Windows.Threading;

namespace WPShield.Desktop.Tests;

internal static class DesktopDispatcher
{
    internal static async Task RunAsync(Func<Task> verify)
    {
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    await verify();
                    completed.SetResult();
                }
                catch (Exception error) { completed.SetException(error); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            });
            Dispatcher.Run();
        });
        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }
}
