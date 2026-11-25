using System.Windows.Threading;

namespace WPShield.Desktop.Tests;

internal static class DesktopDispatcher
{
    /// <summary>
    /// How long a window test may run before it is called hung. It guards against a hang, it does not
    /// measure speed: a window test takes well under a second alone, but in CI every test assembly runs at
    /// once, and a cold WPF start on a loaded runner has taken longer than 30 seconds. A failed assertion
    /// still fails at once.
    /// </summary>
    internal static readonly TimeSpan HangGuard = TimeSpan.FromMinutes(2);

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
        await completed.Task.WaitAsync(HangGuard);
    }
}
