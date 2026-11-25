using System.Windows.Threading;

namespace WPShield.Desktop.Tests;

internal static class DesktopDispatcher
{
    /// <summary>
    /// How long a window test may run before it is called hung. It guards against a hang, it does not
    /// measure speed: a window test takes well under a second alone. A failed assertion still fails at once.
    /// </summary>
    internal static readonly TimeSpan HangGuard = TimeSpan.FromMinutes(2);

    /// <summary>
    /// One window test at a time. WPF started on several STA threads at the same instant can deadlock in its
    /// own first-use initialisation: in a whole-solution run, six window tests from six classes, started
    /// together, all hung for the full guard and timed out at the same millisecond while every other assembly
    /// finished in 18 seconds, and every window test after them hung the same way. That is the "cold WPF start"
    /// PR #138 saw in AttacksWindowTests; a longer guard only waited longer for it. Run alone, the same tests
    /// take a few seconds in all.
    /// </summary>
    private static readonly SemaphoreSlim OneAtATime = new(1, 1);

    internal static async Task RunAsync(Func<Task> verify)
    {
        await OneAtATime.WaitAsync();
        try
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
        finally
        {
            OneAtATime.Release();
        }
    }
}
