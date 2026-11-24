using System.IO;
using System.Windows.Input;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AuditReferenceWindowTests
{
    [Theory]
    [InlineData(true, "Cobertura declarada", "Referencia copiada.")]
    [InlineData(false, "Reported coverage", "Reference copied.")]
    public Task CopyCommandUsesOnlyTheSelectedPreviewAndDisablesOnFailedReload(bool spanish, string coverage, string copied) =>
        DesktopDispatcher.RunAsync(() => VerifyWindow(spanish, coverage, copied));

    private static async Task VerifyWindow(bool spanish, string coverage, string copied)
    {
        var path = Path.GetTempFileName();
        var writes = new List<string>();
        var view = new AuditReferenceWindow(spanish, writes.Add);
        try
        {
            await File.WriteAllTextAsync(path, """
                {"Channel":"Application","Provider":"MSSQLSERVER","AuditStatus":"limited","Events":[
                 {"RecordId":7,"Timestamp":"2026-01-01T00:00:00Z"},
                 {"RecordId":9,"Timestamp":"2026-01-01T00:01:00Z","Private":"private-sentinel"}]}
                """);
            await view.LoadSnapshotAsync(path);
            Assert.StartsWith(coverage, view.CoverageLabel.Text);
            Assert.Equal(2, view.Entries.Items.Count);
            view.Entries.SelectedIndex = 1;
            Assert.Contains("\"RecordId\":9", view.Preview.Text);
            Assert.DoesNotContain("private-sentinel", view.Preview.Text);
            Assert.Empty(writes);
            Assert.True(ApplicationCommands.Copy.CanExecute(null, view.Entries));
            ApplicationCommands.Copy.Execute(null, view.Entries);
            Assert.Equal(view.Preview.Text, Assert.Single(writes));
            Assert.Equal(copied, view.Status.Text);

            await File.WriteAllTextAsync(path, "{}");
            await view.LoadSnapshotAsync(path);
            Assert.Empty(view.Entries.Items);
            Assert.Empty(view.Preview.Text);
            Assert.False(ApplicationCommands.Copy.CanExecute(null, view.Entries));
            Assert.Single(writes);
        }
        finally
        {
            view.Close();
            File.Delete(path);
        }
    }
}
