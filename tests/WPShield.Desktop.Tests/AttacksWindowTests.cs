using System.Net;
using System.Windows;
using WPShield.Evidence;
using WPShield.SecurityMonitor;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AttacksWindowTests
{
    private static AuthFailureSnapshot Snapshot(DateTimeOffset end, string status, string? reason, params AuthFailure[] failures) =>
        new(end.AddHours(-24), end, failures,
        [
            new(AuthFailureFeed.SecurityChannel, status, reason, null, status == "unavailable" ? null : end.AddDays(-3), failures.Length),
            new(AuthFailureFeed.RdpCoreChannel, "read", null, null, end.AddDays(-3), 0)
        ]);

    private sealed class NoWatch : IDisposable
    {
        public void Dispose() { }
    }

    [Theory]
    [InlineData(true, "administrador")]
    [InlineData(false, "administrator")]
    public Task WithoutElevationItSaysItCouldNotLookInsteadOfShowingAQuietHost(bool spanish, string word) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var window = new AttacksWindow(spanish, end => Snapshot(end, "unavailable", "access-denied"), (_, _) => new NoWatch());
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Visible, window.Banner.Visibility);
                Assert.Contains(word, window.BannerText.Text, StringComparison.OrdinalIgnoreCase);
                Assert.Equal(Visibility.Visible, window.ElevateButton.Visibility);
                // "0" would claim nobody tried; the cards must say nothing was read.
                Assert.Equal("—", window.AttemptsValue.Text);
                Assert.Equal("—", window.SourcesValue.Text);
            }
            finally { window.Close(); }
        });

    [Fact]
    public Task LiveFailuresAreAppliedAndShown() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            Action<AuthFailure>? push = null;
            var window = new AttacksWindow(false, end => Snapshot(end, "read", null), (onFailure, _) =>
            {
                push = onFailure;
                return new NoWatch();
            });
            try
            {
                window.Show();
                await window.LoadAsync();
                Assert.Equal(Visibility.Collapsed, window.Banner.Visibility);
                Assert.NotNull(push);
                push(new(DateTimeOffset.UtcNow, "security-4625", IPAddress.Parse("203.0.113.44"), 50000, "admin",
                    "unknown-account", 10, 1));
                await Task.Delay(1600);
                Assert.Equal(1, window.Board.Count);
                Assert.Equal("1", window.AttemptsValue.Text);
            }
            finally { window.Close(); }
        });
}
