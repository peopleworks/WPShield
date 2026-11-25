using System.Windows;
using System.Windows.Media.Imaging;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class AppIconTests
{
    [Fact]
    public Task TheIconCarriesEverySizeWindowsAsksFor() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var decoder = BitmapDecoder.Create(AppIcon.Location, BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            var sizes = decoder.Frames.Select(f => f.PixelWidth).Order().ToArray();
            // 16 and 20 for title bars at 100% and 125%, 32 and 48 for the taskbar and Alt+Tab, 256 for Explorer.
            Assert.Equal([16, 20, 24, 32, 40, 48, 64, 128, 256], sizes);
            Assert.All(decoder.Frames, f => Assert.Equal(f.PixelWidth, f.PixelHeight));
            return Task.CompletedTask;
        });

    [Fact]
    public Task AWindowWithoutAnIconGetsOursAndOneWithItsOwnKeepsIt() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var plain = new Window();
            AppIcon.Apply(plain);
            Assert.Same(AppIcon.Image, plain.Icon);

            var own = BitmapFrame.Create(AppIcon.Location);
            var custom = new Window { Icon = own };
            AppIcon.Apply(custom);
            Assert.Same(own, custom.Icon);
            return Task.CompletedTask;
        });
}
