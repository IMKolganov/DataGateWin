using DataGateWin.Services.Ui;
using Xunit;

namespace DataGateWin.Tests;

public sealed class UiFileBytesCrashSafetyTests
{
    [Fact]
    public void TryRead_HostilePaths_NeverThrow_ReturnNull()
    {
        Assert.Null(UiFileBytes.TryRead(null));
        Assert.Null(UiFileBytes.TryRead(""));
        Assert.Null(UiFileBytes.TryRead("   "));
        Assert.Null(UiFileBytes.TryRead("Z:\\definitely\\missing\\flag.png"));
        Assert.Null(UiFileBytes.TryRead("C:\\", maxBytes: 0));
        Assert.Null(UiFileBytes.TryRead("C:\\", maxBytes: -1));
        Assert.Null(UiFileBytes.TryRead(new string('x', 32_000)));
        Assert.Null(UiFileBytes.TryReadImage(null));
        Assert.False(UiFileBytes.LooksLikeRasterImage([]));
        Assert.False(UiFileBytes.LooksLikeRasterImage("not-an-image"u8));
    }

    [Fact]
    public void TryRead_EmptyAndOversizedFiles_ReturnNull()
    {
        var dir = CreateTempDir();
        try
        {
            var empty = Path.Combine(dir, "empty.png");
            File.WriteAllBytes(empty, []);
            Assert.Null(UiFileBytes.TryRead(empty));
            Assert.Null(UiFileBytes.TryReadImage(empty));

            var huge = Path.Combine(dir, "huge.png");
            File.WriteAllBytes(huge, new byte[UiFileBytes.DefaultMaxBytes + 1]);
            Assert.Null(UiFileBytes.TryRead(huge));
            Assert.Null(UiFileBytes.TryReadImage(huge));
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void TryReadImage_GarbageAndHtml_ReturnNull_SoWinUiNeverSeesThem()
    {
        var dir = CreateTempDir();
        try
        {
            var garbage = Path.Combine(dir, "fi.png");
            File.WriteAllBytes(garbage, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            Assert.NotNull(UiFileBytes.TryRead(garbage));
            Assert.Null(UiFileBytes.TryReadImage(garbage));

            var html = Path.Combine(dir, "avatar.img");
            File.WriteAllText(html, "<html><body>not an image</body></html>");
            Assert.Null(UiFileBytes.TryReadImage(html));

            var truncatedPng = Path.Combine(dir, "trunc.png");
            File.WriteAllBytes(truncatedPng, [0x89, 0x50, 0x4E]);
            Assert.Null(UiFileBytes.TryReadImage(truncatedPng));
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void TryReadImage_AcceptsPngJpegGifWebpIcoBmpMagic()
    {
        var dir = CreateTempDir();
        try
        {
            AssertAccepted(dir, "a.png", [0x89, 0x50, 0x4E, 0x47, 0, 0, 0, 0, 0, 0, 0, 0]);
            AssertAccepted(dir, "a.jpg", [0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0, 0, 0, 0, 0]);
            AssertAccepted(dir, "a.gif", "GIF89aXXXXXX"u8.ToArray());
            AssertAccepted(dir, "a.webp", "RIFF\0\0\0\0WEBP"u8.ToArray());
            AssertAccepted(dir, "a.ico", [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            AssertAccepted(dir, "a.bmp", "BMXXXXXXXXXX"u8.ToArray());
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void TryRead_DirectoryAndLockedFile_ReturnNull()
    {
        var dir = CreateTempDir();
        try
        {
            Assert.Null(UiFileBytes.TryRead(dir));
            Assert.Null(UiFileBytes.TryReadImage(dir));

            var locked = Path.Combine(dir, "lock.png");
            using var fs = new FileStream(locked, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            fs.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0, 0, 0, 0, 0, 0, 0, 0 });
            fs.Flush();
            Assert.Null(UiFileBytes.TryRead(locked));
            Assert.Null(UiFileBytes.TryReadImage(locked));
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    [Fact]
    public void TryReadImage_ParallelHostileMix_NeverThrows()
    {
        var dir = CreateTempDir();
        try
        {
            var png = Path.Combine(dir, "ok.png");
            File.WriteAllBytes(png, [0x89, 0x50, 0x4E, 0x47, 0, 0, 0, 0, 0, 0, 0, 0]);
            var junk = Path.Combine(dir, "bad.bin");
            File.WriteAllText(junk, "????");

            Parallel.For(0, 64, i =>
            {
                _ = UiFileBytes.TryReadImage(null);
                _ = UiFileBytes.TryReadImage(png);
                _ = UiFileBytes.TryReadImage(junk);
                _ = UiFileBytes.TryReadImage(dir);
                _ = UiFileBytes.TryReadImage("\\\\.\\invalid\\path\\" + i);
            });
        }
        finally
        {
            DeleteDir(dir);
        }
    }

    private static void AssertAccepted(string dir, string name, byte[] magic)
    {
        var path = Path.Combine(dir, name);
        File.WriteAllBytes(path, magic);
        var read = UiFileBytes.TryReadImage(path);
        Assert.NotNull(read);
        Assert.Equal(magic, read);
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dg-uifilebytes-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void DeleteDir(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch
        {
            // ignore
        }
    }
}

public sealed class WinUiFailSoftContractTests
{
    [Fact]
    public void UiFileBitmap_RejectsFileUri_UsesCoreBytes_AndSwallowsAllExceptions()
    {
        var helper = ReadWinUi("Services", "Ui", "UiFileBitmap.cs");
        Assert.DoesNotContain("UriSource =", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("bmp.UriSource", helper, StringComparison.Ordinal);
        Assert.Contains("UiFileBytes.TryReadImage(path)", helper, StringComparison.Ordinal);
        Assert.Contains("catch (Exception", helper, StringComparison.Ordinal);
        Assert.Contains("return null", helper, StringComparison.Ordinal);
        Assert.Contains("SetSource", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void UiSafeImage_AssignmentFailures_ReturnFalse_NeverPropagate()
    {
        var cs = ReadWinUi("Services", "Ui", "UiSafeImage.cs");
        Assert.Contains("catch (Exception ex)", cs, StringComparison.Ordinal);
        Assert.Contains("return false", cs, StringComparison.Ordinal);
        Assert.Contains("target.Source = null", cs, StringComparison.Ordinal);
        Assert.Contains("Visibility.Collapsed", cs, StringComparison.Ordinal);
    }

    [Fact]
    public void Home_ConnectFlagPath_LogsError_HidesImage_DoesNotSetRawSource()
    {
        var home = ReadWinUi("Pages", "Home", "HomePage.xaml.cs");
        var xaml = ReadWinUi("Pages", "Home", "HomePage.xaml");
        Assert.Contains("UiSafeImage.TryAssign", home, StringComparison.Ordinal);
        Assert.Contains("Home_Error_UiImage", home, StringComparison.Ordinal);
        Assert.Contains("NetworkServerFlag_OnImageFailed", home, StringComparison.Ordinal);
        Assert.Contains("ImageFailed=\"NetworkServerFlag_OnImageFailed\"", xaml, StringComparison.Ordinal);
        Assert.DoesNotContain("NetworkServerFlag.Source = flag", home, StringComparison.Ordinal);
    }

    [Fact]
    public void App_MarksDispatcherExceptionsHandled_AndDoesNotFailFastFlushThem()
    {
        var app = ReadWinUi("App.xaml.cs");
        Assert.Contains("e.Handled = true", app, StringComparison.Ordinal);
        Assert.DoesNotContain("SetSynchronizationContext", app, StringComparison.Ordinal);

        var crash = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.CrashReporting", "CrashReporter.cs")));
        var idx = crash.IndexOf("public static void HandleDispatcherUnhandled", StringComparison.Ordinal);
        Assert.True(idx >= 0);
        var slice = crash.Substring(idx, Math.Min(500, crash.Length - idx));
        Assert.Contains("CrashReportKind.NonFatal", slice, StringComparison.Ordinal);
        Assert.DoesNotContain("TryFlushBlocking", slice, StringComparison.Ordinal);
        Assert.Contains("exception is null", slice, StringComparison.Ordinal);
    }

    [Fact]
    public void AccessAndLogin_KeepUiDispatch_OnPropertyChanges()
    {
        var access = ReadWinUi("Pages", "AccessPage.xaml.cs");
        var login = ReadWinUi("Views", "LoginWindow.xaml.cs");
        Assert.Contains("UiDispatch.Run", access, StringComparison.Ordinal);
        Assert.Contains("UiDispatch.Run", login, StringComparison.Ordinal);
    }

    private static string ReadWinUi(params string[] parts)
        => File.ReadAllText(FindRepoFile(Path.Combine(["DataGateWin.WinUI", .. parts])));

    private static string FindRepoFile(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, relative);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }

        throw new FileNotFoundException(relative);
    }
}
