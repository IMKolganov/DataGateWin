using DataGateWin.CrashReporting;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Storage.Streams;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Unpackaged WinUI FailFasts (0x80073B01 MUI) if <see cref="BitmapImage.UriSource"/> is a file path.
/// Load pixels from a stream instead.
/// </summary>
internal static class UiFileBitmap
{
    public static BitmapImage? TryLoad(string path, int decodePixelWidth = 0)
    {
        var bytes = UiFileBytes.TryReadImage(path);
        return bytes is null ? null : TryLoadFromBytes(bytes, decodePixelWidth);
    }

    /// <summary>
    /// Always returns a <b>new</b> <see cref="BitmapImage"/>. Never reuse one instance across
    /// multiple <c>Image</c> controls — WinUI FailFasts with InvalidCastException / 0xc000027b.
    /// </summary>
    public static BitmapImage? TryLoadFromBytes(byte[] bytes, int decodePixelWidth = 0)
    {
        if (bytes.Length == 0 || !UiFileBytes.LooksLikeRasterImage(bytes))
            return null;

        try
        {
            var ras = new InMemoryRandomAccessStream();
            var writer = new DataWriter(ras);
            try
            {
                writer.WriteBytes(bytes);
                writer.StoreAsync().AsTask().GetAwaiter().GetResult();
                writer.DetachStream();
            }
            finally
            {
                writer.Dispose();
            }

            ras.Seek(0);
            var bmp = new BitmapImage();
            if (decodePixelWidth > 0)
                bmp.DecodePixelWidth = decodePixelWidth;
            // Sync SetSource is OK for small in-memory flags; SetSourceAsync+block can deadlock UI.
            bmp.SetSource(ras);
            return bmp;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UiFileBitmap.TryLoadFromBytes");
            return null;
        }
    }
}
