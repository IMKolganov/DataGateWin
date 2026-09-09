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
        try
        {
            var bytes = UiFileBytes.TryReadImage(full);
            if (bytes is null)
                return null;

            var ras = new InMemoryRandomAccessStream();
            using (var writer = new DataWriter(ras))
            {
                writer.WriteBytes(bytes);
                writer.StoreAsync().AsTask().GetAwaiter().GetResult();
                writer.DetachStream();
            }

            ras.Seek(0);
            var bmp = new BitmapImage();
            if (decodePixelWidth > 0)
                bmp.DecodePixelWidth = decodePixelWidth;
            bmp.SetSource(ras);
            return bmp;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UiFileBitmap.TryLoad");
            return null;
        }
    }
}
