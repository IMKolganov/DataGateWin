using System.Globalization;

namespace DataGateWin.Services.Traffic;

public static class LiveTrafficFormatting
{
    public static string FormatBytesPerSec(double bytesPerSec, CultureInfo? culture = null)
    {
        culture ??= CultureInfo.CurrentCulture;
        var b = Math.Max(0, bytesPerSec);
        const double k = 1024.0;
        if (b < k)
            return string.Format(culture, "{0:0} B/s", b);
        var kb = b / k;
        if (kb < k)
            return string.Format(culture, "{0:0.0} KB/s", kb);
        var mb = kb / k;
        if (mb < k)
            return string.Format(culture, "{0:0.00} MB/s", mb);
        return string.Format(culture, "{0:0.00} GB/s", mb / k);
    }
}
