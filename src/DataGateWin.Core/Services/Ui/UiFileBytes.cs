namespace DataGateWin.Services.Ui;

/// <summary>
/// Read image files without throwing. Unpackaged WinUI FailFasts on file:// BitmapImage URIs;
/// callers must decode these bytes via <c>SetSource</c> and treat null as "hide the picture".
/// </summary>
public static class UiFileBytes
{
    public const int DefaultMaxBytes = 2 * 1024 * 1024;

    public static byte[]? TryRead(string? path, int maxBytes = DefaultMaxBytes)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || maxBytes <= 0)
                return null;

            var full = Path.GetFullPath(path);
            var info = new FileInfo(full);
            if (!info.Exists || info.Length <= 0 || info.Length > maxBytes)
                return null;

            var bytes = File.ReadAllBytes(full);
            if (bytes.Length == 0 || bytes.Length > maxBytes)
                return null;

            return bytes;
        }
        catch
        {
            return null;
        }
    }

    public static byte[]? TryReadImage(string? path, int maxBytes = DefaultMaxBytes)
    {
        var bytes = TryRead(path, maxBytes);
        return bytes is not null && LooksLikeRasterImage(bytes) ? bytes : null;
    }

    public static bool LooksLikeRasterImage(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 12)
            return false;

        // PNG
        if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47)
            return true;

        // JPEG
        if (bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF)
            return true;

        // GIF
        if (bytes[0] == (byte)'G' && bytes[1] == (byte)'I' && bytes[2] == (byte)'F')
            return true;

        // ICO / CUR
        if (bytes[0] == 0 && bytes[1] == 0 && (bytes[2] == 1 || bytes[2] == 2) && bytes[3] == 0)
            return true;

        // WebP: RIFF....WEBP
        if (bytes[0] == (byte)'R' && bytes[1] == (byte)'I' && bytes[2] == (byte)'F' && bytes[3] == (byte)'F'
            && bytes[8] == (byte)'W' && bytes[9] == (byte)'E' && bytes[10] == (byte)'B' && bytes[11] == (byte)'P')
            return true;

        // BMP
        if (bytes[0] == (byte)'B' && bytes[1] == (byte)'M')
            return true;

        return false;
    }
}
