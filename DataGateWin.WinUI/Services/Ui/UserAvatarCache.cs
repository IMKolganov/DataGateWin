using System.Security.Cryptography;
using System.Text;
using DataGateWin.CrashReporting;
using Microsoft.UI.Xaml.Media.Imaging;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Persists profile pictures under LocalApplicationData so we don&apos;t refetch on every launch.
/// </summary>
public static class UserAvatarCache
{
    private static readonly string CacheDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DataGateWin",
        "cache",
        "avatar");

    /// <summary>
    /// Ensures the image is cached on disk, then builds a <see cref="BitmapImage"/>.
    /// Call from the UI thread (WinUI images are not Freezable).
    /// </summary>
    public static async Task<BitmapImage?> TryLoadOrDownloadAsync(
        string imageUrl,
        string? numericUserId,
        CancellationToken ct)
    {
        var path = await TryEnsureCachedPathAsync(imageUrl, numericUserId, ct).ConfigureAwait(true);
        return path is null ? null : CreateBitmapFromFile(path);
    }

    public static async Task<string?> TryEnsureCachedPathAsync(
        string imageUrl,
        string? numericUserId,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(imageUrl)
            || !Uri.TryCreate(imageUrl.Trim(), UriKind.Absolute, out var uri))
            return null;

        var normalizedUrl = imageUrl.Trim();
        Directory.CreateDirectory(CacheDirectory);

        var baseName = BuildCacheBaseName(numericUserId, normalizedUrl);
        var cachePath = Path.Combine(CacheDirectory, baseName + ".img");
        var urlMarkerPath = Path.Combine(CacheDirectory, baseName + ".url");

        if (File.Exists(cachePath)
            && File.Exists(urlMarkerPath)
            && string.Equals((await File.ReadAllTextAsync(urlMarkerPath, ct).ConfigureAwait(false)).Trim(), normalizedUrl, StringComparison.Ordinal))
        {
            return Path.GetFullPath(cachePath);
        }

        TryDelete(cachePath);
        TryDelete(urlMarkerPath);

        byte[] bytes;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
            bytes = await http.GetByteArrayAsync(uri, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UserAvatarCache.Download");
            return null;
        }

        if (bytes.Length == 0)
            return null;

        try
        {
            await File.WriteAllBytesAsync(cachePath, bytes, ct).ConfigureAwait(false);
            await File.WriteAllTextAsync(urlMarkerPath, normalizedUrl, ct).ConfigureAwait(false);
            return Path.GetFullPath(cachePath);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UserAvatarCache.WriteCached");
            return null;
        }
    }

    public static BitmapImage CreateBitmapFromFile(string path)
    {
        var bmp = new BitmapImage();
        bmp.UriSource = new Uri(Path.GetFullPath(path), UriKind.Absolute);
        bmp.DecodePixelWidth = 96;
        return bmp;
    }

    private static string BuildCacheBaseName(string? numericUserId, string url)
    {
        if (!string.IsNullOrWhiteSpace(numericUserId))
        {
            var s = numericUserId.Trim();
            foreach (var c in Path.GetInvalidFileNameChars())
                s = s.Replace(c, '_');
            return "u_" + s;
        }

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(url)));
        return "url_" + hash[..24].ToLowerInvariant();
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "UserAvatarCache.DeleteCached");
        }
    }
}
