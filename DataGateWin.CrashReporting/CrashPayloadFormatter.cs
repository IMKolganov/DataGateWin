using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace DataGateWin.CrashReporting;

public static class CrashPayloadFormatter
{
    public const int MaxPayloadUtf8Bytes = 1024 * 1024;

    /// <summary>Normalize CRLF/CR to LF.</summary>
    public static string NormalizeNewlines(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;

        return text
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace("\r", "\n", StringComparison.Ordinal);
    }

    /// <summary>UTC ISO-8601 with Z suffix (fractional seconds).</summary>
    public static string FormatTimestampUtcIso(DateTime utc)
        => utc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    public static string BuildBody(
        IReadOnlyDictionary<string, string> metadata,
        string stackTraceOrRaw)
    {
        var meta = new StringBuilder();
        foreach (var kv in metadata)
        {
            meta.Append(kv.Key);
            meta.Append('=');
            meta.Append(NormalizeNewlines(kv.Value).Replace("\n", " ", StringComparison.Ordinal));
            meta.Append('\n');
        }

        meta.Append('\n');
        meta.Append(NormalizeNewlines(stackTraceOrRaw));
        return meta.ToString();
    }

    /// <summary>
    /// Ensures UTF-8 encoded size is at most <paramref name="maxUtf8Bytes"/>.
    /// Metadata block is preserved; tail of the stack section may be replaced with a truncation notice.
    /// </summary>
    public static string EnforceMaxUtf8Size(string payload, int maxUtf8Bytes = MaxPayloadUtf8Bytes)
    {
        var bytes = Encoding.UTF8.GetByteCount(payload);
        if (bytes <= maxUtf8Bytes)
            return payload;

        const string notice = "\n\n[crash payload truncated to respect max size]\n";
        var noticeBytes = Encoding.UTF8.GetByteCount(notice);

        var sepIdx = payload.IndexOf("\n\n", StringComparison.Ordinal);
        if (sepIdx < 0)
        {
            var head = Encoding.UTF8.GetString(TruncateUtf8(payload, maxUtf8Bytes - noticeBytes));
            return head + notice;
        }

        var metaBlock = payload[..sepIdx];
        var stackPart = payload[(sepIdx + 2)..];
        var metaBytes = Encoding.UTF8.GetByteCount(metaBlock) + 2;

        var budget = maxUtf8Bytes - metaBytes - noticeBytes;
        if (budget <= 0)
        {
            var minimal = Encoding.UTF8.GetString(TruncateUtf8(metaBlock, maxUtf8Bytes - noticeBytes));
            return minimal + notice;
        }

        var truncatedStack = Encoding.UTF8.GetString(TruncateUtf8(stackPart, budget));
        return metaBlock + "\n\n" + truncatedStack + notice;
    }

    static byte[] TruncateUtf8(string s, int maxBytes)
    {
        if (maxBytes <= 0)
            return Array.Empty<byte>();

        var enc = Encoding.UTF8;
        var full = enc.GetBytes(s);
        if (full.Length <= maxBytes)
            return full;

        var slice = new byte[maxBytes];
        Array.Copy(full, slice, maxBytes);
        while (maxBytes > 0 && (slice[maxBytes - 1] & 0xC0) == 0x80)
            maxBytes--;

        if (maxBytes <= 0)
            return Array.Empty<byte>();

        Array.Resize(ref slice, maxBytes);
        return slice;
    }

    public static string GetDefaultSdkLabel()
        => $".NET {Environment.Version}";

    public static string GetDefaultDeviceLabel()
    {
        var os = NormalizeNewlines(RuntimeInformation.OSDescription).Replace("\n", " ", StringComparison.Ordinal);
        var arch = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
        return $"{os} ({arch})";
    }

    public static string? TryGetAppAssemblyVersion()
    {
        try
        {
            var v = Assembly.GetEntryAssembly()?.GetName().Version;
            return v?.ToString();
        }
        catch
        {
            return null;
        }
    }
}
