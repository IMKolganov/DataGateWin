using System.Text;
using DataGateWin.CrashReporting;
using Xunit;

namespace DataGateWin.Tests;

public sealed class CrashPayloadFormatterTests
{
    [Fact]
    public void NormalizeNewlines_ReplacesCrlfAndCrWithLf()
    {
        var input = "a\r\nb\rc\n";
        Assert.Equal("a\nb\nc\n", CrashPayloadFormatter.NormalizeNewlines(input));
    }

    [Fact]
    public void BuildBody_SeparatesMetadataBlankLineAndStack()
    {
        var meta = new Dictionary<string, string>
        {
            ["timestamp_utc"] = "2026-05-01T12:34:56.000Z",
            ["kind"] = "fatal",
        };

        var stack = "System.Exception: x\n   at X.Main()";
        var body = CrashPayloadFormatter.BuildBody(meta, stack);

        Assert.StartsWith("timestamp_utc=2026-05-01T12:34:56.000Z\nkind=fatal\n\n", body, StringComparison.Ordinal);
        Assert.EndsWith(stack.Replace("\r\n", "\n", StringComparison.Ordinal), body, StringComparison.Ordinal);
        Assert.Contains("\n\n", body, StringComparison.Ordinal);
    }

    [Fact]
    public void EnforceMaxUtf8Size_TruncatesWhenOverLimit()
    {
        var bigStack = new string('x', 2_000_000);
        var meta = new Dictionary<string, string> { ["kind"] = "fatal" };
        var body = CrashPayloadFormatter.BuildBody(meta, bigStack);
        Assert.True(Encoding.UTF8.GetByteCount(body) > CrashPayloadFormatter.MaxPayloadUtf8Bytes);

        var trimmed = CrashPayloadFormatter.EnforceMaxUtf8Size(body, CrashPayloadFormatter.MaxPayloadUtf8Bytes);
        Assert.True(Encoding.UTF8.GetByteCount(trimmed) <= CrashPayloadFormatter.MaxPayloadUtf8Bytes);
        Assert.Contains("truncated", trimmed, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FormatTimestampUtcIso_UsesInvariantZuluFormat()
    {
        var dt = new DateTime(2026, 5, 1, 12, 34, 56, 789, DateTimeKind.Utc);
        Assert.Equal("2026-05-01T12:34:56.789Z", CrashPayloadFormatter.FormatTimestampUtcIso(dt));
    }

    [Fact]
    public void NormalizeNewlines_NullOrEmpty_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, CrashPayloadFormatter.NormalizeNewlines(null));
        Assert.Equal(string.Empty, CrashPayloadFormatter.NormalizeNewlines(""));
    }

    [Fact]
    public void BuildBody_FlattensNewlinesInsideMetadataValues()
    {
        var meta = new Dictionary<string, string> { ["msg"] = "a\nb\nc" };
        var body = CrashPayloadFormatter.BuildBody(meta, "stack");
        Assert.Contains("msg=a b c", body, StringComparison.Ordinal);
    }

    [Fact]
    public void EnforceMaxUtf8Size_WithoutDoubleBlankLine_TruncatesWholePayload()
    {
        var huge = new string('y', 2_000_000);
        Assert.False(huge.Contains("\n\n", StringComparison.Ordinal));

        var trimmed = CrashPayloadFormatter.EnforceMaxUtf8Size(huge, maxUtf8Bytes: 4096);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(trimmed) <= 4096);
        Assert.Contains("truncated", trimmed, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnforceMaxUtf8Size_MetaTooLarge_TruncatesMetaPath()
    {
        var bigKey = new string('z', 900_000);
        var meta = new Dictionary<string, string>
        {
            ["k"] = bigKey,
        };
        var body = CrashPayloadFormatter.BuildBody(meta, "tail");
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(body) > 1024);

        var trimmed = CrashPayloadFormatter.EnforceMaxUtf8Size(body, maxUtf8Bytes: 1024);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(trimmed) <= 1024);
        Assert.Contains("truncated", trimmed, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetDefaultSdkLabel_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(CrashPayloadFormatter.GetDefaultSdkLabel()));
        Assert.Contains(".NET", CrashPayloadFormatter.GetDefaultSdkLabel(), StringComparison.Ordinal);
    }

    [Fact]
    public void GetDefaultDeviceLabel_IncludesArchitectureToken()
    {
        var label = CrashPayloadFormatter.GetDefaultDeviceLabel();
        Assert.False(string.IsNullOrWhiteSpace(label));
        Assert.Contains("(", label, StringComparison.Ordinal);
    }

    [Fact]
    public void TryGetAppAssemblyVersion_DoesNotThrow()
    {
        _ = CrashPayloadFormatter.TryGetAppAssemblyVersion();
    }
}
