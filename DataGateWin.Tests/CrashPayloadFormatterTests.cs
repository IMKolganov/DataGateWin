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
}
