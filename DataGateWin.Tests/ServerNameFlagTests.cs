using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ServerNameFlagTests
{
    [Theory]
    [InlineData("🇫🇮 Helsinki 3", "🇫🇮", "Helsinki 3")]
    [InlineData("🇨🇾 Cyprus", "🇨🇾", "Cyprus")]
    [InlineData("🇳🇴 Norway xray", "🇳🇴", "Norway xray")]
    [InlineData("  🇫🇮  Helsinki 3  ", "🇫🇮", "Helsinki 3")]
    [InlineData("FI Helsinki 3 tcp", "🇫🇮", "Helsinki 3 tcp")]
    [InlineData("NO Norway 2 udp", "🇳🇴", "Norway 2 udp")]
    [InlineData("CY Cyprus", "🇨🇾", "Cyprus")]
    public void TrySplit_ExtractsLeadingFlag(string input, string flag, string rest)
    {
        Assert.True(ServerNameFlag.TrySplit(input, out var gotFlag, out var gotRest));
        Assert.Equal(flag, gotFlag);
        Assert.Equal(rest, gotRest);
    }

    [Theory]
    [InlineData("Helsinki 3")]
    [InlineData("NL-1")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("fi helsinki")] // lowercase ISO ignored
    public void TrySplit_HandlesMissingOrPlainNames(string? input)
    {
        var ok = ServerNameFlag.TrySplit(input, out var gotFlag, out var gotRest);
        Assert.False(ok);
        Assert.Equal("", gotFlag);
        Assert.Equal(input?.Trim() ?? "", gotRest);
    }

    [Fact]
    public void TrySplit_FlagOnlyEmoji()
    {
        Assert.True(ServerNameFlag.TrySplit("🇫🇮", out var flag, out var rest));
        Assert.Equal("🇫🇮", flag);
        Assert.Equal("", rest);
    }

    [Fact]
    public void WithFlagPrefix_AddsEmojiForIsoNames()
    {
        Assert.Equal("🇫🇮 Helsinki 3 tcp", ServerNameFlag.WithFlagPrefix("FI Helsinki 3 tcp"));
        Assert.Equal("🇫🇮 Helsinki 3", ServerNameFlag.WithFlagPrefix("🇫🇮 Helsinki 3"));
    }
}
