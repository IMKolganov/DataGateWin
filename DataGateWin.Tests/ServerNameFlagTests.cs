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
    [InlineData("Helsinki 3", "🇫🇮", "Helsinki 3")]
    [InlineData("Helsinki", "🇫🇮", "Helsinki")]
    [InlineData("helsinki", "🇫🇮", "helsinki")]
    [InlineData("Norway", "🇳🇴", "Norway")]
    [InlineData("cyprus", "🇨🇾", "cyprus")]
    [InlineData("norway-xray", "🇳🇴", "norway-xray")]
    [InlineData("NL-1", "🇳🇱", "1")]
    [InlineData("de-1", "🇩🇪", "1")]
    [InlineData("ru-1", "🇷🇺", "1")]
    public void TrySplit_InfersFlagFromPlaceOrIsoId(string input, string flag, string rest)
    {
        Assert.True(ServerNameFlag.TrySplit(input, out var gotFlag, out var gotRest));
        Assert.Equal(flag, gotFlag);
        Assert.Equal(rest, gotRest);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("s1-7")]
    [InlineData("xray-1")]
    [InlineData("ambiguous")]
    public void TrySplit_HandlesMissingOrUnknownNames(string? input)
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

    [Theory]
    [InlineData("Helsinki 3", "FI")]
    [InlineData("FI Helsinki 3 tcp", "FI")]
    [InlineData("🇫🇮 Helsinki 3", "FI")]
    [InlineData("NL-1", "NL")]
    [InlineData("norway-xray", "NO")]
    public void TryGetIso2_FromPlaceIsoOrEmoji(string input, string iso)
    {
        Assert.True(ServerNameFlag.TryGetIso2(input, out var got));
        Assert.Equal(iso, got);
    }

    [Fact]
    public void WithFlagPrefix_AddsEmojiForRealApiNames()
    {
        Assert.Equal("🇫🇮 Helsinki 3", ServerNameFlag.WithFlagPrefix("Helsinki 3"));
        Assert.Equal("🇳🇱 1", ServerNameFlag.WithFlagPrefix("NL-1"));
        Assert.Equal("🇫🇮 Helsinki 3 tcp", ServerNameFlag.WithFlagPrefix("FI Helsinki 3 tcp"));
        Assert.Equal("🇫🇮 Helsinki 3", ServerNameFlag.WithFlagPrefix("🇫🇮 Helsinki 3"));
    }
}
