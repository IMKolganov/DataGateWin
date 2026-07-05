using System.Net;
using System.Net.Http;
using System.Text;
using DataGateWin.Services.Update;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ReleaseVersionParserTests
{
    [Theory]
    [InlineData("1.0.8", 1, 0, 8)]
    [InlineData("v1.0.8", 1, 0, 8)]
    [InlineData("V2.3.4", 2, 3, 4)]
    public void ParseTag_ParsesPlainAndPrefixedTags(string tag, int major, int minor, int build)
    {
        var version = ReleaseVersionParser.ParseTag(tag);

        Assert.Equal(new Version(major, minor, build), version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-version")]
    public void ParseTag_ReturnsZeroVersionForInvalidTags(string tag)
    {
        Assert.Equal(new Version(0, 0, 0), ReleaseVersionParser.ParseTag(tag));
    }

    [Theory]
    [InlineData("1.0.8", "1.0.7", true)]
    [InlineData("1.0.8", "1.0.8", false)]
    [InlineData("1.0.8", "1.0.9", false)]
    [InlineData("2.0.0", "1.9.9", true)]
    public void IsUpgradeAvailable_ComparesReleaseTags(string latest, string current, bool expected)
    {
        var result = ReleaseVersionParser.IsUpgradeAvailable(
            ReleaseVersionParser.ParseTag(latest),
            ReleaseVersionParser.ParseTag(current));

        Assert.Equal(expected, result);
    }

    [Fact]
    public void FormatForDisplay_UsesThreePartVersion()
    {
        Assert.Equal("1.0.8", ReleaseVersionParser.FormatForDisplay(new Version(1, 0, 8, 99)));
    }
}
