using DataGateWin.Services.Security;
using Xunit;

namespace DataGateWin.Tests;

public sealed class TorrentProcessDetectorTests
{
    [Theory]
    [InlineData("qbittorrent", true)]
    [InlineData("qBittorrent.exe", true)]
    [InlineData("utorrent", true)]
    [InlineData("transmission-qt", true)]
    [InlineData("BiglyBT.exe", true)]
    [InlineData("Tribler", true)]
    [InlineData("WebTorrent.exe", true)]
    [InlineData("PicoTorrent", true)]
    [InlineData("chrome", false)]
    [InlineData("explorer.exe", false)]
    [InlineData("", false)]
    public void IsTorrentProcessName_DetectsKnownClients(string processName, bool expected)
    {
        Assert.Equal(expected, TorrentProcessDetector.IsTorrentProcessName(processName));
    }

    [Fact]
    public void DetectFromProcessNames_ReturnsDistinctSortedDetectedNames()
    {
        var detected = TorrentProcessDetector.DetectFromProcessNames(
        [
            "qbittorrent.exe",
            "chrome",
            "uTorrent",
            "UTORRENT.exe",
            "explorer"
        ]);

        Assert.Equal(2, detected.Count);
        Assert.Equal("qbittorrent", detected[0], ignoreCase: true);
        Assert.Equal("uTorrent", detected[1], ignoreCase: true);
    }
}
