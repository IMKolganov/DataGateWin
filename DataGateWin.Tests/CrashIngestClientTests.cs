using DataGateWin.CrashReporting;
using Xunit;

namespace DataGateWin.Tests;

public sealed class CrashIngestClientTests
{
    [Theory]
    [InlineData("https://api.example.com", "https://api.example.com/api/v1/windows/crash-ingest")]
    [InlineData("https://api.example.com/", "https://api.example.com/api/v1/windows/crash-ingest")]
    public void BuildRequestUri_AppendsIngestPath(string baseUrl, string expected)
    {
        var uri = CrashIngestClient.BuildRequestUri(baseUrl);
        Assert.Equal(expected, uri.ToString());
    }
}
