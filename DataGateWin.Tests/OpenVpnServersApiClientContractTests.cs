using Xunit;

namespace DataGateWin.Tests;

public sealed class OpenVpnServersApiClientContractTests
{
    [Fact]
    public void OpenVpnServersApiClient_UsesV3GetAllWithStatusOnly()
    {
        var path = FindRepoFile(Path.Combine("DataGateWin.Core", "Services", "VpnServers", "OpenVpnServersApiClient.cs"));
        var src = File.ReadAllText(path);

        Assert.Contains("api/v3/open-vpn-servers/get-all-with-status", src, StringComparison.Ordinal);
        Assert.DoesNotContain("api/v2/open-vpn-servers", src, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api/open-vpn-servers/get-all", src, StringComparison.OrdinalIgnoreCase);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "DataGateWin.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("repo root");
    }

    private static string FindRepoFile(string relative)
    {
        var candidate = Path.Combine(FindRepoRoot(), relative);
        if (!File.Exists(candidate))
            throw new FileNotFoundException(relative);
        return candidate;
    }
}
