using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.VpnServers;
using DataGateWin.Services.Xray;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Catalog / Import / payload must expose Xray after Phase C unlock.
/// </summary>
public sealed class XrayUiUnlockContractTests
{
    [Fact]
    public void ImportViewModel_AllowsXrayImportAndConnect()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "ViewModels", "ImportViewModel.cs")));
        Assert.Contains("ImportXrayText", src, StringComparison.Ordinal);
        Assert.Contains("ImportedVpnProtocol.Xray", src, StringComparison.Ordinal);
        Assert.Contains("CanConnect = true", src, StringComparison.Ordinal);
        Assert.DoesNotContain("Import_XrayComingSoon", src, StringComparison.Ordinal);
    }

    [Fact]
    public void ImportPage_EnablesXrayBrowseAndPaste()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "ImportPage.xaml.cs")));
        Assert.Contains("Import_Hint_Xray", cs, StringComparison.Ordinal);
        Assert.Contains("ImportText", cs, StringComparison.Ordinal);
        Assert.DoesNotContain("if (!_vm.IsOpenVpnSelected)", cs, StringComparison.Ordinal);
    }

    [Fact]
    public void HomeController_StartsImportedXray()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Controllers", "HomeController.cs")));
        Assert.Contains("ImportedXrayPayloadBuilder", src, StringComparison.Ordinal);
        Assert.Contains("XrayClientLinksApiClient", src, StringComparison.Ordinal);
        Assert.DoesNotContain("Import_Log_XrayNotReady", src, StringComparison.Ordinal);
    }

    [Fact]
    public void StartSessionPayloadBuilder_HasXrayProtocolBranch()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine(
            "DataGateWin.Core", "Services", "Ipc", "StartSessionPayloadBuilder.cs")));
        Assert.Contains("xrayShareLinks", src, StringComparison.Ordinal);
        Assert.Contains("XrayClientLinksApiClient", src, StringComparison.Ordinal);
        Assert.Contains("VpnServerType.Xray", src, StringComparison.Ordinal);
        Assert.Contains("OpenVpnFilesApiClient", src, StringComparison.Ordinal);
        Assert.Contains("useWssBridge", src, StringComparison.Ordinal);
        Assert.Contains("IsEnableWss", src, StringComparison.Ordinal);
    }

    [Fact]
    public void WssServerSelector_KeepsOpenVpnWssAndXray()
    {
        var openVpnWss = MakeRow(1, "Helsinki", VpnServerType.OpenVpn, wss: true, accessible: true);
        var xray = MakeRow(2, "Norway xray", VpnServerType.Xray, wss: false, accessible: true);
        var xrayWss = MakeRow(3, "Xray spoof", VpnServerType.Xray, wss: true, accessible: true);
        var openVpnNoWss = MakeRow(4, "Cyprus", VpnServerType.OpenVpn, wss: false, accessible: true);
        var openVpnNoQuota = MakeRow(5, "Tallinn", VpnServerType.OpenVpn, wss: true, accessible: false);

        Assert.True(WssServerSelector.IsWindowsSupported(xray.VpnServerResponses!.VpnServer));
        Assert.True(WssServerSelector.IsXrayWindowsSupported(xray.VpnServerResponses!.VpnServer));
        Assert.True(WssServerSelector.IsWindowsSupported(openVpnNoWss.VpnServerResponses!.VpnServer));
        Assert.True(WssServerSelector.IsOpenVpnDirect(openVpnNoWss.VpnServerResponses!.VpnServer));

        var listed = WssServerSelector.FilterWssEnabled([openVpnWss, xray, xrayWss, openVpnNoWss, openVpnNoQuota]);
        Assert.Equal(5, listed.Count);
        Assert.Contains(listed, r => r.VpnServerResponses!.VpnServer.Id == 1);
        Assert.Contains(listed, r => r.VpnServerResponses!.VpnServer.Id == 2);
        Assert.Contains(listed, r => r.VpnServerResponses!.VpnServer.Id == 3);
        Assert.Contains(listed, r => r.VpnServerResponses!.VpnServer.Id == 4);
        Assert.Contains(listed, r => r.VpnServerResponses!.VpnServer.Id == 5);

        var eligible = WssServerSelector.FilterEligible([openVpnWss, xray, xrayWss, openVpnNoWss, openVpnNoQuota]);
        Assert.Equal(4, eligible.Count);
        Assert.Contains(eligible, r => r.VpnServerResponses!.VpnServer.Id == 4);
        Assert.DoesNotContain(eligible, r => r.VpnServerResponses!.VpnServer.Id == 5);
    }

    [Fact]
    public void RemainingPlan_DocumentsUnlock()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "XRAY_WINDOWS_REMAINING.md")));
        Assert.Contains("unlocked", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("XrayUiUnlockContractTests", doc, StringComparison.Ordinal);
        Assert.Contains("rdp-vpn-safety-kill", doc, StringComparison.Ordinal);
    }

    [Fact]
    public void ExpectedIpcXrayPayload_ShapeForLabSmoke()
    {
        var payload = new JObject
        {
            ["protocol"] = "xray",
            ["xrayShareLinks"] = "vless://uuid@host:443?encryption=none#lab"
        };
        Assert.Equal("xray", payload.Value<string>("protocol"));
        Assert.False(string.IsNullOrWhiteSpace(payload.Value<string>("xrayShareLinks")));
        Assert.Null(payload["ovpnContent"]);
    }

    private static VpnServerWithStatusV2Dto MakeRow(
        int id,
        string name,
        VpnServerType type,
        bool wss,
        bool accessible)
    {
        var responsesType = typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.PropertyType;
        var responses = Activator.CreateInstance(responsesType)!;
        var server = Activator.CreateInstance(typeof(VpnServerV2Dto))!;
        typeof(VpnServerV2Dto).GetProperty("Id")!.SetValue(server, id);
        typeof(VpnServerV2Dto).GetProperty("ServerName")!.SetValue(server, name);
        typeof(VpnServerV2Dto).GetProperty("ServerType")!.SetValue(server, type);
        typeof(VpnServerV2Dto).GetProperty("IsEnableWss")!.SetValue(server, wss);
        typeof(VpnServerV2Dto).GetProperty("IsAccessibleForUserQuotaPlan")!.SetValue(server, accessible);

        responsesType.GetProperty("VpnServer")!.SetValue(responses, server);
        var row = Activator.CreateInstance(typeof(VpnServerWithStatusV2Dto))!;
        typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.SetValue(row, responses);
        return (VpnServerWithStatusV2Dto)row;
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
