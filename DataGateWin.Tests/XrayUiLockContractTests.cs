using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.VpnServers;
using DataGateWin.Services.Xray;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Locks starter behavior: Xray stays hidden / Import locked / payload OpenVPN-only until Phase C.
/// </summary>
public sealed class XrayUiLockContractTests
{
    [Fact]
    public void ImportViewModel_XrayProtocol_CannotImport()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "ViewModels", "ImportViewModel.cs")));
        Assert.Contains("Import_XrayComingSoon", src, StringComparison.Ordinal);
        Assert.Contains("ProtocolIndex != 0", src, StringComparison.Ordinal);
        Assert.Contains("ImportedVpnProtocol.OpenVpn", src, StringComparison.Ordinal);
        Assert.Contains("CanConnect = p.Protocol == ImportedVpnProtocol.OpenVpn", src, StringComparison.Ordinal);
    }

    [Fact]
    public void ImportPage_ShowsComingSoonForXray()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "ImportPage.xaml.cs")));
        Assert.Contains("Import_XrayComingSoon", cs, StringComparison.Ordinal);
        Assert.Contains("XrayHintText", cs, StringComparison.Ordinal);

        var xaml = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "ImportPage.xaml")));
        Assert.Contains("XrayHintText", xaml, StringComparison.Ordinal);
    }

    [Fact]
    public void HomeController_RejectsImportedXrayConnect()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Controllers", "HomeController.cs")));
        Assert.Contains("Import_Log_XrayNotReady", src, StringComparison.Ordinal);
        Assert.Contains("ImportedVpnProtocol.OpenVpn", src, StringComparison.Ordinal);
    }

    [Fact]
    public void StartSessionPayloadBuilder_HasNoXrayProtocolBranchYet()
    {
        var src = File.ReadAllText(FindRepoFile(Path.Combine(
            "DataGateWin.Core", "Services", "Ipc", "StartSessionPayloadBuilder.cs")));
        Assert.DoesNotContain("xrayShareLinks", src, StringComparison.Ordinal);
        Assert.DoesNotContain("XrayClientLinksApiClient", src, StringComparison.Ordinal);
        Assert.Contains("OpenVpnFilesApiClient", src, StringComparison.Ordinal);
        Assert.Contains("ovpnContent", src, StringComparison.Ordinal);
    }

    [Fact]
    public void WssServerSelector_HidesAllXrayRows()
    {
        var openVpnWss = MakeRow(1, "Helsinki", VpnServerType.OpenVpn, wss: true, accessible: true);
        var xray = MakeRow(2, "Norway xray", VpnServerType.Xray, wss: false, accessible: true);
        var xrayWss = MakeRow(3, "Xray spoof", VpnServerType.Xray, wss: true, accessible: true);
        var openVpnNoWss = MakeRow(4, "Cyprus", VpnServerType.OpenVpn, wss: false, accessible: true);
        var openVpnNoQuota = MakeRow(5, "Tallinn", VpnServerType.OpenVpn, wss: true, accessible: false);

        Assert.False(WssServerSelector.IsWindowsSupported(xray.VpnServerResponses!.VpnServer));
        Assert.False(WssServerSelector.IsWindowsSupported(xrayWss.VpnServerResponses!.VpnServer));

        var wss = WssServerSelector.FilterWssEnabled([openVpnWss, xray, xrayWss, openVpnNoWss, openVpnNoQuota]);
        Assert.Equal(2, wss.Count);
        Assert.All(wss, r => Assert.Equal(VpnServerType.OpenVpn, r.VpnServerResponses!.VpnServer.ServerType));

        var eligible = WssServerSelector.FilterEligible([openVpnWss, xray, xrayWss, openVpnNoWss, openVpnNoQuota]);
        Assert.Single(eligible);
        Assert.Equal(1, eligible[0].VpnServerResponses!.VpnServer.Id);
    }

    [Fact]
    public void RemainingPlan_DocumentsP0AndUiLock()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "XRAY_WINDOWS_REMAINING.md")));
        Assert.Contains("Do not unlock Access / Import Xray UI", doc, StringComparison.Ordinal);
        Assert.Contains("direct bypass", doc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("S4", doc, StringComparison.Ordinal);
        Assert.Contains("XrayWindowsConfigBuilderTests", doc, StringComparison.Ordinal);
    }

    [Fact]
    public void PrepareShare_FromIssuedProfile_YieldsShareLinkForConvert()
    {
        var issued =
            """{"vless":"vless://uuid@host:443?encryption=none#n","dnsServers":["172.20.0.1"],"mux":{"enabled":true}}""";
        var prepared = XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput(issued);
        Assert.Equal("vless://uuid@host:443?encryption=none#n", prepared);
        Assert.Equal(
            ["172.20.0.1"],
            XrayWindowsConfigBuilder.ExtractExplicitDnsServers(issued));
    }

    [Fact]
    public void ExpectedIpcXrayPayload_ShapeForLabSmoke()
    {
        // Documents the engine IPC contract used by S4 — UI must not emit this until unlock.
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
