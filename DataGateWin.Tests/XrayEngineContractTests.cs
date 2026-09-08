using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Starter Xray wiring contracts (S1–S5) — no live TUN smoke.
/// </summary>
public sealed class XrayEngineContractTests
{
    [Fact]
    public void FetchScript_PinsLibXrayRelease()
    {
        var script = File.ReadAllText(FindRepoFile(Path.Combine("scripts", "libxray", "fetch-windows.ps1")));
        Assert.Contains("v26.7.28", script, StringComparison.Ordinal);
        Assert.Contains("libxray-windows-x64.zip", script, StringComparison.Ordinal);
        Assert.Contains("engine\\third_party\\libxray", script, StringComparison.Ordinal);
        Assert.Contains("VERSION.txt", script, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildDocs_DescribeRuntimeLayoutAndSmoke()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "BUILD_LIBXRAY_WINDOWS.md")));
        Assert.Contains("libXray.dll", doc, StringComparison.Ordinal);
        Assert.Contains("CGoInvoke", doc, StringComparison.Ordinal);
        Assert.Contains("protocol\": \"xray\"", doc, StringComparison.Ordinal);
        Assert.Contains("xrayShareLinks", doc, StringComparison.Ordinal);
        Assert.Contains("wintun.dll", doc, StringComparison.Ordinal);
    }

    [Fact]
    public void RemainingDoc_LinksTestStrategy()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "XRAY_WINDOWS_REMAINING.md")));
        Assert.Contains("XrayClientLinksApiClientTests", doc, StringComparison.Ordinal);
        Assert.Contains("XrayUiUnlockContractTests", doc, StringComparison.Ordinal);
    }

    [Fact]
    public void EngineSources_WireXrayProtocol()
    {
        var router = File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "app", "IpcCommandRouter.cpp")));
        Assert.Contains("xrayShareLinks", router, StringComparison.Ordinal);
        Assert.Contains("xrayConfigJson", router, StringComparison.Ordinal);
        Assert.Contains("protocol == \"xray\"", router, StringComparison.Ordinal);
        Assert.Contains("Missing xrayShareLinks or xrayConfigJson", router, StringComparison.Ordinal);

        var sessionH = File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "session", "SessionController.h")));
        Assert.Contains("xrayShareLinks", sessionH, StringComparison.Ordinal);
        Assert.Contains("xrayConfigJson", sessionH, StringComparison.Ordinal);
        Assert.Contains("protocol", sessionH, StringComparison.Ordinal);

        var session = File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "session", "SessionController.cpp")));
        Assert.Contains("StartXray", session, StringComparison.Ordinal);
        Assert.Contains("XrayConfigBuilder", session, StringComparison.Ordinal);
        Assert.Contains("IsRunning", session, StringComparison.Ordinal);
        Assert.Contains("user_stop", session, StringComparison.Ordinal);
        Assert.Contains("CollectProxyEndpointCidrs", session, StringComparison.Ordinal);
        Assert.Contains("autoSystemRoutingTable", 
            File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "xray", "XrayConfigBuilder.cpp"))),
            StringComparison.Ordinal);
        Assert.Contains("autoOutboundsInterface",
            File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "xray", "XrayConfigBuilder.cpp"))),
            StringComparison.Ordinal);
        Assert.Contains("xray_not_running", session, StringComparison.Ordinal);
        Assert.Contains("ExtractShareLinkOrEmpty", session, StringComparison.Ordinal);

        var builder = File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "xray", "XrayConfigBuilder.cpp")));
        Assert.Contains("AppendDirectBypassRules", builder, StringComparison.Ordinal);
        Assert.Contains("NormalizeMux", builder, StringComparison.Ordinal);
        Assert.Contains("AppendProxyDnsRules", builder, StringComparison.Ordinal);
        Assert.Contains("ExtractShareLinkOrEmpty", builder, StringComparison.Ordinal);

        var runtime = File.ReadAllText(FindRepoFile(Path.Combine("engine", "src", "xray", "XrayRuntime.cpp")));
        Assert.Contains("convertShareLinksToXrayJson", runtime, StringComparison.Ordinal);
        Assert.Contains("runXrayFromJson", runtime, StringComparison.Ordinal);
        Assert.Contains("stopXray", runtime, StringComparison.Ordinal);
        Assert.Contains("getXrayState", runtime, StringComparison.Ordinal);
        Assert.Contains("CGoInvoke", runtime, StringComparison.Ordinal);

        var cmake = File.ReadAllText(FindRepoFile(Path.Combine("engine", "CMakeLists.txt")));
        Assert.Contains("XrayRuntime.cpp", cmake, StringComparison.Ordinal);
        Assert.Contains("XrayConfigBuilder.cpp", cmake, StringComparison.Ordinal);
        Assert.Contains("libXray.dll", cmake, StringComparison.Ordinal);
    }

    [Fact]
    public void CoreBuilderMirror_ExistsForGoldenTests()
    {
        var path = FindRepoFile(Path.Combine(
            "DataGateWin.Core", "Services", "Xray", "XrayWindowsConfigBuilder.cs"));
        var src = File.ReadAllText(path);
        Assert.Contains("CollectProxyEndpointCidrs", src, StringComparison.Ordinal);
        Assert.Contains("ExtractShareLink", src, StringComparison.Ordinal);
        Assert.Contains("BuildWindowsTunClientConfig", src, StringComparison.Ordinal);
        Assert.Contains("PrepareShareOrOutboundsInput", src, StringComparison.Ordinal);
        Assert.Contains("DirectBypassCidrsPerRule", src, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildScripts_FetchAndCopyLibXray()
    {
        var release = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.UI", "Build-Release.ps1")));
        Assert.Contains("libXray.dll", release, StringComparison.Ordinal);
        Assert.Contains("fetch-windows.ps1", release, StringComparison.Ordinal);

        var engine = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.UI", "Build-Engine.ps1")));
        Assert.Contains("libXray.dll", engine, StringComparison.Ordinal);
        Assert.Contains("fetch-windows.ps1", engine, StringComparison.Ordinal);
    }

    [Fact]
    public void GitIgnore_AllowsVendoredLibXrayDll()
    {
        var gi = File.ReadAllText(FindRepoFile(".gitignore"));
        Assert.Contains("!engine/third_party/libxray/libXray.dll", gi, StringComparison.Ordinal);
    }

    [Fact]
    public void PublishLayoutDoc_ListsLibXray()
    {
        var doc = File.ReadAllText(FindRepoFile(Path.Combine("docs", "WINUI3_PUBLISH_LAYOUT.md")));
        Assert.Contains("libXray.dll", doc, StringComparison.Ordinal);
    }

    [Fact]
    public void StagedLibXrayArtifact_ExistsWithPin()
    {
        var dll = FindRepoFile(Path.Combine("engine", "third_party", "libxray", "libXray.dll"));
        Assert.True(new FileInfo(dll).Length > 1_000_000);

        var hdr = FindRepoFile(Path.Combine("engine", "third_party", "libxray", "libXray.h"));
        var hdrText = File.ReadAllText(hdr);
        Assert.Contains("CGoInvoke", hdrText, StringComparison.Ordinal);
        Assert.Contains("CGoFree", hdrText, StringComparison.Ordinal);
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
