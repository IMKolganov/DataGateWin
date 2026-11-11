using DataGateWin.Services.Installation;
using DataGateWin.Services.Profiles;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ImportedXrayPayloadBuilderTests
{
    [Fact]
    public void Build_SetsProtocolXrayAndShareLinks()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.Xray,
            ConfigText = "vless://uuid@host:443?encryption=none#lab",
            SourceFileName = "lab.txt",
        };

        var payload = ImportedXrayPayloadBuilder.Build(profile, new InstallationIdService());

        Assert.Equal("xray", payload.Value<string>("protocol"));
        Assert.Equal(profile.ConfigText, payload.Value<string>("xrayShareLinks"));
        Assert.StartsWith("imported-", payload.Value<string>("cn"), StringComparison.Ordinal);
        Assert.Null(payload["ovpnContent"]);
    }

    [Fact]
    public void Build_PreservesDnsServersFromIssuedJson()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.Xray,
            ConfigText = """{"vless":"vless://uuid@host:443?encryption=none#n","dnsServers":["172.20.0.1"]}""",
            SourceFileName = "lab.json",
        };

        var payload = ImportedXrayPayloadBuilder.Build(profile, new InstallationIdService());
        var share = JObject.Parse(payload.Value<string>("xrayShareLinks")!);
        Assert.Equal("172.20.0.1", share["dnsServers"]![0]!.Value<string>());
        Assert.Equal("172.20.0.1", payload["dnsServers"]![0]!.Value<string>());
    }

    [Fact]
    public void Build_RejectsOpenVpnProtocol()
    {
        var profile = new ImportedVpnProfile
        {
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\nremote vpn.example.com 1194 udp\n",
        };

        Assert.Throws<InvalidOperationException>(() =>
            ImportedXrayPayloadBuilder.Build(profile, new InstallationIdService()));
    }

    [Fact]
    public void Validator_AcceptsShareAndRejectsGarbage()
    {
        Assert.True(ImportedXrayValidator.TryValidate("vless://u@h:1?encryption=none#n", out _));
        Assert.True(ImportedXrayValidator.TryValidate(
            """{"vless":"vless://u@h:1?encryption=none#n","dnsServers":["1.1.1.1"]}""", out _));
        Assert.False(ImportedXrayValidator.TryValidate("client\nremote x 1\n", out var err));
        Assert.Equal("no_xray_share", err);
        Assert.False(ImportedXrayValidator.TryValidate("  ", out err));
        Assert.Equal("empty", err);
    }
}
