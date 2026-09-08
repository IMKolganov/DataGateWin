using DataGateWin.Services.Installation;
using DataGateWin.Services.Profiles;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ImportedOpenVpnPayloadBuilderTests
{
    [Fact]
    public void Build_SetsUseWssBridgeFalse_AndOvpnContent()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\nremote vpn.example.com 1194 udp\n",
            SourceFileName = "lab.ovpn",
        };

        var payload = ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService());

        Assert.False(payload.Value<bool>("useWssBridge"));
        Assert.Equal(profile.ConfigText, payload.Value<string>("ovpnContent"));
        Assert.Equal("lab.ovpn", payload.Value<string>("ovpnFileName"));
        Assert.StartsWith("imported-", payload.Value<string>("cn"), StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(payload.Value<string>("installationId")));
    }

    [Fact]
    public void Build_RejectsXrayProtocol()
    {
        var profile = new ImportedVpnProfile
        {
            Protocol = ImportedVpnProtocol.Xray,
            ConfigText = "vless://example",
        };

        Assert.Throws<InvalidOperationException>(() =>
            ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService()));
    }

    [Fact]
    public void Build_RejectsInvalidOvpn()
    {
        var profile = new ImportedVpnProfile
        {
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\n",
        };

        Assert.Throws<InvalidOperationException>(() =>
            ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService()));
    }
}
