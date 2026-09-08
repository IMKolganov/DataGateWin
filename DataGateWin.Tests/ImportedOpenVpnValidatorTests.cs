using DataGateWin.Services.Profiles;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ImportedOpenVpnValidatorTests
{
    [Fact]
    public void TryValidate_AcceptsSingleRemote()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194 udp
            <ca>
            ---
            </ca>
            """;
        Assert.True(ImportedOpenVpnValidator.TryValidate(ovpn, out var err));
        Assert.Equal("", err);
    }

    [Theory]
    [InlineData("", "empty")]
    [InlineData("client\ndev tun\n", "no_remote")]
    [InlineData("remote a 1\nremote b 2\n", "multiple_remote")]
    public void TryValidate_RejectsBadConfigs(string ovpn, string code)
    {
        Assert.False(ImportedOpenVpnValidator.TryValidate(ovpn, out var err));
        Assert.Equal(code, err);
    }

    [Fact]
    public void SuggestName_UsesFileNameThenRemote()
    {
        Assert.Equal("my-client", ImportedOpenVpnValidator.SuggestName("my-client.ovpn", "remote x 1"));
        Assert.Equal("vpn.example.com", ImportedOpenVpnValidator.SuggestName(null, "remote vpn.example.com 1194"));
    }
}
