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
        Assert.Null(payload["openVpnUsername"]);
    }

    [Fact]
    public void Build_IncludesCredentialsWhenProvided_DoesNotRewriteOvpn()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\nremote vpn.example.com 1194 udp\nauth-user-pass\n",
        };

        var payload = ImportedOpenVpnPayloadBuilder.Build(
            profile,
            new InstallationIdService(),
            new OpenVpnAuthCredentials { Username = "alice", Password = "secret", Response = "123456" });

        Assert.Equal("alice", payload.Value<string>("openVpnUsername"));
        Assert.Equal("secret", payload.Value<string>("openVpnPassword"));
        Assert.Equal("123456", payload.Value<string>("openVpnResponse"));
        Assert.Equal(profile.ConfigText, payload.Value<string>("ovpnContent"));
        Assert.DoesNotContain("static-challenge", payload.Value<string>("ovpnContent"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_DoesNotInjectAuthIntoCertOnlyProfile()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\nremote vpn.example.com 1194 udp\n",
        };

        var payload = ImportedOpenVpnPayloadBuilder.Build(
            profile,
            new InstallationIdService(),
            new OpenVpnAuthCredentials
            {
                Username = "ivan",
                Response = "654321",
                DynamicChallengeCookie = "CRV1:R:st:aXZhbg==:Token",
            });

        var ovpn = payload.Value<string>("ovpnContent") ?? "";
        Assert.Equal(profile.ConfigText, ovpn);
        Assert.DoesNotContain("auth-user-pass", ovpn, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("static-challenge", ovpn, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("CRV1:R:st:aXZhbg==:Token", payload.Value<string>("openVpnChallengeCookie"));
        Assert.Equal("654321", payload.Value<string>("openVpnResponse"));
    }

    [Fact]
    public void Build_UsesInlineAuthUserPassWhenNoCredentialsPassed()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = """
                client
                remote vpn.example.com 1194 udp
                <auth-user-pass>
                bob
                hidden
                </auth-user-pass>
                """,
        };

        var payload = ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService());

        Assert.Equal("bob", payload.Value<string>("openVpnUsername"));
        Assert.Equal("hidden", payload.Value<string>("openVpnPassword"));
        Assert.Equal("", payload.Value<string>("openVpnResponse"));
    }

    [Fact]
    public void Build_InlineCredentialsWithStaticChallenge_KeepsPasswordAndResponse()
    {
        var profile = new ImportedVpnProfile
        {
            ConfigText = "client\nremote vpn.example.com 1194 udp\nstatic-challenge \"OTP\" 0\n<auth-user-pass>\nbob\nhidden\n</auth-user-pass>\n",
        };
        var requirement = OpenVpnAuthDetector.ForConnect(profile.ConfigText, null);
        Assert.False(requirement.NeedUsernamePassword);
        Assert.True(requirement.NeedChallenge);

        var payload = ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService(),
            new OpenVpnAuthCredentials { Username = requirement.PrefillUsername!, Response = "123456" });

        Assert.Equal("bob", payload.Value<string>("openVpnUsername"));
        Assert.Equal("hidden", payload.Value<string>("openVpnPassword"));
        Assert.Equal("123456", payload.Value<string>("openVpnResponse"));
    }

    [Fact]
    public void Build_DynamicChallenge_DoesNotRestoreInlinePassword()
    {
        var profile = new ImportedVpnProfile
        {
            ConfigText = "client\nremote vpn.example.com 1194 udp\n<auth-user-pass>\nbob\nhidden\n</auth-user-pass>\n",
        };
        var payload = ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService(),
            new OpenVpnAuthCredentials
            {
                Username = "bob",
                Response = "123456",
                DynamicChallengeCookie = "CRV1:R:state:Ym9i:OTP",
            });

        Assert.Equal("", payload.Value<string>("openVpnPassword"));
        Assert.Equal("123456", payload.Value<string>("openVpnResponse"));
        Assert.Equal("CRV1:R:state:Ym9i:OTP", payload.Value<string>("openVpnChallengeCookie"));
    }

    [Fact]
    public void Build_ExplicitCredentials_DoNotUseAnotherUsersInlinePassword()
    {
        var profile = new ImportedVpnProfile
        {
            ConfigText = "client\nremote vpn.example.com 1194 udp\n<auth-user-pass>\nbob\nhidden\n</auth-user-pass>\n",
        };
        var payload = ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService(),
            new OpenVpnAuthCredentials { Username = "alice", Response = "123456" });

        Assert.Equal("alice", payload.Value<string>("openVpnUsername"));
        Assert.Equal("", payload.Value<string>("openVpnPassword"));
    }

    [Fact]
    public void Build_CertOnlyWithoutCredentials_DoesNotAddAuthFields()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\nremote vpn.example.com 1194 udp\n",
        };

        var payload = ImportedOpenVpnPayloadBuilder.Build(profile, new InstallationIdService());

        Assert.Null(payload["openVpnUsername"]);
        Assert.Null(payload["openVpnPassword"]);
        Assert.Null(payload["openVpnResponse"]);
        Assert.Null(payload["openVpnChallengeCookie"]);
        Assert.Equal(profile.ConfigText, payload.Value<string>("ovpnContent"));
    }

    [Fact]
    public void Build_OmitsChallengeCookieWhenEmpty()
    {
        var profile = new ImportedVpnProfile
        {
            Id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            Name = "lab",
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = "client\nremote vpn.example.com 1194 udp\nauth-user-pass\n",
        };

        var payload = ImportedOpenVpnPayloadBuilder.Build(
            profile,
            new InstallationIdService(),
            new OpenVpnAuthCredentials { Username = "alice", Password = "secret" });

        Assert.Equal("alice", payload.Value<string>("openVpnUsername"));
        Assert.Null(payload["openVpnChallengeCookie"]);
        Assert.Equal(profile.ConfigText, payload.Value<string>("ovpnContent"));
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
