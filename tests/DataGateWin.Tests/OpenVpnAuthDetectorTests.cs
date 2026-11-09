using DataGateWin.Services.Profiles;
using Xunit;

namespace DataGateWin.Tests;

public sealed class OpenVpnAuthDetectorTests
{
    [Fact]
    public void CertOnly_NoPrompt()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            <ca>
            x
            </ca>
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.False(r.NeedsPrompt);
        Assert.False(r.NeedUsernamePassword);
        Assert.False(r.NeedChallenge);
    }

    [Fact]
    public void AuthUserPass_NeedsUserAndPassword()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            auth-user-pass
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.True(r.NeedUsernamePassword);
        Assert.False(r.NeedChallenge);
        Assert.True(r.NeedsPrompt);
    }

    [Fact]
    public void CommentedAuthUserPass_Ignored()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            # auth-user-pass
            """;
        Assert.False(OpenVpnAuthDetector.Analyze(ovpn).NeedsPrompt);
    }

    [Fact]
    public void InlineAuthUserPass_NoPromptUnlessChallenge()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            <auth-user-pass>
            alice
            secret
            </auth-user-pass>
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.False(r.NeedUsernamePassword);
        Assert.Equal("alice", r.PrefillUsername);
        Assert.False(r.NeedsPrompt);
    }

    [Fact]
    public void StaticChallenge_NeedsOtp()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            auth-user-pass
            static-challenge "Enter Google Authenticator Code" 1
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.True(r.NeedUsernamePassword);
        Assert.True(r.NeedChallenge);
        Assert.Equal("Enter Google Authenticator Code", r.ChallengePrompt);
        Assert.True(r.ChallengeEcho);
    }

    [Fact]
    public void StaticChallengeEchoOff()
    {
        const string ovpn = """
            auth-user-pass
            remote x 1
            static-challenge "PIN" 0
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.False(r.ChallengeEcho);
        Assert.Equal("PIN", r.ChallengePrompt);
    }

    [Fact]
    public void TryGetInlineCredentials_ReadsEmbeddedUserPass()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            <auth-user-pass>
            alice
            secret
            </auth-user-pass>
            """;
        Assert.True(OpenVpnAuthDetector.TryGetInlineCredentials(ovpn, out var user, out var pass));
        Assert.Equal("alice", user);
        Assert.Equal("secret", pass);
    }

    [Fact]
    public void ForConnect_CertOnly_NoPrompt()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            """;
        var r = OpenVpnAuthDetector.ForConnect(ovpn, lastUsername: "ivankolganov");
        Assert.False(r.NeedsPrompt);
        Assert.False(r.NeedChallenge);
    }

    [Fact]
    public void ForConnect_PrefillsLastUsernameWhenAuthUserPass()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            auth-user-pass
            """;
        var r = OpenVpnAuthDetector.ForConnect(ovpn, lastUsername: "alice");
        Assert.True(r.NeedUsernamePassword);
        Assert.False(r.NeedChallenge);
        Assert.Equal("alice", r.PrefillUsername);
    }

    [Fact]
    public void ForConnect_DoesNotReplaceInlineUsername()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            <auth-user-pass>
            bob
            hidden
            </auth-user-pass>
            """;
        var r = OpenVpnAuthDetector.ForConnect(ovpn, lastUsername: "alice");
        Assert.False(r.NeedUsernamePassword);
        Assert.Equal("bob", r.PrefillUsername);
    }

    [Fact]
    public void SemicolonCommentedAuthUserPass_Ignored()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            ; auth-user-pass
            """;
        Assert.False(OpenVpnAuthDetector.Analyze(ovpn).NeedsPrompt);
    }

    [Fact]
    public void AuthUserPassWithCredsFile_StillNeedsPrompt()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            auth-user-pass credentials.txt
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.True(r.NeedUsernamePassword);
        Assert.False(r.NeedChallenge);
    }

    [Fact]
    public void StaticChallengeWithoutAuthUserPass_NeedsOtpOnly()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            static-challenge "OTP" 1
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.False(r.NeedUsernamePassword);
        Assert.True(r.NeedChallenge);
        Assert.Equal("OTP", r.ChallengePrompt);
        Assert.True(r.NeedsPrompt);
    }

    [Fact]
    public void InlineAuthPlusStaticChallenge_NeedsOtpOnly()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            <auth-user-pass>
            alice
            secret
            </auth-user-pass>
            static-challenge "Enter code" 1
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.False(r.NeedUsernamePassword);
        Assert.True(r.NeedChallenge);
        Assert.Equal("alice", r.PrefillUsername);
        Assert.True(r.NeedsPrompt);
    }

    [Fact]
    public void BareStaticChallenge_ReplacesUnderscores()
    {
        const string ovpn = """
            auth-user-pass
            remote x 1
            static-challenge Enter_PIN 0
            """;
        var r = OpenVpnAuthDetector.Analyze(ovpn);
        Assert.Equal("Enter PIN", r.ChallengePrompt);
        Assert.False(r.ChallengeEcho);
    }

    [Fact]
    public void CommentedStaticChallenge_Ignored()
    {
        const string ovpn = """
            client
            remote vpn.example.com 1194
            # static-challenge "OTP" 1
            """;
        Assert.False(OpenVpnAuthDetector.Analyze(ovpn).NeedChallenge);
        Assert.False(OpenVpnAuthDetector.Analyze(ovpn).NeedsPrompt);
    }

    [Fact]
    public void NullAndEmptyConfig_NoPrompt()
    {
        Assert.False(OpenVpnAuthDetector.Analyze(null).NeedsPrompt);
        Assert.False(OpenVpnAuthDetector.Analyze("").NeedsPrompt);
        Assert.False(OpenVpnAuthDetector.ForConnect(null, "ivan").NeedsPrompt);
    }

    [Fact]
    public void PritunlStyleCertOnly_DoesNotInventTwoFactor()
    {
        const string ovpn = """
            client
            proto udp
            remote 203.0.113.10 1194
            dev tun
            remote-cert-tls server
            auth SHA256
            cipher AES-128-GCM
            tls-client
            <ca>
            x
            </ca>
            <cert>
            y
            </cert>
            <key>
            z
            </key>
            <tls-crypt-v2>
            w
            </tls-crypt-v2>
            """;
        var r = OpenVpnAuthDetector.ForConnect(ovpn, lastUsername: "ivankolganov");
        Assert.False(r.NeedUsernamePassword);
        Assert.False(r.NeedChallenge);
        Assert.False(r.NeedsPrompt);
        Assert.Null(r.DynamicChallengeCookie);
    }
}
