using DataGateWin.Services.Profiles;
using Xunit;

namespace DataGateWin.Tests;

public sealed class OpenVpnDynamicChallengeParserTests
{
    [Fact]
    public void ParsesCrv1Cookie()
    {
        const string cookie = "CRV1:E,R:sess-1:YWxpY2U=:Enter Google Authenticator Code";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(cookie, out var ch));
        Assert.NotNull(ch);
        Assert.Equal(cookie, ch!.Cookie);
        Assert.Equal("sess-1", ch.StateId);
        Assert.Equal("alice", ch.Username);
        Assert.Equal("Enter Google Authenticator Code", ch.ChallengeText);
        Assert.True(ch.Echo);
        Assert.True(ch.ResponseRequired);

        var req = ch.ToRequirement();
        Assert.False(req.NeedUsernamePassword);
        Assert.True(req.NeedChallenge);
        Assert.Equal("alice", req.PrefillUsername);
        Assert.Equal(cookie, req.DynamicChallengeCookie);
    }

    [Fact]
    public void ParsesPrefixedDisconnectReason()
    {
        const string raw = "DYNAMIC_CHALLENGE CRV1:R:abc:Ym9i:Token";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(raw, out var ch));
        Assert.Equal("bob", ch!.Username);
        Assert.False(ch.Echo);
        Assert.Equal("Token", ch.ChallengeText);
    }

    [Fact]
    public void ChallengeTextMayContainColons()
    {
        const string cookie = "CRV1:R:st::Please enter code: 123";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(cookie, out var ch));
        Assert.Equal("Please enter code: 123", ch!.ChallengeText);
        Assert.Equal("", ch.Username);
        Assert.True(ch.ToRequirement().NeedUsernamePassword);
    }

    [Fact]
    public void RejectsAuthFailedWithoutCrv1()
    {
        Assert.False(OpenVpnDynamicChallengeParser.TryParse("AUTH_FAILED", out _));
        Assert.False(OpenVpnDynamicChallengeParser.TryParse("DYNAMIC_CHALLENGE", out _));
        Assert.False(OpenVpnDynamicChallengeParser.TryParse("Server poll timeout, trying next remote entry...", out _));
        Assert.False(OpenVpnDynamicChallengeParser.TryParse(null, out _));
        Assert.False(OpenVpnDynamicChallengeParser.TryParse("   ", out _));
    }

    [Fact]
    public void ParsesCrv1EmbeddedInAuthFailedInfo()
    {
        const string raw = "AUTH_FAILED: CRV1:R:state-9:YWxpY2U=:Enter token";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(raw, out var ch));
        Assert.Equal("alice", ch!.Username);
        Assert.Equal("state-9", ch.StateId);
        Assert.StartsWith("CRV1:", ch.Cookie, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyFlags_ResponseRequired()
    {
        const string cookie = "CRV1::sid:YWxpY2U=:Why?";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(cookie, out var ch));
        Assert.True(ch!.ResponseRequired);
        Assert.False(ch.Echo);
        Assert.Equal("alice", ch.Username);
    }

    [Fact]
    public void EchoOnlyFlag_DoesNotRequireResponse()
    {
        const string cookie = "CRV1:E:sid:YWxpY2U=:FYI";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(cookie, out var ch));
        Assert.True(ch!.Echo);
        Assert.False(ch.ResponseRequired);
    }

    [Fact]
    public void InvalidUsernameBase64_LeavesUsernameEmpty()
    {
        const string cookie = "CRV1:R:sid:%%%not-b64%%%:Code";
        Assert.True(OpenVpnDynamicChallengeParser.TryParse(cookie, out var ch));
        Assert.Equal("", ch!.Username);
        Assert.True(ch.ToRequirement().NeedUsernamePassword);
        Assert.Equal(cookie, ch.ToRequirement().DynamicChallengeCookie);
    }

    [Fact]
    public void CaseInsensitiveCrv1Prefix()
    {
        Assert.True(OpenVpnDynamicChallengeParser.TryParse("dynamic_challenge crv1:R:s:Ym9i:Pin", out var ch));
        Assert.Equal("bob", ch!.Username);
        Assert.Equal("Pin", ch.ChallengeText);
    }

    [Fact]
    public void TruncatedCookie_Rejected()
    {
        Assert.False(OpenVpnDynamicChallengeParser.TryParse("CRV1:R:only-two", out _));
        Assert.False(OpenVpnDynamicChallengeParser.TryParse("CRV1:", out _));
    }
}
