using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateWin.Services.Auth;
using Xunit;

namespace DataGateWin.Tests;

public sealed class LoginFlowTests
{
    [Fact]
    public void Resolve_TotpChallenge_WithoutTokens()
    {
        var flow = LoginFlow.Resolve(new GoogleLoginResponse
        {
            RequiresTotp = true,
            LoginChallengeId = "challenge-1",
            DisplayName = "Admin User",
        });

        var challenge = Assert.IsType<ResolvedLoginFlow.TotpChallenge>(flow);
        Assert.Equal("challenge-1", challenge.LoginChallengeId);
        Assert.Equal("Admin User", challenge.DisplayName);
    }

    [Fact]
    public void Resolve_Tokens_WithSetupFlag()
    {
        var flow = LoginFlow.Resolve(new GoogleLoginResponse
        {
            Token = "access",
            Expiration = DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
            RefreshToken = "refresh",
            RequiresTotpSetup = true,
            DisplayName = "User",
        });

        var tokens = Assert.IsType<ResolvedLoginFlow.Tokens>(flow);
        Assert.True(tokens.RequiresTotpSetup);
        Assert.Equal("access", tokens.Response.Token);
    }

    [Fact]
    public void Resolve_MissingToken_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            LoginFlow.Resolve(new GoogleLoginResponse
            {
                RequiresTotp = false,
                Token = " ",
            }));
    }

    [Fact]
    public void IsLoginChallengeExpiredMessage_MatchesApiPhrases()
    {
        Assert.True(LoginFlow.IsLoginChallengeExpiredMessage("Login challenge expired"));
        Assert.True(LoginFlow.IsLoginChallengeExpiredMessage("Too many invalid attempts"));
        Assert.True(LoginFlow.IsLoginChallengeExpiredMessage("Please sign in again"));
        Assert.False(LoginFlow.IsLoginChallengeExpiredMessage("Invalid code"));
    }
}
