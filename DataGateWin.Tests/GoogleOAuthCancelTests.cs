using DataGateWin.Services.Auth;
using Xunit;

namespace DataGateWin.Tests;

public sealed class GoogleOAuthCancelTests
{
    [Theory]
    [InlineData("access_denied")]
    [InlineData("ACCESS_DENIED")]
    [InlineData("cancelled")]
    [InlineData("canceled")]
    public void Google_user_cancel_errors_are_recognized(string error)
    {
        Assert.True(GoogleAuthService.IsUserCancelledError(error));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("server_error")]
    public void Other_google_errors_are_not_treated_as_cancel(string? error)
    {
        Assert.False(GoogleAuthService.IsUserCancelledError(error));
    }
}
