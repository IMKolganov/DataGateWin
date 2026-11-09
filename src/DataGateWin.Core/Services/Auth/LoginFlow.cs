using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using System.Text.RegularExpressions;

namespace DataGateWin.Services.Auth;

public abstract record ResolvedLoginFlow
{
    public sealed record TotpChallenge(string LoginChallengeId, string? DisplayName) : ResolvedLoginFlow;

    /// <summary>Tokens are present; persist before continuing. <see cref="RequiresTotpSetup"/> may gate admin UI.</summary>
    public sealed record Tokens(GoogleLoginResponse Response, bool RequiresTotpSetup) : ResolvedLoginFlow;
}

public static class LoginFlow
{
    private static readonly Regex ChallengeExpired = new(
        "challenge expired|too many invalid attempts|sign in again",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static ResolvedLoginFlow Resolve(GoogleLoginResponse payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.RequiresTotp && !string.IsNullOrWhiteSpace(payload.LoginChallengeId))
        {
            return new ResolvedLoginFlow.TotpChallenge(
                payload.LoginChallengeId.Trim(),
                payload.DisplayName);
        }

        if (string.IsNullOrWhiteSpace(payload.Token))
            throw new InvalidOperationException("No token returned by API.");

        return new ResolvedLoginFlow.Tokens(payload, payload.RequiresTotpSetup);
    }

    public static bool IsLoginChallengeExpiredMessage(string? message) =>
        !string.IsNullOrWhiteSpace(message) && ChallengeExpired.IsMatch(message);
}
