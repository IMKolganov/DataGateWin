using System.Text;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Identity;

public static class JwtClaimReader
{
    public static string? GetClaimFromBearerToken(string? bearerToken, string claimName)
    {
        if (string.IsNullOrWhiteSpace(bearerToken))
            return null;

        var parts = bearerToken.Split('.');
        if (parts.Length < 2)
            return null;

        var payload = parts[1]
            .Replace('-', '+')
            .Replace('_', '/');

        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }

        var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
        var obj = JObject.Parse(json);

        return obj.Value<string>(claimName);
    }

    /// <summary>Linux parity: <c>nameid</c> then WS-Federation nameidentifier claim (numeric user id for quota APIs).</summary>
    public static string? GetNumericUserIdFromBearerToken(string? bearerToken) =>
        GetClaimFromBearerToken(bearerToken, "nameid")
        ?? GetClaimFromBearerToken(
            bearerToken,
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

    /// <summary>
    /// Resolves a human-readable name: prefers Google-style <c>given_name</c> + <c>family_name</c>,
    /// then full <c>name</c>, then backend/alternate claim pairs, then login handles.
    /// </summary>
    public static string? GetDisplayNameFromBearerToken(string? bearerToken)
    {
        var given = GetClaimFromBearerToken(bearerToken, "given_name");
        var family = GetClaimFromBearerToken(bearerToken, "family_name");
        if (!string.IsNullOrWhiteSpace(given) && !string.IsNullOrWhiteSpace(family))
            return $"{given.Trim()} {family.Trim()}";

        if (!string.IsNullOrWhiteSpace(given))
            return given.Trim();

        if (!string.IsNullOrWhiteSpace(family))
            return family.Trim();

        var firstAlt = GetClaimFromBearerToken(bearerToken, "first_name")
            ?? GetClaimFromBearerToken(bearerToken, "firstName");
        var lastAlt = GetClaimFromBearerToken(bearerToken, "last_name")
            ?? GetClaimFromBearerToken(bearerToken, "lastName");
        if (!string.IsNullOrWhiteSpace(firstAlt) && !string.IsNullOrWhiteSpace(lastAlt))
            return $"{firstAlt.Trim()} {lastAlt.Trim()}";

        if (!string.IsNullOrWhiteSpace(firstAlt))
            return firstAlt.Trim();

        if (!string.IsNullOrWhiteSpace(lastAlt))
            return lastAlt.Trim();

        var name = GetClaimFromBearerToken(bearerToken, "name");
        if (!string.IsNullOrWhiteSpace(name))
            return name.Trim();

        var unique = GetClaimFromBearerToken(bearerToken, "unique_name");
        if (!string.IsNullOrWhiteSpace(unique))
            return unique.Trim();

        var preferred = GetClaimFromBearerToken(bearerToken, "preferred_username");
        if (!string.IsNullOrWhiteSpace(preferred))
            return preferred.Trim();

        return null;
    }

    /// <summary>Google OIDC profile photo URL.</summary>
    public static string? GetPictureUrlFromBearerToken(string? bearerToken) =>
        GetClaimFromBearerToken(bearerToken, "picture");

    /// <summary>DataGate backend stores avatar on user; JWT claim <c>avatarUrl</c>. Fallback: Google <c>picture</c>.</summary>
    public static string? GetProfileImageUrlFromBearerToken(string? bearerToken)
    {
        var backend = GetClaimFromBearerToken(bearerToken, "avatarUrl");
        if (!string.IsNullOrWhiteSpace(backend))
            return backend.Trim();

        return GetPictureUrlFromBearerToken(bearerToken)?.Trim();
    }

    /// <summary>ASP.NET role claim may be a string or JSON array. Prefer "Admin" when present.</summary>
    public static string? GetRoleFromBearerToken(string? bearerToken)
    {
        var obj = TryParsePayload(bearerToken);
        if (obj is null)
            return null;

        return ReadRoleClaim(obj, "role")
            ?? ReadRoleClaim(obj, "http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
    }

    /// <summary>Android parity: JWT role equals Admin (case-insensitive).</summary>
    public static bool IsAdmin(string? bearerToken)
    {
        var role = GetRoleFromBearerToken(bearerToken);
        return !string.IsNullOrWhiteSpace(role)
            && role.Equals("Admin", StringComparison.OrdinalIgnoreCase);
    }

    private static JObject? TryParsePayload(string? bearerToken)
    {
        if (string.IsNullOrWhiteSpace(bearerToken))
            return null;

        var parts = bearerToken.Split('.');
        if (parts.Length < 2)
            return null;

        var payload = parts[1]
            .Replace('-', '+')
            .Replace('_', '/');

        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            return JObject.Parse(json);
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadRoleClaim(JObject obj, string claimName)
    {
        var token = obj[claimName];
        if (token is null || token.Type == JTokenType.Null)
            return null;

        if (token.Type == JTokenType.String)
        {
            var s = token.Value<string>()?.Trim();
            return string.IsNullOrEmpty(s) ? null : s;
        }

        if (token is JArray arr)
        {
            string? fallback = null;
            foreach (var item in arr)
            {
                var s = item.Type == JTokenType.String ? item.Value<string>()?.Trim() : item.ToString()?.Trim();
                if (string.IsNullOrEmpty(s))
                    continue;
                if (s.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                    return s;
                fallback ??= s;
            }
            return fallback;
        }

        return null;
    }
}