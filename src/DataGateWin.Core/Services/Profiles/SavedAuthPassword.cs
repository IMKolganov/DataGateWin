using System.Security.Cryptography;
using System.Text;

namespace DataGateWin.Services.Profiles;

/// <summary>
/// Opt-in storage of an OpenVPN password: DPAPI (current Windows user) + app-specific entropy.
/// Protects against copying the profile file to another machine/account, not against malware running as the same user.
/// </summary>
public static class SavedAuthPassword
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("DataGateWin.OpenVpnAuthPassword.v1");

    public static string? Protect(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return null;
        var cipher = ProtectedData.Protect(Encoding.UTF8.GetBytes(password), Entropy, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(cipher);
    }

    /// <summary>Returns null when nothing is stored or it cannot be decrypted (other user / corrupted).</summary>
    public static string? Unprotect(string? protectedBase64)
    {
        if (string.IsNullOrEmpty(protectedBase64))
            return null;
        try
        {
            var plain = ProtectedData.Unprotect(Convert.FromBase64String(protectedBase64), Entropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(plain);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
