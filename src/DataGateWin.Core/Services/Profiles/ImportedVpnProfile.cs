namespace DataGateWin.Services.Profiles;

public enum ImportedVpnProtocol
{
    OpenVpn = 0,
    Xray = 1,
}

public sealed class ImportedVpnProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public ImportedVpnProtocol Protocol { get; set; } = ImportedVpnProtocol.OpenVpn;
    public string ConfigText { get; set; } = "";
    public string? SourceFileName { get; set; }
    /// <summary>Last OpenVPN username used for <c>auth-user-pass</c> (the password is only stored when the user opts in, see <see cref="EncryptedAuthPassword"/>).</summary>
    public string? LastAuthUsername { get; set; }
    /// <summary>
    /// Opt-in: OpenVPN password encrypted with DPAPI (current Windows user), base64. Storing it is not recommended.
    /// </summary>
    public string? EncryptedAuthPassword { get; set; }
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
}
