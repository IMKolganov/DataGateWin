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
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
}
