namespace DataGateWin.Services.Update;

public static class ReleaseVersionParser
{
    public static Version ParseTag(string tag)
    {
        tag = tag.Trim().TrimStart('v', 'V');
        return Version.TryParse(tag, out var version)
            ? version
            : new Version(0, 0, 0);
    }

    public static bool IsUpgradeAvailable(Version latest, Version current)
        => Normalize(latest) > Normalize(current);

    public static string FormatForDisplay(Version version)
        => version.Revision > 0 ? version.ToString(4) : Normalize(version).ToString(3);

    private static Version Normalize(Version version)
        => new(version.Major, version.Minor, Math.Max(0, version.Build), Math.Max(0, version.Revision));
}
