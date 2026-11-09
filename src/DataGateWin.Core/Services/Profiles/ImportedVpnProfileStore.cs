using System.Text.Json;
using DataGateWin.CrashReporting;

namespace DataGateWin.Services.Profiles;

public sealed class ImportedVpnProfileStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly object _gate = new();
    private readonly string _path;

    public ImportedVpnProfileStore(string? storePath = null)
    {
        _path = storePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DataGateWin",
            "imported-profiles.json");
    }

    public IReadOnlyList<ImportedVpnProfile> List()
    {
        lock (_gate)
            return LoadUnlocked().OrderByDescending(p => p.UpdatedUtc).ToList();
    }

    public ImportedVpnProfile? Get(Guid id)
    {
        lock (_gate)
            return LoadUnlocked().FirstOrDefault(p => p.Id == id);
    }

    public ImportedVpnProfile Upsert(ImportedVpnProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        lock (_gate)
        {
            var list = LoadUnlocked();
            var idx = list.FindIndex(p => p.Id == profile.Id);
            profile.UpdatedUtc = DateTimeOffset.UtcNow;
            if (idx < 0)
            {
                if (profile.CreatedUtc == default)
                    profile.CreatedUtc = profile.UpdatedUtc;
                list.Add(profile);
            }
            else
            {
                profile.CreatedUtc = list[idx].CreatedUtc;
                list[idx] = profile;
            }

            SaveUnlocked(list);
            return profile;
        }
    }

    public bool Delete(Guid id)
    {
        lock (_gate)
        {
            var list = LoadUnlocked();
            var n = list.RemoveAll(p => p.Id == id);
            if (n > 0)
                SaveUnlocked(list);
            return n > 0;
        }
    }

    private List<ImportedVpnProfile> LoadUnlocked()
    {
        try
        {
            if (!File.Exists(_path))
                return [];

            var json = File.ReadAllText(_path);
            var list = JsonSerializer.Deserialize<List<ImportedVpnProfile>>(json, JsonOptions);
            return list ?? [];
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "ImportedVpnProfileStore.Load");
            return [];
        }
    }

    private void SaveUnlocked(List<ImportedVpnProfile> list)
    {
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(list, JsonOptions));
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "ImportedVpnProfileStore.Save");
        }
    }
}
