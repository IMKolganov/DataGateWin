using DataGateWin.Services.Profiles;
using Xunit;

namespace DataGateWin.Tests;

public sealed class ImportedVpnProfileStoreTests
{
    [Fact]
    public void Upsert_List_Get_Delete_RoundTrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "DataGateWin-tests", Guid.NewGuid().ToString("N"), "profiles.json");
        try
        {
            var store = new ImportedVpnProfileStore(path);
            var p = new ImportedVpnProfile
            {
                Name = "one",
                Protocol = ImportedVpnProtocol.OpenVpn,
                ConfigText = "remote a.example 1194\n",
                SourceFileName = "one.ovpn",
            };

            store.Upsert(p);
            var listed = store.List();
            Assert.Single(listed);
            Assert.Equal("one", listed[0].Name);

            var got = store.Get(p.Id);
            Assert.NotNull(got);
            Assert.Equal(p.ConfigText, got!.ConfigText);

            p.Name = "one-renamed";
            store.Upsert(p);
            Assert.Equal("one-renamed", store.Get(p.Id)!.Name);
            Assert.Single(store.List());

            Assert.True(store.Delete(p.Id));
            Assert.Empty(store.List());
            Assert.Null(store.Get(p.Id));
        }
        finally
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
                var dir = Path.GetDirectoryName(path);
                if (dir is not null && Directory.Exists(dir))
                    Directory.Delete(dir, recursive: true);
            }
            catch { /* ignore */ }
        }
    }
}
