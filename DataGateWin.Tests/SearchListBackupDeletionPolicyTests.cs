using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Documents installer SearchList contract: backups are only deleted after a successful SetValue.
/// Engine C++ mirrors this (RegSetValueExW must succeed before RegDeleteValueW of Original/Initial).
/// </summary>
public sealed class SearchListBackupDeletionPolicyTests
{
    [Fact]
    public void ResolveRestoredSearchList_NonNullMeansWriteThenDeleteBackups()
    {
        // When resolve returns a value, caller must SetValue(SearchList) first;
        // only on success delete Initial/Original (see WindowsDnsRecovery.RestoreSearchListUnderKey).
        var restored = WindowsDnsRecovery.ResolveRestoredSearchList("corp.local", "vpn.backup");
        Assert.Equal("corp.local", restored);
        Assert.NotNull(restored);
    }

    [Fact]
    public void ResolveRestoredSearchList_NullMeansLeaveKeyUntouched()
    {
        Assert.Null(WindowsDnsRecovery.ResolveRestoredSearchList(null, null));
    }
}
