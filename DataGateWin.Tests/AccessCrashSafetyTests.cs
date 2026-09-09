using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.Access;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class AccessQuotaBarMathTests
{
    [Theory]
    [InlineData(double.NaN, 0)]
    [InlineData(double.PositiveInfinity, 0)]
    [InlineData(double.NegativeInfinity, 0)]
    [InlineData(-1, 0)]
    [InlineData(0, 0)]
    [InlineData(50.4, 50.4)]
    [InlineData(100, 100)]
    [InlineData(100.1, 100)]
    [InlineData(1e20, 100)]
    public void ClampPercent_NeverLeaves_0_100(double input, double expected)
        => Assert.Equal(expected, AccessQuotaBarMath.ClampPercent(input));

    [Fact]
    public void PercentUsed_HandlesOverflowInputs()
    {
        Assert.Equal(0, AccessQuotaBarMath.PercentUsed(0, 100));
        Assert.Equal(0, AccessQuotaBarMath.PercentUsed(10, 0));
        Assert.Equal(0, AccessQuotaBarMath.PercentUsed(-1, 100));
        Assert.Equal(50, AccessQuotaBarMath.PercentUsed(50, 100));
        Assert.Equal(100, AccessQuotaBarMath.PercentUsed(100, 100));
        Assert.Equal(100, AccessQuotaBarMath.PercentUsed(long.MaxValue, 1));
        Assert.Equal(100, AccessQuotaBarMath.PercentUsed(long.MaxValue, long.MaxValue));
        Assert.InRange(AccessQuotaBarMath.PercentUsed(1, long.MaxValue), 0, 100);
    }

    [Fact]
    public void From_NullAndApiError_HidesBar()
    {
        Assert.Equal(AccessQuotaBarKind.ApiError, AccessQuotaBarMath.From(null).Kind);
        var err = AccessQuotaBarMath.From(new UserVpnAccessInfo { QuotaApiError = "boom" });
        Assert.Equal(AccessQuotaBarKind.ApiError, err.Kind);
        Assert.False(err.BarVisible);
        Assert.Equal(0, err.BarValue);
        Assert.False(err.IsOver);
    }

    [Fact]
    public void From_ExternalIdAndUnlimited_HideBar()
    {
        var ext = AccessQuotaBarMath.From(new UserVpnAccessInfo { TrafficUsageNeedsExternalId = true, QuotaLimitBytes = 100 });
        Assert.Equal(AccessQuotaBarKind.NeedsExternalId, ext.Kind);
        Assert.False(ext.BarVisible);

        var unlimited = AccessQuotaBarMath.From(new UserVpnAccessInfo { QuotaLimitBytes = 0 });
        Assert.Equal(AccessQuotaBarKind.Unlimited, unlimited.Kind);
        Assert.False(unlimited.BarVisible);
    }

    [Fact]
    public void From_UnknownUsage_ShowsZeroBar()
    {
        var unknown = AccessQuotaBarMath.From(new UserVpnAccessInfo
        {
            QuotaLimitBytes = 1024,
            TrafficUsedBytesForPeriod = -1,
        });
        Assert.Equal(AccessQuotaBarKind.UsageUnknown, unknown.Kind);
        Assert.True(unknown.BarVisible);
        Assert.Equal(0, unknown.BarValue);
        Assert.False(unknown.IsOver);
    }

    [Fact]
    public void From_NormalAndOverQuota_StayInRange()
    {
        var normal = AccessQuotaBarMath.From(new UserVpnAccessInfo
        {
            QuotaLimitBytes = 1000,
            TrafficUsedBytesForPeriod = 250,
        });
        Assert.Equal(AccessQuotaBarKind.Normal, normal.Kind);
        Assert.True(normal.BarVisible);
        Assert.Equal(25, normal.BarValue);
        Assert.False(normal.IsOver);

        var over = AccessQuotaBarMath.From(new UserVpnAccessInfo
        {
            QuotaLimitBytes = 100,
            TrafficUsedBytesForPeriod = long.MaxValue,
        });
        Assert.Equal(100, over.BarValue);
        Assert.True(over.IsOver);
    }

    [Fact]
    public void From_HostileInputs_NeverThrow()
    {
        var cases = new UserVpnAccessInfo?[]
        {
            null,
            new(),
            new() { QuotaApiError = new string('x', 50_000) },
            new() { QuotaLimitBytes = long.MinValue, TrafficUsedBytesForPeriod = long.MaxValue },
            new() { QuotaLimitBytes = long.MaxValue, TrafficUsedBytesForPeriod = long.MinValue },
            new() { QuotaLimitBytes = -5, TrafficUsedBytesForPeriod = -9 },
            new() { TrafficUsageNeedsExternalId = true, QuotaLimitBytes = long.MaxValue, TrafficUsedBytesForPeriod = long.MaxValue },
        };

        foreach (var c in cases)
        {
            var state = AccessQuotaBarMath.From(c);
            Assert.InRange(state.BarValue, 0, 100);
            Assert.False(double.IsNaN(state.BarValue));
            Assert.False(double.IsInfinity(state.BarValue));
        }
    }
}

public sealed class UiSafeTextTests
{
    [Fact]
    public void Truncate_NullEmptyAndShort()
    {
        Assert.Equal("", UiSafeText.Truncate(null, 10));
        Assert.Equal("", UiSafeText.Truncate("", 10));
        Assert.Equal("ok", UiSafeText.Truncate("ok", 10));
        Assert.Equal("", UiSafeText.Truncate("abc", 0));
    }

    [Fact]
    public void Truncate_HugeEngineDump_FitsBudget()
    {
        var dump = new string('A', 80_000);
        var status = UiSafeText.ForStatus(dump);
        Assert.Equal(UiSafeText.StatusMaxChars, status.Length);
        Assert.EndsWith("…", status);

        var err = UiSafeText.ForError(dump);
        Assert.Equal(UiSafeText.ErrorMaxChars, err.Length);
        Assert.EndsWith("…", err);
    }
}

public sealed class AccessServerListCrashSafetyTests
{
    [Fact]
    public void FilterWssEnabled_NullEmptyAndNullRows_DoNotThrow()
    {
        Assert.Empty(WssServerSelector.FilterWssEnabled(null));
        Assert.Empty(WssServerSelector.FilterWssEnabled([]));

        var mixed = new List<VpnServerWithStatusV2Dto>
        {
            null!,
            MakeRow(1, "🇫🇮 Helsinki", VpnServerType.OpenVpn, wss: true),
            MakeRow(2, "Norway xray", VpnServerType.Xray, wss: false),
        };

        var filtered = WssServerSelector.FilterWssEnabled(mixed);
        Assert.Equal(2, filtered.Count);
        Assert.All(filtered, r => Assert.NotNull(r.VpnServerResponses?.VpnServer));
    }

    [Fact]
    public void FilterEligible_NullNestedServer_DoesNotThrow()
    {
        var eligible = WssServerSelector.FilterEligible(
        [
            null!,
            MakeRow(1, "A", VpnServerType.OpenVpn, wss: true, accessible: true),
        ]);
        Assert.Single(eligible);
    }

    [Fact]
    public void FilterWssEnabled_ThousandsOfRows_DoesNotThrow()
    {
        var rows = new List<VpnServerWithStatusV2Dto>(10_001) { null! };
        for (var i = 0; i < 10_000; i++)
            rows.Add(MakeRow(i + 1, $"FI Server {i}", VpnServerType.OpenVpn, wss: i % 2 == 0));

        var filtered = WssServerSelector.FilterWssEnabled(rows);
        Assert.Equal(10_000, filtered.Count);
    }

    [Fact]
    public void FilterWssEnabled_ParallelHostileLists_DoNotThrow()
    {
        var row = MakeRow(7, "🇨🇾 Cyprus", VpnServerType.Xray, wss: false);
        Parallel.For(0, 32, _ =>
        {
            var list = new VpnServerWithStatusV2Dto?[] { null, row };
            var filtered = WssServerSelector.FilterWssEnabled(list!);
            Assert.Single(filtered);
        });
    }

    [Fact]
    public void ServerNameFlag_HugeAndGarbageNames_DoNotThrow()
    {
        var huge = new string('x', 50_000);
        Assert.False(ServerNameFlag.TrySplit(huge, out _, out _));
        Assert.False(ServerNameFlag.TryGetIso2(huge, out _));
        _ = ServerNameFlag.WithFlagPrefix(huge);
        _ = ServerNameFlag.WithFlagPrefix(null);
        Assert.True(ServerNameFlag.TrySplit("🇫🇮 " + huge, out var flag, out _));
        Assert.Equal("🇫🇮", flag);
    }

    private static VpnServerWithStatusV2Dto MakeRow(
        int id,
        string name,
        VpnServerType type,
        bool wss,
        bool accessible = true)
    {
        var responsesType = typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.PropertyType;
        var responses = Activator.CreateInstance(responsesType)!;
        var server = Activator.CreateInstance(typeof(VpnServerV2Dto))!;
        typeof(VpnServerV2Dto).GetProperty("ServerType")!.SetValue(server, type);
        typeof(VpnServerV2Dto).GetProperty("IsEnableWss")!.SetValue(server, wss);
        typeof(VpnServerV2Dto).GetProperty("Id")!.SetValue(server, id);
        typeof(VpnServerV2Dto).GetProperty("ServerName")!.SetValue(server, name);
        typeof(VpnServerV2Dto).GetProperty("IsAccessibleForUserQuotaPlan")!.SetValue(server, accessible);
        responsesType.GetProperty("VpnServer")!.SetValue(responses, server);
        var row = Activator.CreateInstance(typeof(VpnServerWithStatusV2Dto))!;
        typeof(VpnServerWithStatusV2Dto).GetProperty("VpnServerResponses")!.SetValue(row, responses);
        return (VpnServerWithStatusV2Dto)row;
    }
}

public sealed class WinUiAccessCrashContractTests
{
    [Fact]
    public void AccessPage_MarshalsVmToUiDispatcher()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "AccessPage.xaml.cs")));
        Assert.Contains("UiDispatch.Run", cs, StringComparison.Ordinal);
        Assert.Contains("AccessQuotaBarMath.ClampPercent", cs, StringComparison.Ordinal);
        Assert.Contains("UiSafeText.ForError", cs, StringComparison.Ordinal);
        Assert.DoesNotContain("ConfigureAwait(true)", cs, StringComparison.Ordinal);
    }

    [Fact]
    public void AccessViewModel_DoesNotResumeOnCapturedContext()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "ViewModels", "AccessViewModel.cs")));
        Assert.Contains("ConfigureAwait(false)", cs, StringComparison.Ordinal);
        Assert.Contains("AccessQuotaBarMath.From", cs, StringComparison.Ordinal);
        Assert.DoesNotContain("ConfigureAwait(true)", cs, StringComparison.Ordinal);
    }

    [Fact]
    public void App_ConfiguresCrashReporting_WithPublicApiUrl_BeforeLaunch()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "App.xaml.cs")));
        Assert.Contains("CrashReporter.Configure", cs, StringComparison.Ordinal);
        Assert.Contains("DataGatePublicDefaults.ApiBaseUrl", cs, StringComparison.Ordinal);
        Assert.Contains("HandleDispatcherUnhandled", cs, StringComparison.Ordinal);
    }

    [Fact]
    public void App_DoesNotInstallCustomSynchronizationContext()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "App.xaml.cs")));
        Assert.DoesNotContain("SetSynchronizationContext", cs, StringComparison.Ordinal);
        Assert.DoesNotContain("DispatcherQueueSyncContext", cs, StringComparison.Ordinal);
    }

    [Fact]
    public void Unpackaged_images_load_from_stream_not_file_uri()
    {
        var flag = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Services", "Ui", "ServerNameUi.cs")));
        var avatar = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Services", "Ui", "UserAvatarCache.cs")));
        var helper = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Services", "Ui", "UiFileBitmap.cs")));
        Assert.DoesNotContain("UriSource =", flag, StringComparison.Ordinal);
        Assert.DoesNotContain("UriSource =", avatar, StringComparison.Ordinal);
        Assert.Contains("SetSource", helper, StringComparison.Ordinal);
        Assert.Contains("0x80073B01", helper, StringComparison.Ordinal);
        var assign = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Services", "Ui", "UiSafeImage.cs")));
        Assert.Contains("TryAssign", assign, StringComparison.Ordinal);
        var home = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Pages", "Home", "HomePage.xaml.cs")));
        Assert.Contains("Home_Error_UiImage", home, StringComparison.Ordinal);
        Assert.Contains("NetworkServerFlag_OnImageFailed", home, StringComparison.Ordinal);
    }

    [Fact]
    public void UiDispatch_SkipsWorkWhenQueueMissing()
    {
        var cs = File.ReadAllText(FindRepoFile(Path.Combine("DataGateWin.WinUI", "Services", "Ui", "UiDispatch.cs")));
        Assert.Contains("No DispatcherQueue", cs, StringComparison.Ordinal);
        Assert.Contains("skipped UI mutate", cs, StringComparison.Ordinal);
    }

    private static string FindRepoFile(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, relative);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }

        throw new FileNotFoundException(relative);
    }
}
