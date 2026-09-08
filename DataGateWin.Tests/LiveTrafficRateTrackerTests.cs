using System.Globalization;
using DataGateWin.Services.Traffic;
using Xunit;

namespace DataGateWin.Tests;

public sealed class LiveTrafficRateTrackerTests
{
    [Fact]
    public void Pick_WhenBothUpAndIdle_FallsBackToDataGate()
    {
        var picked = VpnAdapterTrafficPicker.Pick(
        [
            new VpnAdapterCounters("xray0", 10, 20, IsUp: true),
            new VpnAdapterCounters("DataGate", 1, 2, IsUp: true),
        ]);

        Assert.NotNull(picked);
        Assert.Equal("DataGate", picked.Value.Name);
    }

    [Fact]
    public void Pick_WhenBothUp_PrefersAdapterWhoseCountersGrew()
    {
        var previous = new Dictionary<string, VpnAdapterCounters>(StringComparer.OrdinalIgnoreCase)
        {
            ["DataGate"] = new VpnAdapterCounters("DataGate", 5000, 5000, true),
            ["xray0"] = new VpnAdapterCounters("xray0", 10, 20, true),
        };

        var picked = VpnAdapterTrafficPicker.Pick(
        [
            new VpnAdapterCounters("DataGate", 5000, 5000, IsUp: true),
            new VpnAdapterCounters("xray0", 410, 220, IsUp: true),
        ],
            previous);

        Assert.NotNull(picked);
        Assert.Equal("xray0", picked.Value.Name);
    }

    [Fact]
    public void Pick_WhenBothUp_PrefersNewlyAppearedAdapter()
    {
        var previous = new Dictionary<string, VpnAdapterCounters>(StringComparer.OrdinalIgnoreCase)
        {
            ["DataGate"] = new VpnAdapterCounters("DataGate", 5000, 5000, true),
        };

        var picked = VpnAdapterTrafficPicker.Pick(
        [
            new VpnAdapterCounters("DataGate", 5000, 5000, IsUp: true),
            new VpnAdapterCounters("xray0", 0, 0, IsUp: true),
        ],
            previous);

        Assert.NotNull(picked);
        Assert.Equal("xray0", picked.Value.Name);
    }

    [Fact]
    public void Pick_KeepsLastPickedWhenNeitherAdapterMoved()
    {
        var previous = new Dictionary<string, VpnAdapterCounters>(StringComparer.OrdinalIgnoreCase)
        {
            ["DataGate"] = new VpnAdapterCounters("DataGate", 100, 100, true),
            ["xray0"] = new VpnAdapterCounters("xray0", 50, 50, true),
        };

        var picked = VpnAdapterTrafficPicker.Pick(
        [
            new VpnAdapterCounters("DataGate", 100, 100, IsUp: true),
            new VpnAdapterCounters("xray0", 50, 50, IsUp: true),
        ],
            previous,
            lastPickedName: "xray0");

        Assert.NotNull(picked);
        Assert.Equal("xray0", picked.Value.Name);
    }

    [Fact]
    public void Pick_UsesXrayWhenDataGateIsDown()
    {
        var picked = VpnAdapterTrafficPicker.Pick(
        [
            new VpnAdapterCounters("DataGate", 1, 2, IsUp: false),
            new VpnAdapterCounters("xray0", 9, 8, IsUp: true),
        ]);

        Assert.NotNull(picked);
        Assert.Equal("xray0", picked.Value.Name);
    }

    [Fact]
    public void Pick_IgnoresUnrelatedAdapters()
    {
        var picked = VpnAdapterTrafficPicker.Pick(
        [
            new VpnAdapterCounters("Ethernet", 100, 200, IsUp: true),
            new VpnAdapterCounters("Wi-Fi", 3, 4, IsUp: true),
        ]);

        Assert.Null(picked);
    }

    [Fact]
    public void FirstSample_IsZeroRateBaseline()
    {
        var t = new LiveTrafficRateTracker();
        var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        var tick = t.Push(new VpnAdapterCounters("DataGate", 1000, 2000, true), t0);

        Assert.Equal(0, tick.InBytesPerSec);
        Assert.Equal(0, tick.OutBytesPerSec);
        Assert.Equal(0, tick.SessionInBytes);
        Assert.Equal("DataGate", tick.AdapterName);
    }

    [Fact]
    public void SecondSample_ComputesBytesPerSecond()
    {
        var t = new LiveTrafficRateTracker();
        var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        t.Push(new VpnAdapterCounters("DataGate", 1000, 2000, true), t0);

        var tick = t.Push(new VpnAdapterCounters("DataGate", 3000, 2500, true), t0.AddSeconds(2));

        Assert.Equal(1000, tick.InBytesPerSec);
        Assert.Equal(250, tick.OutBytesPerSec);
        Assert.Equal(2000, tick.SessionInBytes);
        Assert.Equal(500, tick.SessionOutBytes);
    }

    [Fact]
    public void CounterReset_StartsNewBaseline()
    {
        var t = new LiveTrafficRateTracker();
        var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        t.Push(new VpnAdapterCounters("DataGate", 8000, 9000, true), t0);

        var tick = t.Push(new VpnAdapterCounters("DataGate", 10, 20, true), t0.AddSeconds(1));

        Assert.Equal(0, tick.InBytesPerSec);
        Assert.Equal(0, tick.SessionInBytes);
    }

    [Fact]
    public void LongGap_DoesNotSpike()
    {
        var t = new LiveTrafficRateTracker();
        var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        t.Push(new VpnAdapterCounters("DataGate", 100, 100, true), t0);

        var tick = t.Push(
            new VpnAdapterCounters("DataGate", 1_000_000, 1_000_000, true),
            t0.AddSeconds(30));

        Assert.Equal(0, tick.InBytesPerSec);
        Assert.Equal(0, tick.OutBytesPerSec);
    }

    [Fact]
    public void MissingAdapter_ClearsRates()
    {
        var t = new LiveTrafficRateTracker();
        var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        t.Push(new VpnAdapterCounters("DataGate", 100, 100, true), t0);
        t.Push(new VpnAdapterCounters("DataGate", 200, 150, true), t0.AddSeconds(1));

        var tick = t.Push(null, t0.AddSeconds(2));
        Assert.Equal(0, tick.InBytesPerSec);
        Assert.Null(tick.AdapterName);
    }

    [Theory]
    [InlineData(0, "0 B/s")]
    [InlineData(512, "512 B/s")]
    [InlineData(1536, "1.5 KB/s")]
    public void FormatBytesPerSec_UsesBinaryUnits(double bytes, string expected)
        => Assert.Equal(expected, LiveTrafficFormatting.FormatBytesPerSec(bytes, CultureInfo.InvariantCulture));

    [Fact]
    public void IsKnownVpnAdapter_MatchesEngineNames()
    {
        Assert.True(VpnAdapterTrafficPicker.IsKnownVpnAdapter("DataGate"));
        Assert.True(VpnAdapterTrafficPicker.IsKnownVpnAdapter("xray0"));
        Assert.False(VpnAdapterTrafficPicker.IsKnownVpnAdapter("Ethernet"));
    }

    [Fact]
    public void LocKey_AccessDenied_UsesAccessMessage()
        => Assert.Equal(
            LiveTrafficError.KeyAccess,
            LiveTrafficError.LocKey(new UnauthorizedAccessException("Access is denied")));

    [Fact]
    public void LocKey_NetworkInfo_UsesUnavailableMessage()
        => Assert.Equal(
            LiveTrafficError.KeyUnavailable,
            LiveTrafficError.LocKey(new System.Net.NetworkInformation.NetworkInformationException()));

    [Fact]
    public void LocKey_Unknown_UsesGenericMessage()
        => Assert.Equal(LiveTrafficError.KeyGeneric, LiveTrafficError.LocKey(new InvalidCastException("boom")));

    [Fact]
    public void LocKey_InnerException_IsUnwrapped()
        => Assert.Equal(
            LiveTrafficError.KeyAccess,
            LiveTrafficError.LocKey(new InvalidOperationException("wrap", new UnauthorizedAccessException())));
}
