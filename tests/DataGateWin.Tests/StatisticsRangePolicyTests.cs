using DataGateWin.Services.Statistics;
using Xunit;

namespace DataGateWin.Tests;

public sealed class StatisticsRangePolicyTests
{
    [Theory]
    [InlineData("7d", 7)]
    [InlineData("30d", 30)]
    [InlineData("90d", 90)]
    public void DayPresets_PreserveTimeOfDayAndEndAtNow(string preset, int days)
    {
        var now = new DateTimeOffset(2026, 11, 11, 16, 37, 12, TimeSpan.FromHours(2));
        var range = StatisticsRangePolicy.Resolve(preset, now);
        Assert.Equal(now.ToUniversalTime(), range.To);
        Assert.Equal(TimeSpan.FromDays(days), range.To - range.From);
        Assert.Equal(TimeSpan.Zero, range.From.Offset);
    }

    [Theory]
    [InlineData("2m", 2)]
    [InlineData("3m", 3)]
    [InlineData("6m", 6)]
    [InlineData("1y", 12)]
    [InlineData("2y", 24)]
    public void CalendarPresets_MatchCalendarMonths_NotFixedThirtyDayMultiples(string preset, int months)
    {
        var now = new DateTimeOffset(2024, 2, 29, 14, 15, 0, TimeSpan.FromHours(-5));
        var range = StatisticsRangePolicy.Resolve(preset, now);
        Assert.Equal(now.AddMonths(-months).ToUniversalTime(), range.From);
        Assert.Equal(now.ToUniversalTime(), range.To);
    }

    [Theory]
    [InlineData(14)]
    [InlineData(-12)]
    public void Last24Hours_WorksAcrossUtcDateBoundary(int utcOffsetHours)
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 5, 0, TimeSpan.FromHours(utcOffsetHours));
        var range = StatisticsRangePolicy.Resolve("24h", now);
        Assert.Equal(now.UtcDateTime.AddHours(-24), range.From.UtcDateTime);
    }

    [Theory]
    [InlineData("")]
    [InlineData("24")]
    [InlineData("unknown")]
    public void UnknownPreset_DoesNotSilentlyRequestAnotherPeriod(string preset)
        => Assert.Throws<ArgumentOutOfRangeException>(() => StatisticsRangePolicy.Resolve(preset, DateTimeOffset.UtcNow));

    [Fact]
    public void Last24Hours_is_exactly_24_hours_ending_now()
    {
        var now = new DateTimeOffset(2026, 11, 11, 16, 37, 12, TimeSpan.FromHours(2));
        var range = StatisticsRangePolicy.Resolve("24h", now);
        Assert.Equal(TimeSpan.FromHours(24), range.To - range.From);
        Assert.Equal(now.ToUniversalTime(), range.To);
        Assert.Equal(14, range.From.Hour);
        Assert.Equal(37, range.From.Minute);
        Assert.Equal(TimeSpan.Zero, range.From.Offset);
    }

    [Fact]
    public void Month_preset_uses_calendar_months_including_short_months()
    {
        var now = new DateTimeOffset(2026, 3, 31, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2025, 9, 30, 12, 0, 0, TimeSpan.Zero),
            StatisticsRangePolicy.Resolve("6m", now).From);
    }
}
