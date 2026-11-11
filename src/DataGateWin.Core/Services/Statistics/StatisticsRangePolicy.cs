namespace DataGateWin.Services.Statistics;

public static class StatisticsRangePolicy
{
    public static (DateTimeOffset From, DateTimeOffset To) Resolve(string preset, DateTimeOffset now)
    {
        var from = preset switch
        {
            "24h" => now.AddHours(-24),
            "7d" => now.AddDays(-7),
            "30d" => now.AddDays(-30),
            "90d" => now.AddDays(-90),
            "2m" => now.AddMonths(-2),
            "3m" => now.AddMonths(-3),
            "6m" => now.AddMonths(-6),
            "1y" => now.AddYears(-1),
            "2y" => now.AddYears(-2),
            _ => throw new ArgumentOutOfRangeException(nameof(preset)),
        };
        return (from.ToUniversalTime(), now.ToUniversalTime());
    }
}
