namespace DataGateWin.Services.Access;

public enum AccessQuotaBarKind
{
    ApiError,
    NeedsExternalId,
    Unlimited,
    UsageUnknown,
    Normal,
}

/// <summary>
/// WinUI ProgressBar FailFasts on NaN / out-of-range Value. All Access quota
/// numbers must go through this before touching XAML.
/// </summary>
public static class AccessQuotaBarMath
{
    public const double MinPercent = 0;
    public const double MaxPercent = 100;

    public static double ClampPercent(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
            return MinPercent;
        return Math.Clamp(value, MinPercent, MaxPercent);
    }

    public static double PercentUsed(long used, long limit)
    {
        if (limit <= 0 || used <= 0)
            return MinPercent;
        return ClampPercent(100.0 * used / (double)limit);
    }

    public static AccessQuotaBarState From(UserVpnAccessInfo? info)
    {
        if (info is null || !string.IsNullOrEmpty(info.QuotaApiError))
            return new AccessQuotaBarState(AccessQuotaBarKind.ApiError, false, 0, false);
        if (info.TrafficUsageNeedsExternalId)
            return new AccessQuotaBarState(AccessQuotaBarKind.NeedsExternalId, false, 0, false);
        if (info.QuotaLimitBytes <= 0)
            return new AccessQuotaBarState(AccessQuotaBarKind.Unlimited, false, 0, false);
        if (info.TrafficUsedBytesForPeriod < 0)
            return new AccessQuotaBarState(AccessQuotaBarKind.UsageUnknown, true, 0, false);

        var used = info.TrafficUsedBytesForPeriod;
        var lim = info.QuotaLimitBytes;
        return new AccessQuotaBarState(
            AccessQuotaBarKind.Normal,
            BarVisible: true,
            BarValue: PercentUsed(used, lim),
            IsOver: used > lim);
    }
}

public readonly record struct AccessQuotaBarState(
    AccessQuotaBarKind Kind,
    bool BarVisible,
    double BarValue,
    bool IsOver);
