using System.Net.NetworkInformation;

namespace DataGateWin.Services.Traffic;

/// <summary>Maps VPN-adapter read failures to UI loc keys (never show raw exception text).</summary>
public static class LiveTrafficError
{
    public const string KeyGeneric = "Home_Traffic_Error";
    public const string KeyAccess = "Home_Traffic_Error_Access";
    public const string KeyUnavailable = "Home_Traffic_Error_Unavailable";

    public static string LocKey(Exception? ex)
    {
        var sawUnavailable = false;
        for (var e = ex; e is not null; e = e.InnerException)
        {
            if (e is UnauthorizedAccessException)
                return KeyAccess;

            if (e is NetworkInformationException
                or InvalidOperationException
                or ObjectDisposedException
                or IOException
                or TimeoutException)
            {
                sawUnavailable = true;
                continue;
            }

            var name = e.GetType().Name;
            if (name.Contains("COMException", StringComparison.Ordinal)
                || name.Contains("Win32Exception", StringComparison.Ordinal)
                || name.Contains("RpcException", StringComparison.Ordinal))
                sawUnavailable = true;
        }

        return sawUnavailable ? KeyUnavailable : KeyGeneric;
    }
}
