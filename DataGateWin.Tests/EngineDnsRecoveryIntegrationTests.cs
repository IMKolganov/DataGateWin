using System.Diagnostics;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineDnsRecoveryIntegrationTests
{
    [Fact]
    public void EngineRecoverDnsFlag_ExitsZeroWhenBinaryIsPresent()
    {
        var enginePath = TryResolveEngineExePath();
        if (enginePath == null)
        {
            // Native engine is optional in CI/dev environments without a C++ build.
            return;
        }

        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = enginePath,
            Arguments = "--recover-dns",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });

        Assert.NotNull(process);
        Assert.True(process!.WaitForExit(15000), "engine --recover-dns timed out");
        Assert.Equal(0, process.ExitCode);

        var stderr = process.StandardError.ReadToEnd();
        Assert.Contains("stale NRPT rule", stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("flushed DNS cache", stderr, StringComparison.OrdinalIgnoreCase);
    }

    static string? TryResolveEngineExePath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "engine.exe"),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "engine", "build", "Release", "engine.exe"),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "engine", "build", "Debug", "engine.exe"),
        };

        foreach (var candidate in candidates)
        {
            var fullPath = Path.GetFullPath(candidate);
            if (File.Exists(fullPath))
                return fullPath;
        }

        return null;
    }
}
