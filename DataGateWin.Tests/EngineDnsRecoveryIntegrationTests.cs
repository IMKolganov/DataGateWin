using System.Diagnostics;
using Microsoft.Win32;
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
        Assert.True(process!.WaitForExit(20000), "engine --recover-dns timed out");
        Assert.Equal(0, process.ExitCode);

        var stderr = process.StandardError.ReadToEnd();
        Assert.Contains("stale NRPT rule", stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SearchList", stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("flushed DNS cache", stderr, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PlantOpenVpnNrptRule_ThenRecoverDns_RemovesRuleWhenElevated()
    {
        var enginePath = TryResolveEngineExePath();
        if (enginePath == null)
            return;

        const string plantName = "OpenVPNDNSRouting-0";
        const string subkeyPath =
            @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

        try
        {
            using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var nrptRoot = baseKey.OpenSubKey(subkeyPath, writable: true))
            {
                if (nrptRoot == null)
                    return; // not elevated / key missing

                using var planted = nrptRoot.CreateSubKey(plantName);
                Assert.NotNull(planted);
                planted!.SetValue("Name", new[] { "." }, RegistryValueKind.MultiString);
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Plant requires admin; skip in non-elevated CI.
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
        Assert.True(process!.WaitForExit(20000), "engine --recover-dns timed out");
        Assert.Equal(0, process.ExitCode);

        using var verifyBase = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var verifyRoot = verifyBase.OpenSubKey(subkeyPath, writable: false);
        Assert.NotNull(verifyRoot);
        Assert.DoesNotContain(plantName, verifyRoot!.GetSubKeyNames());
    }

    static string? TryResolveEngineExePath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "engine.exe"),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "build", "engine", "Release", "engine.exe"),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "build", "engine", "Debug", "engine.exe"),
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
