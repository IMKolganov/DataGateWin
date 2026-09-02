using System.Diagnostics;
using Microsoft.Win32;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineDnsRecoveryIntegrationTests
{
    [Fact]
    public void EngineRecoverDnsFlag_CompletesWithDocumentedExitCodeWhenBinaryIsPresent()
    {
        var enginePath = TryResolveEngineExePath();
        if (enginePath == null)
            return;

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

        var stderr = process.StandardError.ReadToEnd();

        // 0 = cleaned, 3 = refused (session active), 5 = ACCESS_DENIED without admin.
        Assert.Contains(process.ExitCode, (int[])[0, 3, 5]);

        if (process.ExitCode == 0)
        {
            Assert.Contains("stale NRPT rule", stderr, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("SearchList", stderr, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("flushed DNS cache", stderr, StringComparison.OrdinalIgnoreCase);
        }
        else if (process.ExitCode == 5)
        {
            Assert.Contains("ACCESS_DENIED", stderr, StringComparison.OrdinalIgnoreCase);
        }
        else if (process.ExitCode == 3)
        {
            Assert.Contains("SKIPPED", stderr, StringComparison.OrdinalIgnoreCase);
        }
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

        // Pid 0 is never "alive", so refuse-if-active should not block; admin may still be required.
        if (process.ExitCode == 5)
            return;

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
