using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class StartupDnsRecoveryTests
{
    [Fact]
    public void HealthyMachineDoesNotRunRecovery()
    {
        var result = StartupDnsRecovery.Run(_ => { }, () => false, () => false,
            () => throw new InvalidOperationException("Must not mutate a healthy machine"));
        Assert.Equal(StartupDnsRecoveryResult.NoChanges, result);
    }

    [Fact]
    public void ActiveSessionDoesNotEvenProbeArtifacts()
    {
        var result = StartupDnsRecovery.Run(_ => { }, () => true,
            () => throw new InvalidOperationException("Must not probe"),
            () => throw new InvalidOperationException("Must not recover"));
        Assert.Equal(StartupDnsRecoveryResult.ActiveSession, result);
    }

    [Fact]
    public void RecoversOfflineAndVerifiesArtifactsAreGone()
    {
        var artifacts = true;
        var calls = 0;
        var result = StartupDnsRecovery.Run(_ => { }, () => false, () => artifacts,
            () => { calls++; artifacts = false; });
        Assert.Equal(StartupDnsRecoveryResult.Recovered, result);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void RemainingArtifactsAreReportedAsFailure()
    {
        Assert.Equal(StartupDnsRecoveryResult.Failed,
            StartupDnsRecovery.Run(_ => { }, () => false, () => true, () => { }));
    }

    [Fact]
    public void SessionStartingDuringProbePreventsMutation()
    {
        var probes = 0;
        Assert.Equal(StartupDnsRecoveryResult.ActiveSession,
            StartupDnsRecovery.Run(_ => { }, () => ++probes > 1, () => true,
                () => throw new InvalidOperationException("Must not recover")));
    }

    [Fact]
    public void UncertainOwnershipFailsWithoutMutation()
    {
        Assert.Equal(StartupDnsRecoveryResult.Failed,
            StartupDnsRecovery.Run(_ => { }, () => throw new UnauthorizedAccessException(), () => true,
                () => throw new InvalidOperationException("Must not recover")));
    }
}
