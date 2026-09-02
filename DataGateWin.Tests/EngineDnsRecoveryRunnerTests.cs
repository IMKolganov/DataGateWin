using DataGateWin.Services.Ipc;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineDnsRecoveryRunnerTests
{
    [Fact]
    public void ForcedKillThenRecover_SequenceIsKillThenRecoverDns()
    {
        // Documents UI policy: after forced engine kill, always run recover-dns once.
        Assert.Equal(
            ["kill_engine", "recover_dns"],
            EngineDnsShutdownSequence.ForcedKillRecoverySteps);
    }

    [Fact]
    public void TryRecover_MissingEngine_DoesNotThrow()
    {
        var logs = new List<string>();
        EngineDnsRecoveryRunner.TryRecover(
            Path.Combine(Path.GetTempPath(), "missing-datagate-engine.exe"),
            logs.Add);

        Assert.Contains(logs, l => l.Contains("not found", StringComparison.OrdinalIgnoreCase));
    }
}
