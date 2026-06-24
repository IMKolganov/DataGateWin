using DataGateWin.Services.Ipc;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineSessionServiceShutdownTests
{
    [Fact]
    public async Task TryStopActiveSessionSafeAsync_WithNoActiveInstance_CompletesWithoutError()
    {
        await EngineSessionService.TryStopActiveSessionSafeAsync(TimeSpan.FromSeconds(1));
    }
}
