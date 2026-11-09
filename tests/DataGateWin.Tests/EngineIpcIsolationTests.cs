using System.IO.Pipes;
using System.Text;
using DataGateWin.Ipc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

public sealed class EngineIpcIsolationTests
{
    [Fact]
    public async Task ExitedProcess_DoesNotBlockNextStartWithAlreadyStarted()
    {
        // cmd rejects the engine arguments and exits: simulate a process that dies at startup.
        using var client = new EngineIpcClient(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            Guid.NewGuid().ToString("N"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await Assert.ThrowsAnyAsync<Exception>(() => client.StartOrAttachAsync(timeout.Token));
        client.ResetConnection();
        var error = await Assert.ThrowsAnyAsync<Exception>(() => client.StartOrAttachAsync(timeout.Token));
        Assert.DoesNotContain("Engine already started", error.Message);
    }

    [Fact]
    public async Task EngineReadsButNeverReplies_RequestCanBeCanceled()
    {
        using var pipes = new FakeEngine();
        await pipes.ConnectAsync();
        using var cancellation = new CancellationTokenSource();
        var request = pipes.Client.SendCommandAsync("GetStatus", "{}", cancellation.Token);
        using var reader = new StreamReader(pipes.Control, Encoding.UTF8, leaveOpen: true);
        Assert.NotNull(await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(pipes.Client.IsConnected);
    }

    [Fact]
    public async Task EngineStopsReading_CancellationInterruptsBlockedWrite()
    {
        using var pipes = new FakeEngine();
        await pipes.ConnectAsync();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        var payload = JsonConvert.SerializeObject(new { data = new string('x', 2_000_000) });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            pipes.Client.SendCommandAsync("StartSession", payload, cancellation.Token).WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.False(pipes.Client.IsConnected);
    }

    [Fact]
    public async Task EngineDisconnects_PendingCommandFailsWithoutWaitingForTimeout()
    {
        using var pipes = new FakeEngine();
        await pipes.ConnectAsync();
        var request = pipes.Client.SendCommandAsync("GetStatus", "{}", CancellationToken.None);
        using var reader = new StreamReader(pipes.Control, Encoding.UTF8, leaveOpen: true);
        Assert.NotNull(await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)));
        pipes.Control.Dispose();
        await Assert.ThrowsAsync<IOException>(() => request.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ConcurrentCommands_AreWrittenAsCompleteJsonFrames()
    {
        using var pipes = new FakeEngine();
        await pipes.ConnectAsync();
        var server = Task.Run(async () =>
        {
            using var reader = new StreamReader(pipes.Control, Encoding.UTF8, leaveOpen: true);
            using var writer = new StreamWriter(pipes.Control, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            for (var i = 0; i < 8; i++)
            {
                var command = JObject.Parse((await reader.ReadLineAsync())!);
                Assert.Equal(50_000, command["payload"]!["data"]!.Value<string>()!.Length);
                await writer.WriteLineAsync(JsonConvert.SerializeObject(new { id = command.Value<string>("id"), ok = true, payload = new { } }));
            }
        });
        var payload = JsonConvert.SerializeObject(new { data = new string('x', 50_000) });
        var requests = Enumerable.Range(0, 8).Select(_ => pipes.Client.SendCommandAsync("Test", payload, CancellationToken.None)).ToArray();
        var replies = await Task.WhenAll(requests).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.All(replies, reply => Assert.True(reply.Ok));
        await server.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private sealed class FakeEngine : IDisposable
    {
        private readonly string _session = Guid.NewGuid().ToString("N");
        public NamedPipeServerStream Control { get; }
        private NamedPipeServerStream Events { get; }
        public EngineIpcClient Client { get; }
        public FakeEngine()
        {
            Control = new NamedPipeServerStream($"datagate.engine.{_session}.control", PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 512, 512);
            Events = new NamedPipeServerStream($"datagate.engine.{_session}.events", PipeDirection.Out, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            Client = new EngineIpcClient("unused.exe", _session);
        }
        public async Task ConnectAsync()
        {
            var ready = Task.WhenAll(Control.WaitForConnectionAsync(), Events.WaitForConnectionAsync());
            Assert.True(await Client.TryConnectExistingAsync(3000, CancellationToken.None));
            await ready.WaitAsync(TimeSpan.FromSeconds(5));
        }
        public void Dispose() { Client.Dispose(); Control.Dispose(); Events.Dispose(); }
    }
}
