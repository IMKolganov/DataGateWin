using System.Net;
using System.Net.Sockets;
using System.Text;
using DataGateWin.CrashReporting;
using Xunit;

namespace DataGateWin.Tests;

[CollectionDefinition(nameof(CrashReporterStaticState), DisableParallelization = true)]
public sealed class CrashReporterStaticState
{
}

[Collection(nameof(CrashReporterStaticState))]
public sealed class CrashReporterDeliveryTests
{
    const string EngineProcessName = "com.imkolganov.datagate.win.engine";
    const string InstallerProcessName = "com.imkolganov.datagate.win.installer";

    [Fact]
    public async Task ReportNonFatal_PostsThrownExceptionToConfiguredServer()
    {
        var queueDir = CreateTempQueueDirectory();
        await using var server = new LoopbackCrashServer();

        try
        {
            CrashReporter.UseQueueForTests(new CrashReportQueue(queueDir));
            CrashReporter.Configure(new CrashReportingConfiguration
            {
                Enabled = true,
                BaseUrl = server.BaseUrl,
                ProcessName = "test.ui",
                CrashToken = "test-token",
            });

            try
            {
                throw new InvalidOperationException("nonfatal probe exception");
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "NonFatalProbe");
            }

            var request = await server.WaitForRequestAsync();

            Assert.Equal("POST", request.Method);
            Assert.Equal("/api/v1/windows/crash-ingest", request.Path);
            Assert.Equal("test.ui", request.Headers["X-Crash-Process"]);
            Assert.Equal("test-token", request.Headers["X-Crash-Token"]);
            Assert.StartsWith("win_crash_", request.Headers["X-Crash-Filename"], StringComparison.Ordinal);
            Assert.Contains("kind=nonfatal", request.Body, StringComparison.Ordinal);
            Assert.Contains("tag=NonFatalProbe", request.Body, StringComparison.Ordinal);
            Assert.Contains("nonfatal probe exception", request.Body, StringComparison.Ordinal);
        }
        finally
        {
            CrashReporter.ResetForTests();
            DeleteDirectoryBestEffort(queueDir);
        }
    }

    [Fact]
    public async Task ReportNonFatalAsync_PostsInstallerExceptionWithInstallerProcessHeader()
    {
        var queueDir = CreateTempQueueDirectory();
        await using var server = new LoopbackCrashServer();

        try
        {
            CrashReporter.UseQueueForTests(new CrashReportQueue(queueDir));
            CrashReporter.Configure(new CrashReportingConfiguration
            {
                Enabled = true,
                BaseUrl = server.BaseUrl,
                ProcessName = InstallerProcessName,
            });

            await CrashReporter.ReportNonFatalAsync(
                new InvalidOperationException("installer probe exception"),
                "Installer.Probe",
                CancellationToken.None);

            var request = await server.WaitForRequestAsync();

            Assert.Equal("POST", request.Method);
            Assert.Equal("/api/v1/windows/crash-ingest", request.Path);
            Assert.Equal(InstallerProcessName, request.Headers["X-Crash-Process"]);
            Assert.StartsWith("win_crash_", request.Headers["X-Crash-Filename"], StringComparison.Ordinal);
            Assert.Contains("kind=nonfatal", request.Body, StringComparison.Ordinal);
            Assert.Contains("tag=Installer.Probe", request.Body, StringComparison.Ordinal);
            Assert.Contains("installer probe exception", request.Body, StringComparison.Ordinal);
        }
        finally
        {
            CrashReporter.ResetForTests();
            DeleteDirectoryBestEffort(queueDir);
        }
    }

    [Fact]
    public async Task HandleDispatcherUnhandled_QueuesAndPostsFatalException()
    {
        var queueDir = CreateTempQueueDirectory();
        var queue = new CrashReportQueue(queueDir);
        await using var server = new LoopbackCrashServer();

        try
        {
            CrashReporter.UseQueueForTests(queue);
            CrashReporter.Configure(new CrashReportingConfiguration
            {
                Enabled = true,
                BaseUrl = server.BaseUrl,
                ProcessName = "test.ui",
            });

            CrashReporter.HandleDispatcherUnhandled(new ApplicationException("fatal dispatcher probe"));

            var request = await server.WaitForRequestAsync();
            await WaitForQueueToDrainAsync(queue);

            Assert.Equal("POST", request.Method);
            Assert.Equal("/api/v1/windows/crash-ingest", request.Path);
            Assert.Equal("test.ui", request.Headers["X-Crash-Process"]);
            Assert.StartsWith("win_crash_", request.Headers["X-Crash-Filename"], StringComparison.Ordinal);
            Assert.Contains("kind=fatal", request.Body, StringComparison.Ordinal);
            Assert.Contains("thread=UI Thread", request.Body, StringComparison.Ordinal);
            Assert.Contains("fatal dispatcher probe", request.Body, StringComparison.Ordinal);
            Assert.Empty(queue.ReadPending());
        }
        finally
        {
            CrashReporter.ResetForTests();
            DeleteDirectoryBestEffort(queueDir);
        }
    }

    [Fact]
    public async Task FlushPendingAsync_PostsQueuedEngineCrashWithEngineProcessHeader()
    {
        var queueDir = CreateTempQueueDirectory();
        var queue = new CrashReportQueue(queueDir);
        await using var server = new LoopbackCrashServer();

        try
        {
            queue.Enqueue(
                "win_engine_crash_probe.txt",
                "timestamp_utc=2026-05-11T00:00:00.000Z\nprocess=com.imkolganov.datagate.win.engine\nkind=fatal\nmessage=engine probe\n\nengine probe",
                EngineProcessName);

            CrashReporter.UseQueueForTests(queue);
            CrashReporter.Configure(new CrashReportingConfiguration
            {
                Enabled = true,
                BaseUrl = server.BaseUrl,
                ProcessName = "test.ui",
            });

            await CrashReporter.FlushPendingAsync(CancellationToken.None);

            var request = await server.WaitForRequestAsync();

            Assert.Equal("POST", request.Method);
            Assert.Equal("/api/v1/windows/crash-ingest", request.Path);
            Assert.Equal(EngineProcessName, request.Headers["X-Crash-Process"]);
            Assert.Equal("win_engine_crash_probe.txt", request.Headers["X-Crash-Filename"]);
            Assert.Contains("kind=fatal", request.Body, StringComparison.Ordinal);
            Assert.Contains("engine probe", request.Body, StringComparison.Ordinal);
            Assert.Empty(queue.ReadPending());
        }
        finally
        {
            CrashReporter.ResetForTests();
            DeleteDirectoryBestEffort(queueDir);
        }
    }

    static string CreateTempQueueDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), "datagate_crash_delivery_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    static async Task WaitForQueueToDrainAsync(CrashReportQueue queue)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            if (queue.ReadPending().Count == 0)
                return;

            await Task.Delay(50);
        }
    }

    static void DeleteDirectoryBestEffort(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch
        {
        }
    }

    sealed class LoopbackCrashServer : IAsyncDisposable
    {
        readonly TcpListener _listener;
        readonly Task<ReceivedRequest> _requestTask;

        public LoopbackCrashServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            var port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            BaseUrl = $"http://127.0.0.1:{port}/";
            _requestTask = AcceptOneAsync();
        }

        public string BaseUrl { get; }

        public Task<ReceivedRequest> WaitForRequestAsync()
            => _requestTask.WaitAsync(TimeSpan.FromSeconds(10));

        public ValueTask DisposeAsync()
        {
            _listener.Stop();
            return ValueTask.CompletedTask;
        }

        async Task<ReceivedRequest> AcceptOneAsync()
        {
            using var client = await _listener.AcceptTcpClientAsync();
            await using var stream = client.GetStream();

            var data = new List<byte>();
            var buffer = new byte[4096];
            var headerEnd = -1;

            while (headerEnd < 0)
            {
                var read = await stream.ReadAsync(buffer);
                if (read == 0)
                    throw new IOException("Client closed before sending headers.");

                data.AddRange(buffer.AsSpan(0, read).ToArray());
                headerEnd = FindHeaderEnd(data);
            }

            var headersBytes = data.Take(headerEnd).ToArray();
            var headersText = Encoding.ASCII.GetString(headersBytes);
            var lines = headersText.Split("\r\n", StringSplitOptions.None);
            var requestLine = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var headers = ParseHeaders(lines.Skip(1));
            var contentLength = headers.TryGetValue("Content-Length", out var rawLength)
                ? int.Parse(rawLength)
                : 0;

            var bodyStart = headerEnd + 4;
            while (data.Count - bodyStart < contentLength)
            {
                var read = await stream.ReadAsync(buffer);
                if (read == 0)
                    throw new IOException("Client closed before sending body.");

                data.AddRange(buffer.AsSpan(0, read).ToArray());
            }

            var body = Encoding.UTF8.GetString(data.Skip(bodyStart).Take(contentLength).ToArray());
            var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(response);

            return new ReceivedRequest(requestLine[0], requestLine[1], headers, body);
        }

        static int FindHeaderEnd(IReadOnlyList<byte> data)
        {
            for (var i = 3; i < data.Count; i++)
            {
                if (data[i - 3] == '\r'
                    && data[i - 2] == '\n'
                    && data[i - 1] == '\r'
                    && data[i] == '\n')
                {
                    return i - 3;
                }
            }

            return -1;
        }

        static Dictionary<string, string> ParseHeaders(IEnumerable<string> lines)
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var separator = line.IndexOf(':', StringComparison.Ordinal);
                if (separator <= 0)
                    continue;

                headers[line[..separator]] = line[(separator + 1)..].Trim();
            }

            return headers;
        }
    }

    sealed record ReceivedRequest(
        string Method,
        string Path,
        IReadOnlyDictionary<string, string> Headers,
        string Body);
}
