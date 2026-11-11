using System.Windows;
using System.Windows.Controls;
using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

[Collection(WpfStaCollection.Name)]
public sealed class InstallerUiThreadTests(WpfStaHost wpf)
{
    [Fact]
    public async Task Run_MarshalsCallbackOntoWpfDispatcherThread()
    {
        await wpf.RunAsync(async () =>
        {
            var uiThreadId = Environment.CurrentManagedThreadId;
            var observedThreadId = -1;

            await Task.Run(() =>
            {
                InstallerUiThread.Run(() => observedThreadId = Environment.CurrentManagedThreadId);
            }).ConfigureAwait(true);

            Assert.Equal(uiThreadId, observedThreadId);
            await Task.CompletedTask;
        });
    }

    [Fact]
    public async Task Run_AllowsBackgroundThreadToAppendInstallerLogSafely()
    {
        await wpf.RunAsync(async () =>
        {
            var logBox = new TextBox();

            await Task.Run(() =>
            {
                InstallerUiThread.Run(() => logBox.AppendText("background-safe"));
            }).ConfigureAwait(true);

            Assert.Equal("background-safe", logBox.Text);
            await Task.CompletedTask;
        });
    }
}

[Collection(WpfStaCollection.Name)]
public sealed class ProcessStopCoordinatorTests(WpfStaHost wpf)
{
    [Fact]
    public async Task EnsureAppProcessesStoppedAsync_CompletesWhenNoAppProcessesAreRunning()
    {
        await wpf.RunAsync(() =>
            ProcessStopCoordinator.EnsureAppProcessesStoppedAsync(
                interactivePrompts: false,
                log: _ => { }));
    }

    [Fact]
    public async Task EnsureAppProcessesStoppedAsync_DoesNotThrowWhenLoggingFromBackgroundAfterAwait()
    {
        await wpf.RunAsync(async () =>
        {
            var logBox = new TextBox();
            Exception? captured = null;

            try
            {
                await Task.Run(async () =>
                {
                    await ProcessStopCoordinator.EnsureAppProcessesStoppedAsync(
                        interactivePrompts: false,
                        log: message =>
                        {
                            InstallerUiThread.Run(() => logBox.AppendText(message));
                        }).ConfigureAwait(false);
                }).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                captured = ex;
            }

            Assert.Null(captured);
            await Task.CompletedTask;
        });
    }
}

[CollectionDefinition(WpfStaCollection.Name, DisableParallelization = true)]
public sealed class WpfStaCollectionDefinition : ICollectionFixture<WpfStaHost>;

public static class WpfStaCollection
{
    public const string Name = "WpfSta";
}

public sealed class WpfStaHost : IDisposable
{
    private readonly Thread _thread;
    private readonly ManualResetEventSlim _ready = new(false);
    private Application? _app;

    public WpfStaHost()
    {
        _thread = new Thread(() =>
        {
            _app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            _ready.Set();
            _app.Run();
        })
        {
            IsBackground = true
        };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        _ready.Wait();
    }

    public Task RunAsync(Func<Task> testBody)
    {
        if (_app == null)
            throw new InvalidOperationException("WPF application is not running.");

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _app.Dispatcher.InvokeAsync(async () =>
        {
            try
            {
                await testBody().ConfigureAwait(true);
                tcs.SetResult();
            }
            catch (Exception ex)
            {
                tcs.SetException(ex);
            }
        });
        return tcs.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    public void Dispose()
    {
        if (_app != null)
        {
            _app.Dispatcher.Invoke(() => _app.Shutdown());
            _thread.Join(TimeSpan.FromSeconds(5));
        }

        _ready.Dispose();
    }
}
