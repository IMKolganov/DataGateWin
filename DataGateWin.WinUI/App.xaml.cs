using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Principal;
using DataGateWin.Services.Ui;
using DataGateWin.Configuration;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Ipc;
using DataGateWin.Services.Tray;
using DataGateWin.Services.Update;
using Microsoft.Extensions.Configuration;
using Microsoft.UI.Dispatching;
using DataGateWin.Views;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin;

public partial class App : Application
{
    public static IConfiguration AppConfiguration { get; private set; } = null!;
    public static AuthApiClient AuthApi { get; private set; } = null!;
    public static AuthSession Session { get; private set; } = null!;
    public static HttpClient AuthedApiHttp { get; private set; } = null!;
    public static GoogleAuthService GoogleAuth { get; private set; } = null!;
    public static AppSettings Settings { get; private set; } = new();
    public static DispatcherQueue? UiDispatcher { get; private set; }
    public static Window? CurrentMainWindow { get; set; }

    private TrayService? _tray;
    private readonly EnginePathResolver _enginePathResolver = new();
    private string? _engineExePath;
    private Window? _startupWindow;
    private bool _exitRequested;
    private bool _suppressExitOnWindowClose;

    public App()
    {
        try
        {
            // Must run before any window — otherwise WinUI unpackaged taskbar icon stays blank/generic.
            AppIcon.SetProcessAppUserModelId();

            var boot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DataGateWin",
                "startup-error.log");
            Directory.CreateDirectory(Path.GetDirectoryName(boot)!);
            File.WriteAllText(boot, "App() before InitializeComponent\n");

            // Application.RequestedTheme is only reliably set before the first window.
            Settings = AppSettingsStore.LoadSafe();
            try
            {
                RequestedTheme = ResolveApplicationTheme(Settings.Theme);
            }
            catch (Exception ex)
            {
                File.AppendAllText(boot, "RequestedTheme early WARN: " + ex.Message + "\n");
            }

            InitializeComponent();
            File.AppendAllText(boot, "App() after InitializeComponent OK\n");
        }
        catch (Exception ex)
        {
            try
            {
                var boot = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "DataGateWin",
                    "startup-error.log");
                Directory.CreateDirectory(Path.GetDirectoryName(boot)!);
                File.WriteAllText(boot, "App() InitializeComponent FAILED\n" + ex);
            }
            catch { /* ignore */ }
            throw;
        }

        UnhandledException += (_, e) =>
        {
            CrashReporter.HandleDispatcherUnhandled(e.Exception);
            try
            {
                var boot = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "DataGateWin",
                    "startup-error.log");
                File.AppendAllText(boot, "\nUnhandled: " + e.Exception + "\n");
            }
            catch { /* ignore */ }
            e.Handled = true;
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            var boot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DataGateWin",
                "startup-error.log");
            File.WriteAllText(boot, "OnLaunched\n");

            CrashReporter.InstallDomainHandlers();
            UiDispatcher = DispatcherQueue.GetForCurrentThread();

            try
            {
                Resources.MergedDictionaries.Add(new Microsoft.UI.Xaml.Controls.XamlControlsResources());
                File.AppendAllText(boot, "XamlControlsResources OK\n");
            }
            catch (Exception ex)
            {
                File.AppendAllText(boot, "XamlControlsResources WARN: " + ex + "\n");
            }

            WinUiLanguageService.WireLocResolver();
            // Settings already loaded in App() for early RequestedTheme.
            Settings = AppSettingsStore.LoadSafe();
            WinUiLanguageService.ApplyFromSettings();
            NormalizeThemeSetting();

            File.AppendAllText(boot, "RunStartupAsync begin\n");
            _ = RunStartupAsync();
        }
        catch (Exception ex)
        {
            try
            {
                var logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "DataGateWin",
                    "startup-error.log");
                Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
                File.WriteAllText(logPath, ex.ToString());
            }
            catch { /* ignore */ }

            throw;
        }
    }

    private void NormalizeThemeSetting()
    {
        var themeName = Settings.Theme;
        if (!string.Equals(themeName, "Light", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(themeName, "Dark", StringComparison.OrdinalIgnoreCase))
        {
            Settings.Theme = "Dark";
            AppSettingsStore.SaveSafe(Settings);
        }
    }

    private static ApplicationTheme ResolveApplicationTheme(string? themeName)
        => string.Equals(themeName, "Light", StringComparison.OrdinalIgnoreCase)
            ? ApplicationTheme.Light
            : ApplicationTheme.Dark;

    public static ElementTheme ResolveElementTheme()
        => string.Equals(Settings.Theme, "Light", StringComparison.OrdinalIgnoreCase)
            ? ElementTheme.Light
            : ElementTheme.Dark;

    /// <summary>
    /// Runtime theme switch: Application.RequestedTheme cannot change after launch on WinUI.
    /// Set ElementTheme on each shell window root instead.
    /// </summary>
    public static void ApplyElementTheme(ElementTheme? theme = null)
    {
        var resolved = theme ?? ResolveElementTheme();
        ApplyElementThemeToWindow(CurrentMainWindow, resolved);
    }

    public static void ApplyElementThemeToWindow(Window? window, ElementTheme? theme = null)
    {
        if (window?.Content is not FrameworkElement root)
            return;
        root.RequestedTheme = theme ?? ResolveElementTheme();
    }

    public static XamlRoot? GetActiveXamlRoot()
    {
        if (CurrentMainWindow?.Content is FrameworkElement fe)
            return fe.XamlRoot;
        return null;
    }

    public static void RequestExit()
    {
        if (Current is App app)
            app.ExitApp();
    }

    private void ExitApp()
    {
        if (_exitRequested)
            return;
        _exitRequested = true;

        TryGracefulEngineShutdownSync();
        try { AppSettingsStore.SaveSafe(Settings); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "App.Exit.SaveSettings"); }
        try { _tray?.Unregister(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "App.Exit.TrayUnregister"); }

        CurrentMainWindow?.Close();
        _startupWindow?.Close();
        Exit();
    }

    private void TryGracefulEngineShutdownSync()
    {
        try
        {
            EngineSessionService.TryStopActiveSessionSafeAsync(TimeSpan.FromSeconds(20))
                .GetAwaiter()
                .GetResult();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "App.TryGracefulEngineShutdown.StopSession");
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(_engineExePath) && File.Exists(_engineExePath))
            {
                KillEngineProcessesByExactPathOnce(_engineExePath);
                EngineDnsRecoveryRunner.TryRecover(_engineExePath);
            }
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "App.TryGracefulEngineShutdown.KillEngine");
        }
    }

    private async Task RunStartupAsync()
    {
        var boot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DataGateWin",
            "startup-error.log");

        try
        {
            File.AppendAllText(boot, "admin check\n");
            if (ShouldQuitForMissingAdministrator())
            {
                await ShowMessageAsync(Loc.T("Msg_AdminTitle"), Loc.T("Msg_AdminBody")).ConfigureAwait(true);
                ExitApp();
                return;
            }

            _engineExePath = _enginePathResolver.ResolveEngineExePath();
            var configDir = AppContext.BaseDirectory;
            var configPath = Path.Combine(configDir, "appsettings.json");
            File.AppendAllText(boot, $"config={configPath} engine={_engineExePath}\n");

            while (true)
            {
                AppsettingsConnection.TryLoadFile(configPath, out var api, out var google);

                if (AppsettingsConnection.IsComplete(api, google))
                    break;

                File.AppendAllText(boot, "FirstRun show\n");
                var dlg = new FirstRunConfigurationWindow(api, google);
                var completed = await dlg.ShowAsync().ConfigureAwait(true);
                if (!completed)
                {
                    ExitApp();
                    return;
                }
            }

            File.AppendAllText(boot, "config OK, building services\n");
            AppConfiguration = new ConfigurationBuilder()
                .SetBasePath(configDir)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            var apiSettings = AppConfiguration.GetSection("Api").Get<ApiSettings>()
                ?? throw new InvalidOperationException("Api settings are missing.");

            if (string.IsNullOrWhiteSpace(apiSettings.BaseUrl))
                throw new InvalidOperationException("Api:BaseUrl is missing.");

            ConfigureCrashReporting(apiSettings.BaseUrl);
            _ = CrashReporter.FlushPendingAsync(CancellationToken.None);

            var googleSettings = AppConfiguration.GetSection("GoogleAuth").Get<GoogleAuthSettings>()
                ?? throw new InvalidOperationException("GoogleAuth settings are missing.");

            if (string.IsNullOrWhiteSpace(googleSettings.ClientId))
                throw new InvalidOperationException("GoogleAuth:ClientId is missing.");

            if (googleSettings.RedirectPort <= 0 || googleSettings.RedirectPort > 65535)
                throw new InvalidOperationException("GoogleAuth:RedirectPort is invalid.");

            var deviceId = DeviceInfo.GetOrCreateDeviceId();
            var userAgent = DeviceInfo.GetUserAgent();
            var baseUri = new Uri(apiSettings.BaseUrl, UriKind.Absolute);
            var startupHttpTimeout = TimeSpan.FromSeconds(30);

            AuthApi = new AuthApiClient(new HttpClient { BaseAddress = baseUri, Timeout = startupHttpTimeout });
            Session = new AuthSession(AuthApi, new FileTokenStore("DataGateWin"), deviceId, userAgent);
            await Session.InitializeAsync(CancellationToken.None);

            AuthedApiHttp = new HttpClient(new AuthenticatedHttpHandler(Session, new HttpClientHandler()))
            {
                BaseAddress = baseUri,
                Timeout = TimeSpan.FromMinutes(2)
            };

            GoogleAuth = new GoogleAuthService(new HttpClient { Timeout = TimeSpan.FromMinutes(2) });

            var authState = new AuthStateStore();
            var token = await Session.GetValidAccessTokenAsync(CancellationToken.None);
            File.AppendAllText(boot, $"token empty={string.IsNullOrWhiteSpace(token)}\n");

            if (!string.IsNullOrWhiteSpace(token))
            {
                authState.SetAuthorized(token);
                File.AppendAllText(boot, "ShowMain\n");
                ShowMain(authState);
                File.AppendAllText(boot, "ShowMain done\n");
                return;
            }

            File.AppendAllText(boot, "ShowLogin\n");
            ShowLogin(authState);
            File.AppendAllText(boot, "ShowLogin done\n");
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "StartupFailed");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(boot)!);
                var detail = ex.ToString();
                if (ex is Microsoft.UI.Xaml.Markup.XamlParseException xpe)
                {
                    detail +=
                        $"{Environment.NewLine}HResult=0x{xpe.HResult:X8}" +
                        $"{Environment.NewLine}Message={xpe.Message}" +
                        $"{Environment.NewLine}Inner={xpe.InnerException}";
                }

                await File.WriteAllTextAsync(boot, detail).ConfigureAwait(true);
            }
            catch { /* ignore */ }

            await ShowMessageAsync(
                Loc.T("Msg_StartupFailedTitle"),
                Loc.T("Msg_StartupFailedBodyFmt", ex.Message)).ConfigureAwait(true);
            ExitApp();
        }
    }

    public void ShowMain(AuthStateStore authState)
    {
        _suppressExitOnWindowClose = true;
        try
        {
            var previous = CurrentMainWindow;
            var main = new MainWindow(authState, AuthedApiHttp);
            CurrentMainWindow = main;
            _startupWindow = main;
            main.Closed += OnShellWindowClosed;
            ApplyElementThemeToWindow(main);
            main.Activate();

            ScheduleUpdateCheck();

            try { _tray?.Unregister(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "App.ShowMain.TrayUnregister"); }
            _tray = new TrayService();
            _tray.AttachMainWindow(main);
            _tray.Register();

            if (previous is not null && !ReferenceEquals(previous, main))
                previous.Close();
        }
        finally
        {
            _suppressExitOnWindowClose = false;
        }
    }

    public void ShowLogin(AuthStateStore authState)
    {
        _suppressExitOnWindowClose = true;
        try
        {
            var previous = CurrentMainWindow;
            try { _tray?.Unregister(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "App.ShowLogin.TrayUnregister"); }
            _tray = null;

            var login = new LoginWindow(authState);
            CurrentMainWindow = login;
            _startupWindow = login;
            login.Closed += OnShellWindowClosed;
            ApplyElementThemeToWindow(login);
            login.Activate();
            ScheduleUpdateCheck();

            if (previous is not null && !ReferenceEquals(previous, login))
                previous.Close();
        }
        finally
        {
            _suppressExitOnWindowClose = false;
        }
    }

    private void OnShellWindowClosed(object sender, WindowEventArgs args)
    {
        if (_exitRequested || _suppressExitOnWindowClose)
            return;

        // Last shell window gone with no tray → quit (e.g. user closed Login).
        if (_tray is null && ReferenceEquals(CurrentMainWindow, sender))
            ExitApp();
    }

    internal static void ScheduleUpdateCheck()
    {
        _ = Task.Run(async () =>
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            var checker = new GitHubUpdateChecker(http, "IMKolganov", "DataGateWin");
            await checker.CheckForUpdateAsync(CancellationToken.None).ConfigureAwait(false);
        });
    }

    private static void ConfigureCrashReporting(string apiBaseUrl)
    {
        var crashSettings = AppConfiguration.GetSection("CrashReporting").Get<CrashReportingConfiguration>()
            ?? AppsettingsConnection.CreateDefaultCrashReporting();

        if (string.IsNullOrWhiteSpace(crashSettings.BaseUrl))
            crashSettings.BaseUrl = apiBaseUrl;

        if (string.IsNullOrWhiteSpace(crashSettings.ProcessName))
            crashSettings.ProcessName = CrashReporter.DefaultProcessName;

        crashSettings.CrashToken ??= "";
        CrashReporter.Configure(crashSettings);
    }

    private static bool ShouldQuitForMissingAdministrator()
    {
#if DEBUG
        return false;
#else
        var skip = Environment.GetEnvironmentVariable("DATAGATE_WIN_SKIP_ADMIN_CHECK");
        if (string.Equals(skip, "1", StringComparison.Ordinal)
            || string.Equals(skip, "true", StringComparison.OrdinalIgnoreCase))
            return false;

        return !IsRunningAsAdministrator();
#endif
    }

    private static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private async Task ShowMessageAsync(string title, string body)
    {
        // Bootstrap a tiny host window so ContentDialog has a XamlRoot before MainWindow exists.
        var host = new Window { Title = title };
        var root = new Grid();
        host.Content = root;
        host.Activate();
        await Task.Delay(50);

        var dlg = new ContentDialog
        {
            Title = title,
            Content = body,
            CloseButtonText = Loc.T("Action_Ok"),
            XamlRoot = root.XamlRoot,
        };
        await dlg.ShowAsync();
        host.Close();
    }

    private static void KillEngineProcessesByExactPathOnce(string engineExePath)
    {
        var targetPath = Path.GetFullPath(engineExePath).TrimEnd(Path.DirectorySeparatorChar);
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(targetPath)))
        {
            try
            {
                var procPath = p.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(procPath))
                    continue;
                procPath = Path.GetFullPath(procPath).TrimEnd(Path.DirectorySeparatorChar);
                if (!string.Equals(procPath, targetPath, StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    if (!p.HasExited)
                    {
                        p.CloseMainWindow();
                        p.WaitForExit(500);
                    }
                }
                catch (Exception ex)
                {
                    CrashReporter.ReportNonFatal(ex, "App.KillEngineProcesses.CloseMainWindow");
                }

                if (!p.HasExited)
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(1500);
                }
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "App.KillEngineProcesses");
            }
            finally
            {
                try { p.Dispose(); } catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "App.KillEngineProcesses.Dispose"); }
            }
        }
    }
}
