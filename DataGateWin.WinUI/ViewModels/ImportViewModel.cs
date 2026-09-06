using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Profiles;

namespace DataGateWin.ViewModels;

public sealed partial class ImportViewModel : ObservableObject
{
    private readonly ImportedVpnProfileStore _store = new();
    private readonly HomeController _home;

    public ImportViewModel(HomeController homeController)
    {
        _home = homeController;
        Reload();
    }

    public ObservableCollection<ImportedProfileListItem> Profiles { get; } = new();

    [ObservableProperty]
    private string statusText = "";

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private int protocolIndex; // 0 OpenVPN, 1 Xray

    public bool IsOpenVpnSelected => ProtocolIndex == 0;
    public bool IsXraySelected => ProtocolIndex == 1;

    partial void OnProtocolIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsOpenVpnSelected));
        OnPropertyChanged(nameof(IsXraySelected));
        StatusText = value == 1 ? Loc.T("Import_XrayComingSoon") : "";
    }

    public void Reload()
    {
        Profiles.Clear();
        foreach (var p in _store.List())
        {
            Profiles.Add(new ImportedProfileListItem
            {
                Id = p.Id,
                Name = p.Name,
                ProtocolLabel = p.Protocol == ImportedVpnProtocol.Xray
                    ? Loc.T("Import_Protocol_Xray")
                    : Loc.T("Import_Protocol_OpenVpn"),
                Meta = Loc.T(
                    "Import_ProfileMetaFmt",
                    p.SourceFileName ?? "—",
                    p.UpdatedUtc.ToLocalTime().ToString("g")),
                CanConnect = p.Protocol == ImportedVpnProtocol.OpenVpn,
            });
        }
    }

    public ImportedVpnProfile? ImportOpenVpnText(string configText, string? fileName)
    {
        if (ProtocolIndex != 0)
        {
            StatusText = Loc.T("Import_XrayComingSoon");
            return null;
        }

        if (!ImportedOpenVpnValidator.TryValidate(configText, out var err))
        {
            StatusText = Loc.T("Import_Validate_" + err);
            return null;
        }

        var profile = new ImportedVpnProfile
        {
            Name = ImportedOpenVpnValidator.SuggestName(fileName, configText),
            Protocol = ImportedVpnProtocol.OpenVpn,
            ConfigText = configText,
            SourceFileName = string.IsNullOrWhiteSpace(fileName) ? null : Path.GetFileName(fileName),
        };
        _store.Upsert(profile);
        Reload();
        StatusText = Loc.T("Import_Status_ImportedFmt", profile.Name);
        return profile;
    }

    [RelayCommand]
    private void DeleteProfile(Guid? id)
    {
        if (id is null || id == Guid.Empty)
            return;
        if (_store.Delete(id.Value))
        {
            Reload();
            StatusText = Loc.T("Import_Status_Deleted");
        }
    }

    [RelayCommand]
    private async Task ConnectProfile(Guid? id)
    {
        if (id is null || id == Guid.Empty || IsBusy)
            return;

        var profile = _store.Get(id.Value);
        if (profile is null)
        {
            StatusText = Loc.T("Import_Log_ProfileMissing");
            return;
        }

        if (profile.Protocol != ImportedVpnProtocol.OpenVpn)
        {
            StatusText = Loc.T("Import_XrayComingSoon");
            return;
        }

        IsBusy = true;
        try
        {
            StatusText = Loc.T("Import_Status_ConnectingFmt", profile.Name);
            var started = await _home.ConnectImportedProfileAsync(profile.Id);
            StatusText = started
                ? Loc.T("Import_Status_ConnectStartedFmt", profile.Name)
                : Loc.T("Import_Status_ConnectFailedFmt", profile.Name);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "ImportViewModel.ConnectProfile");
            StatusText = Loc.T("Home_Log_ErrorFmt", ex.Message);
        }
        finally
        {
            IsBusy = false;
        }
    }
}

public sealed class ImportedProfileListItem
{
    public Guid Id { get; init; }
    public string Name { get; init; } = "";
    public string ProtocolLabel { get; init; } = "";
    public string Meta { get; init; } = "";
    public bool CanConnect { get; init; }
}
