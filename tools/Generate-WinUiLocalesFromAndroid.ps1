# Regenerates DataGateWin.WinUI Localization/Strings.{code}.xaml from Android values-*/strings.xml.
# Master keys come from Strings.en.xaml. Existing overlay translations that differ from English are kept.
# Android snake_case keys are mapped from WinUI keys (auto + explicit aliases). Format %1$s → {0}.
#
# Usage: powershell -NoProfile -File tools/Generate-WinUiLocalesFromAndroid.ps1

param(
    [string]$AndroidResRoot = "F:\Android\DataGateAndroid\app\src\main\res",
    [string]$WinUiRoot = "$PSScriptRoot\..\DataGateWin.WinUI",
    [string]$WpfRoot = "$PSScriptRoot\..\DataGateWin.UI",
    [switch]$AlsoWpf
)

$ErrorActionPreference = "Stop"

$folderToCode = [ordered]@{
    "values-ar"     = "ar"
    "values-bg"     = "bg"
    "values-cs"     = "cs"
    "values-da"     = "da"
    "values-de"     = "de"
    "values-el"     = "el"
    "values-es"     = "es"
    "values-es-rMX" = "es-mx"
    "values-et"     = "et"
    "values-fa-rIR" = "fa"
    "values-fi"     = "fi"
    "values-fil"    = "fil"
    "values-fr"     = "fr"
    "values-ga"     = "ga"
    "values-hi-rIN" = "hi"
    "values-hr"     = "hr"
    "values-hu"     = "hu"
    "values-in"     = "id"
    "values-it"     = "it"
    "values-ja"     = "ja"
    "values-ko"     = "ko"
    "values-lt"     = "lt"
    "values-lv"     = "lv"
    "values-mt"     = "mt"
    "values-nl"     = "nl"
    "values-pl"     = "pl"
    "values-pt"     = "pt"
    "values-pt-rBR" = "pt-br"
    "values-ro"     = "ro"
    "values-ru"     = "ru"
    "values-sk"     = "sk"
    "values-sl"     = "sl"
    "values-sv"     = "sv"
    "values-th"     = "th"
    "values-tr"     = "tr"
    "values-uk"     = "uk"
    "values-vi"     = "vi"
    "values-zh-rCN" = "zh-hans"
    "values-zh-rTW" = "zh-hant"
}

# WinUI key → Android string name when ConvertTo-AndroidKey would miss.
$aliases = @{
    "About_Close"                              = "free_tier_close"
    "About_Title"                              = "settings_about"
    "Access_Col_In"                            = "label_in"
    "Access_Col_Online"                        = "status_online"
    "Access_Col_Out"                           = "label_out"
    "Access_Col_Server"                        = "label_server"
    "Access_EffectiveFromFmt"                  = "access_quota_effective_from"
    "Access_ExternalIdNote"                    = "access_quota_needs_external_id"
    "Access_NoTrafficLimitNote"                = "access_quota_no_traffic_cap"
    "Access_OverByFmt"                         = "access_quota_over_by"
    "Access_QuotaMetaThisMonth"                = "access_quota_period_month"
    "Access_QuotaMetaToday"                    = "access_quota_period_today"
    "Access_RemainingFmt"                      = "access_quota_remaining"
    "Access_Title"                             = "nav_access"
    "Access_TrafficQuota"                      = "access_quota_traffic_title"
    "Access_UsageUnavailable"                  = "access_quota_usage_unavailable"
    "Access_UsedLineFmt"                       = "access_quota_used_line"
    "Action_Ok"                                = "action_ok"
    "Btn_Refresh"                              = "access_refresh"
    "Common_Offline"                           = "status_offline"
    "Common_Online"                            = "status_online"
    "FreeTierOnboarding_BodyGeneric"           = "free_tier_body_generic"
    "FreeTierOnboarding_BodyLink"              = "free_tier_body_link"
    "FreeTierOnboarding_BodySubscribeOnly"     = "free_tier_body_subscribe_only"
    "FreeTierOnboarding_CheckAgain"            = "free_tier_check_again"
    "FreeTierOnboarding_CodeExpired"           = "free_tier_code_expired"
    "FreeTierOnboarding_CodeExpires"           = "free_tier_code_expires"
    "FreeTierOnboarding_CodeExpiresSoon"       = "free_tier_code_expires_soon"
    "FreeTierOnboarding_CodeRequestFailed"     = "free_tier_link_code_failed"
    "FreeTierOnboarding_CopyCode"              = "free_tier_copy_code"
    "FreeTierOnboarding_GetCode"               = "free_tier_get_code"
    "FreeTierOnboarding_OpenBot"               = "free_tier_open_bot"
    "FreeTierOnboarding_OpenChannel"           = "free_tier_open_channel"
    "FreeTierOnboarding_StatusRefreshFailed"   = "free_tier_status_check_failed"
    "FreeTierOnboarding_TelegramVpnHint"       = "free_tier_telegram_blocked_hint"
    "FreeTierOnboarding_TitleLink"             = "free_tier_title_link"
    "FreeTierOnboarding_TitleSubscribe"        = "free_tier_title_subscribe"
    "Home_Connect"                             = "action_connect"
    "Home_Disconnect"                          = "action_disconnect"
    "Home_ModeManual"                          = "access_choose_server"
    "Home_Network_ExternalIp"                  = "access_your_external_ip"
    "Home_Network_Server"                      = "label_server"
    "Home_Network_VpnIp"                       = "access_your_vpn_ip"
    "Home_Refresh"                             = "access_refresh"
    "Home_ReportEmail"                         = "home_report_email"
    "Home_ReportGithub"                        = "home_report_github"
    "Home_ReportIssue"                         = "home_report_issue"
    "Home_ReportIssueHint"                     = "home_report_issue_hint"
    "Home_ReportIssueTitle"                    = "home_report_issue_title"
    "Home_ReportTelegram"                      = "home_report_telegram"
    "Home_Server"                              = "label_server"
    "Home_Status_Connected"                    = "vpn_status_connected"
    "Home_Status_ConnectedFmt"                 = "vpn_msg_connected_to"
    "Home_Status_ConnectedIpFmt"               = "vpn_msg_connected_to"
    "Home_Status_ConnectedServerFmt"           = "vpn_msg_connected_to"
    "Home_Status_Connecting"                   = "vpn_status_connecting"
    "Home_Status_ConnectingWaiting"            = "vpn_waiting_events"
    "Home_Status_Disconnecting"                = "vpn_disconnecting"
    "Home_Status_ReconnectingFmt"              = "vpn_msg_reconnecting"
    "Home_Traffic_In"                          = "stats_traffic_in"
    "Home_Traffic_Out"                         = "stats_traffic_out"
    "Home_Traffic_Title"                       = "metric_traffic_total"
    "Import_AddSection"                        = "profiles_add"
    "Import_Delete"                            = "action_delete"
    "Import_Empty"                             = "profiles_empty_title"
    "Import_Hint_Xray"                         = "profiles_xray_paste_hint"
    "Import_Log_ProfileMissing"                = "profiles_error_not_found"
    "Import_Log_XrayNotReady"                  = "profiles_error_xray_not_supported"
    "Import_Protocol_OpenVpn"                  = "label_openvpn"
    "Import_Protocol_Xray"                     = "label_server_type_xray"
    "Import_Save"                              = "action_save"
    "Import_Status_ImportedFmt"                = "profiles_imported"
    "Import_Subtitle"                          = "profiles_empty_body"
    "Import_Title"                             = "profiles_title"
    "IpList_CoverageFast"                      = "settings_ip_lists_coverage_fast"
    "IpList_CoverageFull"                      = "settings_ip_lists_coverage_full"
    "IpList_CoverageLabel"                     = "settings_ip_lists_coverage_label"
    "IpList_DisabledNotice"                    = "settings_ip_lists_detail_disabled_notice"
    "IpList_EnableSubtitle"                    = "settings_ip_lists_enable_subtitle"
    "IpList_EnableTitle"                       = "settings_ip_lists_enable_title"
    "IpList_Freq_6h"                           = "settings_ip_lists_frequency_6h"
    "IpList_Freq_Daily"                        = "settings_ip_lists_frequency_daily"
    "IpList_Freq_Manual"                       = "settings_ip_lists_frequency_manual"
    "IpList_Freq_Weekly"                       = "settings_ip_lists_frequency_weekly"
    "IpList_FrequencyLabel"                    = "settings_ip_lists_frequency_label"
    "IpList_LastError"                         = "settings_ip_lists_last_error"
    "IpList_LastErrorNone"                     = "settings_ip_lists_last_error_none"
    "IpList_LastUpdated"                       = "settings_ip_lists_last_updated"
    "IpList_LastUpdatedNever"                  = "settings_ip_lists_last_updated_never"
    "IpList_Save"                              = "action_save"
    "IpList_SourceSubtitle"                    = "settings_ip_lists_source_subtitle"
    "IpList_SourceTitle"                       = "settings_ip_lists_source_title"
    "IpList_StatusTitle"                       = "settings_ip_lists_status_title"
    "IpList_Title"                             = "settings_ip_lists_title"
    "IpList_UpdateFailedFallbackFmt"           = "settings_ip_lists_update_failed_fallback"
    "IpList_UpdateFailedFmt"                   = "settings_ip_lists_update_failed"
    "IpList_UpdateNow"                         = "settings_ip_lists_update_now"
    "IpList_Saved"                             = "settings_ip_lists_saved"
    "Lang_Name_system"                         = "language_system"
    "Login_Cancel"                             = "action_cancel"
    "Login_SignInGoogle"                       = "login_sign_in_google"
    "Login_Totp_Back"                          = "totp_back_to_sign_in"
    "Login_Totp_ChallengeExpired"              = "totp_challenge_expired"
    "Login_Totp_Error_CodeRequired"            = "totp_error_code_required"
    "Login_Totp_Lead"                          = "totp_challenge_lead"
    "Login_Totp_LeadNamedFmt"                  = "totp_challenge_lead_named"
    "Login_Totp_Title"                         = "totp_field_code"
    "Login_Totp_Verify"                        = "totp_verify_sign_in"
    "Msg_ErrorTitle"                           = "error_request_failed"
    "Msg_LogoutConfirm"                        = "sign_out_confirm_message"
    "Msg_LogoutTitle"                          = "sign_out_confirm_title"
    "Msg_UpdateAvailableTitle"                 = "home_update_banner_title"
    "Settings_Account"                         = "account_title"
    "Settings_AccountHint"                     = "sign_out_subtitle"
    "Settings_AppearanceHint"                  = "settings_appearance_subtitle"
    "Settings_Checking"                        = "settings_check_updates_now_loading"
    "Settings_CurrentVersion"                  = "settings_app_version_label"
    "Settings_DarkMode"                        = "theme_dark"
    "Settings_IpLists"                         = "settings_ip_lists"
    "Settings_IpLists_Enable"                  = "settings_ip_lists_enable_title"
    "Settings_IpLists_EnableSubtitle"          = "settings_ip_lists_enable_subtitle"
    "Settings_IpLists_Open"                    = "settings_ip_lists_open"
    "Settings_IpLists_Subtitle"                = "settings_ip_lists_subtitle"
    "Settings_LanguageHint"                    = "settings_language_subtitle"
    "Settings_Logout"                          = "sign_out"
    "Stats_Group_Auto"                         = "grouping_auto"
    "Stats_Group_Hours"                        = "grouping_hours"
    "Stats_Group_Months"                       = "grouping_months"
    "Stats_Group_Years"                        = "grouping_years"
    "Stats_Last7"                              = "presets_last_7"
    "Stats_Last30"                             = "presets_last_30"
    "Stats_PeriodDataFmt"                      = "date_range_arrow"
    "Stats_Title"                              = "nav_statistics"
    "Telegram_SubscribeHint"                   = "home_telegram_channel_title"
}

function ConvertTo-AndroidKey([string]$winKey) {
    $parts = $winKey -split '_'
    $out = @()
    foreach ($p in $parts) {
        if ([string]::IsNullOrEmpty($p)) { continue }
        $s = [regex]::Replace($p, '(?<!^)(?=[A-Z][a-z])|(?<=[a-z])(?=[A-Z])', '_').ToLowerInvariant()
        $out += $s
    }
    return ($out -join '_')
}

function ConvertFrom-AndroidFormat([string]$text) {
    if ($null -eq $text) { return "" }
    $t = $text.Replace('\n', "`n").Replace("\'", "'").Replace('\"', '"')
    $t = [regex]::Replace($t, '%(\d+)\$[sdif]', {
            param($m)
            '{' + ([int]$m.Groups[1].Value - 1) + '}'
        })
    return $t.Replace('%%', '%')
}

function Get-PlaceholderIndexes([string]$text) {
    $list = New-Object System.Collections.Generic.List[int]
    foreach ($m in [regex]::Matches($text, '\{(\d+)\}')) {
        $list.Add([int]$m.Groups[1].Value)
    }
    return @($list | Select-Object -Unique)
}

function Test-PlaceholderCompatible([string]$enText, [string]$candidate) {
    $enIdx = @(Get-PlaceholderIndexes $enText)
    $cIdx = @(Get-PlaceholderIndexes $candidate)
    if ($enIdx.Count -eq 0) { return ($cIdx.Count -eq 0) }
    if ($cIdx.Count -ne $enIdx.Count) { return $false }
    foreach ($i in $enIdx) {
        if ($cIdx -notcontains $i) { return $false }
    }
    return $true
}

function Unescape-XmlText([string]$inner) {
    if ($null -eq $inner) { return "" }
    $prev = $null
    $t = $inner
    while ($t -ne $prev) {
        $prev = $t
        $t = $t.Replace('&amp;', '&').Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"')
        $t = $t -replace '&#x0[aA];', "`n"
    }
    return $t
}

function ConvertTo-Comparable([string]$text) {
    return (Unescape-XmlText $text).Trim()
}

function ConvertTo-XamlInner([string]$text) {
    if ($null -eq $text) { return "" }
    return $text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace("`r`n", '&#x0a;').Replace("`n", '&#x0a;')
}

function Read-XamlStringMap([string]$path) {
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $path)) { return $map }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    foreach ($m in [regex]::Matches($raw, '<(?:x|sys):String x:Key="([^"]+)">(.*?)</(?:x|sys):String>', 'Singleline')) {
        $inner = Unescape-XmlText $m.Groups[2].Value
        $map[$m.Groups[1].Value] = $inner
    }
    return $map
}

function Read-XamlKeyOrder([string]$path) {
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    return @(
        [regex]::Matches($raw, 'x:Key="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
    )
}

function Read-AndroidStrings([string]$xmlPath) {
    $d = @{}
    if (-not (Test-Path -LiteralPath $xmlPath)) { return $d }
    [xml]$x = Get-Content -LiteralPath $xmlPath -Encoding UTF8
    foreach ($el in $x.resources.string) {
        $name = $el.name
        if (-not $name) { continue }
        $translatable = $el.translatable
        if ($translatable -eq "false") { continue }
        $inner = $el.InnerText
        if ($null -eq $inner) { $inner = "" }
        $d[$name] = ConvertFrom-AndroidFormat $inner
    }
    return $d
}

function Resolve-AndroidCandidates([string]$winKey) {
    $list = New-Object System.Collections.Generic.List[string]
    if ($aliases.ContainsKey($winKey)) { $list.Add([string]$aliases[$winKey]) }
    $auto = ConvertTo-AndroidKey $winKey
    if (-not $list.Contains($auto)) { $list.Add($auto) }
    if ($winKey.StartsWith("FreeTierOnboarding_")) {
        $rest = ConvertTo-AndroidKey ($winKey.Substring("FreeTierOnboarding_".Length))
        $alt = "free_tier_$rest"
        if (-not $list.Contains($alt)) { $list.Add($alt) }
    }
    if ($winKey.StartsWith("IpList_")) {
        $rest = ConvertTo-AndroidKey ($winKey.Substring("IpList_".Length))
        $alt = "settings_ip_lists_$rest"
        if (-not $list.Contains($alt)) { $list.Add($alt) }
    }
    if ($winKey.StartsWith("Login_Totp_")) {
        $rest = ConvertTo-AndroidKey ($winKey.Substring("Login_Totp_".Length))
        $alt = "totp_$rest"
        if (-not $list.Contains($alt)) { $list.Add($alt) }
    }
    if ($winKey.StartsWith("Import_")) {
        $rest = ConvertTo-AndroidKey ($winKey.Substring("Import_".Length))
        $alt = "profiles_$rest"
        if (-not $list.Contains($alt)) { $list.Add($alt) }
    }
    return $list
}

function Resolve-TranslatedValue(
    [string]$key,
    [string]$code,
    [string]$enValue,
    $android,
    $existing,
    $androidEn
) {
    $enCmp = ConvertTo-Comparable $enValue

    # Russian overlay is hand-maintained for Windows-only copy; keep it over Android.
    if ($code -eq "ru" -and $null -ne $existing -and $existing.Contains($key)) {
        $had = ConvertTo-Comparable ([string]$existing[$key])
        if ($had.Length -gt 0 -and $had -ne $enCmp) {
            return [string]$existing[$key]
        }
    }

    foreach ($androidKey in (Resolve-AndroidCandidates $key)) {
        if (-not $android.ContainsKey($androidKey)) { continue }
        $candidate = [string]$android[$androidKey]
        if (-not (Test-PlaceholderCompatible $enValue $candidate)) { continue }
        if ((ConvertTo-Comparable $candidate).Length -eq 0) { continue }

        $enAndroid = ""
        if ($androidEn.ContainsKey($androidKey)) { $enAndroid = [string]$androidEn[$androidKey] }
        if ($enAndroid.Length -gt 0 -and (ConvertTo-Comparable $candidate) -eq (ConvertTo-Comparable $enAndroid)) {
            continue
        }
        return $candidate
    }

    return $enValue
}

function Invoke-Generate(
    [string]$root,
    [string]$stringTag,
    [string]$xmlnsSys
) {
    $locDir = Join-Path $root "Localization"
    $enPath = Join-Path $locDir "Strings.en.xaml"
    if (-not (Test-Path -LiteralPath $enPath)) { throw "Missing $enPath" }

    $enMap = Read-XamlStringMap $enPath
    $keyOrder = Read-XamlKeyOrder $enPath
    $androidEn = Read-AndroidStrings (Join-Path (Join-Path $AndroidResRoot "values") "strings.xml")

    $stats = @()
    foreach ($folder in $folderToCode.Keys) {
        $code = $folderToCode[$folder]
        $androidPath = Join-Path (Join-Path $AndroidResRoot $folder) "strings.xml"
        $android = Read-AndroidStrings $androidPath
        $existingPath = Join-Path $locDir "Strings.$code.xaml"
        $existing = Read-XamlStringMap $existingPath
        if ($code -eq "ru") {
            $wpfRu = Join-Path $WpfRoot "Localization\Strings.ru.xaml"
            $wpfMap = Read-XamlStringMap $wpfRu
            foreach ($k in @($wpfMap.Keys)) {
                if (-not $existing.Contains($k)) {
                    $existing[$k] = $wpfMap[$k]
                    continue
                }
                $enVal = ""
                if ($enMap.Contains($k)) { $enVal = ConvertTo-Comparable ([string]$enMap[$k]) }
                if ((ConvertTo-Comparable ([string]$existing[$k])) -eq $enVal -and (ConvertTo-Comparable ([string]$wpfMap[$k])) -ne $enVal) {
                    $existing[$k] = $wpfMap[$k]
                }
            }
        }

        $values = @{}
        $fromAndroid = 0
        $kept = 0
        $fallback = 0
        foreach ($key in $keyOrder) {
            $enValue = [string]$enMap[$key]
            $resolved = Resolve-TranslatedValue $key $code $enValue $android $existing $androidEn
            $values[$key] = $resolved
            $cmp = ConvertTo-Comparable $resolved
            $enCmp = ConvertTo-Comparable $enValue
            if ($existing.Contains($key) -and (ConvertTo-Comparable ([string]$existing[$key])) -eq $cmp -and $cmp -ne $enCmp) {
                $kept++
            }
            elseif ($cmp -ne $enCmp) {
                $fromAndroid++
            }
            else {
                $fallback++
            }
        }

        $outPath = Join-Path $locDir "Strings.$code.xaml"
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"')
        if ($xmlnsSys) {
            [void]$sb.AppendLine('                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"')
            [void]$sb.AppendLine('                    xmlns:sys="clr-namespace:System;assembly=System.Runtime">')
        }
        else {
            [void]$sb.AppendLine('                    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"')
            [void]$sb.AppendLine('                    >')
        }
        [void]$sb.AppendLine()
        foreach ($key in $keyOrder) {
            $inner = ConvertTo-XamlInner ([string]$values[$key])
            [void]$sb.AppendLine(('    <{0} x:Key="{1}">{2}</{0}>' -f $stringTag, $key, $inner))
        }
        [void]$sb.AppendLine('</ResourceDictionary>')
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($outPath, $sb.ToString(), $utf8)
        Write-Host ("Wrote {0}  translated={1} kept={2} en-fallback={3}" -f $outPath, $fromAndroid, $kept, $fallback)
        $stats += [PSCustomObject]@{ Code = $code; Translated = $fromAndroid; Kept = $kept; Fallback = $fallback }
    }
    return $stats
}

Write-Host "Generating WinUI locales from Android..."
$winUiStats = Invoke-Generate -root $WinUiRoot -stringTag "x:String" -xmlnsSys $null
$worst = $winUiStats | Sort-Object Fallback -Descending | Select-Object -First 5
Write-Host "Highest English fallback counts:"
$worst | ForEach-Object { Write-Host ("  {0}: en-fallback={1} translated={2} kept={3}" -f $_.Code, $_.Fallback, $_.Translated, $_.Kept) }

if ($AlsoWpf) {
    Write-Host "Generating WPF locales from Android..."
    [void](Invoke-Generate -root $WpfRoot -stringTag "sys:String" -xmlnsSys "sys")
}

Write-Host "Done."
