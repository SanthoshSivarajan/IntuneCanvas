<#
================================================================================
  IntuneCanvas -- Paint the Full Picture of Your Intune Environment
  Version: 1.0
  Author : Santhosh Sivarajan, Microsoft MVP
  Purpose: Generates a comprehensive HTML report of Microsoft Intune / Endpoint
           Manager including devices, compliance policies, configuration profiles,
           apps, Autopilot, security baselines, enrollment, and more.
  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/IntuneCanvas
================================================================================
#>

#Requires -Modules Microsoft.Graph.Authentication

param(
    [string]$OutputPath = $PSScriptRoot
)

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "IntuneCanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   IntuneCanvas -- Intune Documentation Tool v1.0           |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP              |" -ForegroundColor Cyan
Write-Host "  |   Web    : github.com/SanthoshSivarajan/IntuneCanvas      |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

# --- Connect to Microsoft Graph -----------------------------------------------
$RequiredScopes = @(
    'DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All',
    'DeviceManagementApps.Read.All','DeviceManagementServiceConfig.Read.All',
    'DeviceManagementRBAC.Read.All','Directory.Read.All','Organization.Read.All'
)

$graphContext = Get-MgContext -ErrorAction SilentlyContinue
if (-not $graphContext) {
    Write-Host "  [*] Connecting to Microsoft Graph ..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
        $graphContext = Get-MgContext
    } catch {
        Write-Host "  [!] Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      Install module: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [*] Using existing Microsoft Graph session." -ForegroundColor Yellow
}

$Org = (Get-MgOrganization -ErrorAction SilentlyContinue)
$TenantName = $Org.DisplayName
$TenantId   = $Org.Id

Write-Host "  [*] Tenant    : $TenantName ($TenantId)" -ForegroundColor White
Write-Host "  [*] Account   : $($graphContext.Account)" -ForegroundColor White
Write-Host "  [*] Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""
Write-Host "  Collecting Intune data ..." -ForegroundColor Yellow
Write-Host ""

# --- Helpers ------------------------------------------------------------------
Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }
function ConvertTo-HtmlTable {
    param([Parameter(Mandatory)]$Data,[string[]]$Properties)
    if (-not $Data -or @($Data).Count -eq 0) { return '<p class="empty-note">No data found.</p>' }
    $rows = @($Data)
    if (-not $Properties) { $Properties = ($rows[0].PSObject.Properties).Name }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($p in $Properties) { [void]$sb.Append("<th>$(HtmlEncode $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Properties) {
            $val = $row.$p
            if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = ($val | ForEach-Object { [string]$_ }) -join ", " }
            [void]$sb.Append("<td>$(HtmlEncode $val)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}
function Graph-Get {
    param([string]$Uri, [string]$Label)
    $all = @()
    try {
        $result = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        if ($result.value) { $all += $result.value }
        while ($result.'@odata.nextLink') {
            $result = Invoke-MgGraphRequest -Method GET -Uri $result.'@odata.nextLink' -ErrorAction Stop
            if ($result.value) { $all += $result.value }
        }
        if ($Label) { Write-Host "  [+] $Label ($($all.Count))" -ForegroundColor Green }
    } catch {
        if ($Label) { Write-Host "  [i] Could not collect: $Label -- $($_.Exception.Message)" -ForegroundColor Gray }
    }
    return $all
}

# ==============================================================================
# DATA COLLECTION
# ==============================================================================

# --- Managed Devices ----------------------------------------------------------
$ManagedDevices = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices' -Label "Managed devices"
$TotalDevices     = $ManagedDevices.Count
$CompliantDevices = @($ManagedDevices | Where-Object { $_.complianceState -eq 'compliant' }).Count
$NonCompliant     = @($ManagedDevices | Where-Object { $_.complianceState -eq 'noncompliant' }).Count
$InGracePeriod    = @($ManagedDevices | Where-Object { $_.complianceState -eq 'inGracePeriod' }).Count
$UnknownCompliance = $TotalDevices - $CompliantDevices - $NonCompliant - $InGracePeriod
$ManagedCount     = @($ManagedDevices | Where-Object { $_.managementAgent -ne 'unknown' }).Count

# OS breakdown
$WindowsDevices = @($ManagedDevices | Where-Object { $_.operatingSystem -eq 'Windows' }).Count
$iOSDevices     = @($ManagedDevices | Where-Object { $_.operatingSystem -eq 'iOS' }).Count
$AndroidDevices = @($ManagedDevices | Where-Object { $_.operatingSystem -eq 'Android' }).Count
$macOSDevices   = @($ManagedDevices | Where-Object { $_.operatingSystem -eq 'macOS' }).Count
$OtherOSDevices = $TotalDevices - $WindowsDevices - $iOSDevices - $AndroidDevices - $macOSDevices

# Ownership
$CorporateDevices = @($ManagedDevices | Where-Object { $_.managedDeviceOwnerType -eq 'company' }).Count
$PersonalDevices  = @($ManagedDevices | Where-Object { $_.managedDeviceOwnerType -eq 'personal' }).Count

# Enrollment
$MDMEnrolled = @($ManagedDevices | Where-Object { $_.managementAgent -like '*mdm*' }).Count
$CoManaged   = @($ManagedDevices | Where-Object { $_.managementAgent -eq 'configurationManagerClientMdm' }).Count

# OS version distribution
$OSVersionDist = @{}
$ManagedDevices | ForEach-Object {
    $key = "$($_.operatingSystem) $($_.osVersion)"
    if ($key.Trim()) {
        if ($OSVersionDist.ContainsKey($key)) { $OSVersionDist[$key]++ } else { $OSVersionDist[$key] = 1 }
    }
}

# Device summary table (top 100)
$DeviceSummary = $ManagedDevices | Sort-Object { $_.lastSyncDateTime } -Descending | Select-Object -First 100 | ForEach-Object {
    [PSCustomObject]@{
        DeviceName  = $_.deviceName
        UserName    = $_.userDisplayName
        OS          = $_.operatingSystem
        OSVersion   = $_.osVersion
        Compliance  = $_.complianceState
        Ownership   = $_.managedDeviceOwnerType
        Management  = $_.managementAgent
        Encrypted   = $_.isEncrypted
        LastSync    = $_.lastSyncDateTime
        EnrolledDate = $_.enrolledDateTime
    }
}

# --- Compliance Policies ------------------------------------------------------
$CompliancePolicies = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies' -Label "Compliance policies"
$CompPolicySummary = $CompliancePolicies | ForEach-Object {
    $platform = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.','' -replace 'CompliancePolicy',''
    [PSCustomObject]@{
        Name        = $_.displayName
        Platform    = $platform
        Created     = $_.createdDateTime
        Modified    = $_.lastModifiedDateTime
        Description = $_.description
    }
}

# --- Configuration Profiles ---------------------------------------------------
$ConfigProfiles = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations' -Label "Configuration profiles"
$ConfigProfileSummary = $ConfigProfiles | ForEach-Object {
    $platform = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.','' -replace 'Configuration',''
    [PSCustomObject]@{
        Name        = $_.displayName
        Platform    = $platform
        Created     = $_.createdDateTime
        Modified    = $_.lastModifiedDateTime
        Description = $_.description
    }
}

# --- Settings Catalog Profiles (Beta) -----------------------------------------
$SettingsCatalog = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Label "Settings Catalog policies"
$SettingsCatalogSummary = $SettingsCatalog | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.name
        Platforms   = $_.platforms
        Technologies = $_.technologies
        Created     = $_.createdDateTime
        Modified    = $_.lastModifiedDateTime
        Description = $_.description
    }
}

# --- App Protection Policies --------------------------------------------------
$AppProtectionAndroid = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections' -Label "App protection (Android)"
$AppProtectioniOS     = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections' -Label "App protection (iOS)"
$AppProtectionAll = @()
foreach ($p in $AppProtectionAndroid) {
    $AppProtectionAll += [PSCustomObject]@{ Name=$p.displayName; Platform='Android'; Created=$p.createdDateTime; Modified=$p.lastModifiedDateTime }
}
foreach ($p in $AppProtectioniOS) {
    $AppProtectionAll += [PSCustomObject]@{ Name=$p.displayName; Platform='iOS'; Created=$p.createdDateTime; Modified=$p.lastModifiedDateTime }
}

# --- Managed Apps -------------------------------------------------------------
$ManagedApps = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps' -Label "Mobile apps"
$TotalApps = $ManagedApps.Count

# Categorize apps by type
$AppsByType = @{}
$ManagedApps | ForEach-Object {
    $type = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
    if ($AppsByType.ContainsKey($type)) { $AppsByType[$type]++ } else { $AppsByType[$type] = 1 }
}
$AppSummary = $ManagedApps | ForEach-Object {
    $type = $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
    [PSCustomObject]@{
        Name      = $_.displayName
        Type      = $type
        Publisher = $_.publisher
        Created   = $_.createdDateTime
    }
} | Sort-Object Name

# --- Autopilot Profiles -------------------------------------------------------
$AutopilotProfiles = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles' -Label "Autopilot profiles"
$AutopilotProfileSummary = $AutopilotProfiles | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.displayName
        Description = $_.description
        Mode        = $_.extractHardwareHash
        OOBE        = $_.outOfBoxExperienceSetting
        Created     = $_.createdDateTime
    }
}

# Autopilot devices
$AutopilotDevices = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities' -Label "Autopilot devices"

# --- Windows Update Rings -----------------------------------------------------
$UpdateRings = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$filter=isof(%27microsoft.graph.windowsUpdateForBusinessConfiguration%27)' -Label "Windows Update rings"
if ($UpdateRings.Count -eq 0) {
    $UpdateRings = $ConfigProfiles | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.windowsUpdateForBusinessConfiguration' }
    if ($UpdateRings) { Write-Host "  [+] Windows Update rings found in config profiles ($(@($UpdateRings).Count))" -ForegroundColor Green }
}
$UpdateRingSummary = @($UpdateRings) | ForEach-Object {
    [PSCustomObject]@{
        Name     = $_.displayName
        Created  = $_.createdDateTime
        Modified = $_.lastModifiedDateTime
    }
}

# --- Endpoint Security --------------------------------------------------------
$SecurityBaselines = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/templates?$filter=templateType eq %27securityBaseline%27' -Label "Security baseline templates"
$EndpointSecPolicies = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/intents' -Label "Endpoint security policies"
$EndpointSecSummary = @()
foreach ($ep in $EndpointSecPolicies) {
    $EndpointSecSummary += [PSCustomObject]@{
        Name=$ep.displayName; Description=$ep.description; IsAssigned=$ep.isAssigned; Created=$ep.createdDateTime
    }
}

# --- Enrollment Restrictions --------------------------------------------------
$EnrollmentConfigs = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations' -Label "Enrollment configurations"
$EnrollmentSummary = @()
foreach ($e in $EnrollmentConfigs) {
    $type = $e.'@odata.type'
    if (-not $type -and $e.AdditionalProperties) { $type = $e.AdditionalProperties.'@odata.type' }
    $type = ($type -replace '#microsoft.graph.','') -replace 'Configuration',''
    $EnrollmentSummary += [PSCustomObject]@{
        Name=$e.displayName; Type=$type; Priority=$e.priority; Created=$e.createdDateTime
    }
}

# --- RBAC Roles ---------------------------------------------------------------
$RBACRoles = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions' -Label "RBAC role definitions"
$RBACRoleSummary = $RBACRoles | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.displayName
        Description = $_.description
        IsBuiltIn   = $_.isBuiltIn
    }
}

# --- Scope Tags ---------------------------------------------------------------
$ScopeTags = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/roleScopeTags' -Label "Scope tags"
$ScopeTagSummary = @()
foreach ($st in $ScopeTags) {
    $ScopeTagSummary += [PSCustomObject]@{
        Name=$st.displayName; Description=$st.description; Id=$st.id; IsBuiltIn=$st.isBuiltIn
    }
}

# --- Assignment Filters -------------------------------------------------------
$Filters = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters' -Label "Assignment filters"
$FilterSummary = @()
foreach ($f in $Filters) {
    $FilterSummary += [PSCustomObject]@{ Name=$f.displayName; Platform=$f.platform; Rule=$f.rule; Created=$f.createdDateTime }
}

# --- Device Categories --------------------------------------------------------
$DeviceCategories = Graph-Get -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories' -Label "Device categories"

# --- Scripts / Remediations ---------------------------------------------------
$DeviceScripts = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -Label "PowerShell scripts"
$DeviceScriptSummary = @()
foreach ($ds in $DeviceScripts) {
    $DeviceScriptSummary += [PSCustomObject]@{ Name=$ds.displayName; RunAsAccount=$ds.runAsAccount; EnforceSignature=$ds.enforceSignatureCheck; RunAs32Bit=$ds.runAs32Bit; Created=$ds.createdDateTime }
}
$Remediations = Graph-Get -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts' -Label "Remediation scripts"
$RemediationSummary = @()
foreach ($rm in $Remediations) {
    $RemediationSummary += [PSCustomObject]@{ Name=$rm.displayName; Publisher=$rm.publisher; IsGlobal=$rm.isGlobalScript; Created=$rm.createdDateTime }
}

Write-Host ""
Write-Host "  [+] Data collection complete." -ForegroundColor Green

# ==============================================================================
# BUILD TABLES
# ==============================================================================
$DeviceTable      = if ($DeviceSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $DeviceSummary -Properties DeviceName, UserName, OS, OSVersion, Compliance, Ownership, Management, Encrypted, LastSync } else { '<p class="empty-note">No managed devices.</p>' }
$CompPolicyTable  = if ($CompPolicySummary.Count -gt 0) { ConvertTo-HtmlTable -Data $CompPolicySummary -Properties Name, Platform, Created, Modified, Description } else { '<p class="empty-note">No compliance policies.</p>' }
$ConfigTable      = if ($ConfigProfileSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $ConfigProfileSummary -Properties Name, Platform, Created, Modified, Description } else { '<p class="empty-note">No configuration profiles.</p>' }
$SettCatTable     = if ($SettingsCatalogSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $SettingsCatalogSummary -Properties Name, Platforms, Technologies, Created, Modified } else { '<p class="empty-note">No Settings Catalog policies.</p>' }
$AppProtTable     = if ($AppProtectionAll.Count -gt 0) { ConvertTo-HtmlTable -Data $AppProtectionAll -Properties Name, Platform, Created, Modified } else { '<p class="empty-note">No app protection policies.</p>' }
$AppTable         = if ($AppSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $AppSummary -Properties Name, Type, Publisher, Created } else { '<p class="empty-note">No mobile apps.</p>' }
$AutopilotTable   = if ($AutopilotProfileSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $AutopilotProfileSummary -Properties Name, Description, Created } else { '<p class="empty-note">No Autopilot profiles.</p>' }
$UpdateRingTable  = if ($UpdateRingSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $UpdateRingSummary -Properties Name, Created, Modified } else { '<p class="empty-note">No Windows Update rings.</p>' }
$EndpointSecTable = if ($EndpointSecSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $EndpointSecSummary -Properties Name, Description, IsAssigned, Created } else { '<p class="empty-note">No endpoint security policies.</p>' }
$BaselineTable    = if ($SecurityBaselines.Count -gt 0) {
    $blData = @()
    foreach ($bl in $SecurityBaselines) {
        $blData += [PSCustomObject]@{
            Name        = if ($bl.displayName) { $bl.displayName } else { $bl.id }
            Description = $bl.description
            Version     = if ($bl.versionInfo) { $bl.versionInfo } else { '--' }
            TemplateType = $bl.templateType
        }
    }
    ConvertTo-HtmlTable -Data $blData -Properties Name, Description, Version, TemplateType
} else { '<p class="empty-note">No security baseline templates.</p>' }
$EnrollTable      = if ($EnrollmentSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $EnrollmentSummary -Properties Name, Type, Priority, Created } else { '<p class="empty-note">No enrollment configurations.</p>' }
$RBACTable        = if ($RBACRoleSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $RBACRoleSummary -Properties Name, Description, IsBuiltIn } else { '<p class="empty-note">No RBAC roles.</p>' }
$ScopeTagTable    = if ($ScopeTagSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $ScopeTagSummary -Properties Name, Description, Id, IsBuiltIn } else { '<p class="empty-note">No scope tags.</p>' }
$FilterTable      = if ($FilterSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $FilterSummary -Properties Name, Platform, Rule, Created } else { '<p class="empty-note">No assignment filters.</p>' }
$DevCatTable = '<p class="empty-note">No device categories.</p>'
if ($DeviceCategories.Count -gt 0) {
    $dcData = @()
    foreach ($dc in $DeviceCategories) { $dcData += [PSCustomObject]@{Name=$dc.displayName;Description=$dc.description} }
    $DevCatTable = ConvertTo-HtmlTable -Data $dcData -Properties Name, Description
}
$ScriptTable      = if ($DeviceScriptSummary.Count -gt 0) { ConvertTo-HtmlTable -Data $DeviceScriptSummary -Properties Name, RunAsAccount, EnforceSignature, RunAs32Bit, Created } else { '<p class="empty-note">No PowerShell scripts.</p>' }
$RemediationTable = if ($RemediationSummary.Count -gt 0) { ConvertTo-HtmlTable -Data ($RemediationSummary | Where-Object { -not $_.IsGlobal }) -Properties Name, Publisher, Created } else { '<p class="empty-note">No custom remediation scripts.</p>' }

# Chart data
$ComplianceJSON = '{"Compliant":' + $CompliantDevices + ',"Non-Compliant":' + $NonCompliant + ',"In Grace Period":' + $InGracePeriod + ',"Unknown":' + $UnknownCompliance + '}'
$OSJSON         = '{"Windows":' + $WindowsDevices + ',"iOS":' + $iOSDevices + ',"Android":' + $AndroidDevices + ',"macOS":' + $macOSDevices + ',"Other":' + $OtherOSDevices + '}'
$OwnerJSON      = '{"Corporate":' + $CorporateDevices + ',"Personal":' + $PersonalDevices + '}'
$MgmtJSON       = '{"MDM":' + $MDMEnrolled + ',"Co-Managed":' + $CoManaged + ',"Other":' + ($TotalDevices - $MDMEnrolled - $CoManaged) + '}'
$AppTypeJSON    = '{' + (($AppsByType.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { '"' + ($_.Key -replace '"','') + '":' + $_.Value }) -join ',') + '}'
if ($AppTypeJSON -eq '{}') { $AppTypeJSON = '{"None":0}' }

$PolicyCountJSON = '{"Compliance":' + $CompliancePolicies.Count + ',"Config Profiles":' + $ConfigProfiles.Count + ',"Settings Catalog":' + $SettingsCatalog.Count + ',"App Protection":' + $AppProtectionAll.Count + ',"Endpoint Security":' + $EndpointSecPolicies.Count + ',"Update Rings":' + @($UpdateRings).Count + '}'

# ==============================================================================
# HTML REPORT
# ==============================================================================
$HTML = @"
<!--
================================================================================
  IntuneCanvas -- Intune Documentation Report
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Author    : Santhosh Sivarajan, Microsoft MVP
  GitHub    : https://github.com/SanthoshSivarajan/IntuneCanvas
================================================================================
-->
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>IntuneCanvas -- $TenantName</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;--text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;--green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;--pink:#f472b6;--orange:#fb923c;--accent-bg:rgba(96,165,250,.1);--radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);--font-body:'Segoe UI',system-ui,-apple-system,sans-serif}
html{scroll-behavior:smooth;font-size:15px}body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}.section{margin-bottom:36px}.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}.card:hover{border-color:var(--accent)}.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px}.info-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;box-shadow:var(--shadow)}.info-label{display:block;font-size:.68rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}.info-value{font-size:.95rem;font-weight:600;color:var(--text)}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;font-size:.78rem}thead{background:var(--accent-bg)}th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}td{padding:7px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:360px;overflow:hidden;text-overflow:ellipsis}tbody tr:hover{background:rgba(96,165,250,.06)}tbody tr:nth-child(even){background:var(--surface2)}.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.exec-summary{background:linear-gradient(135deg,#1e293b 0%,#1e3a5f 100%);border:1px solid #334155;border-radius:var(--radius);padding:22px 26px;margin-bottom:28px;box-shadow:var(--shadow)}.exec-summary h2{font-size:1.1rem;color:var(--accent);margin-bottom:8px}.exec-summary p{color:var(--text-dim);font-size:.86rem;line-height:1.7;margin-bottom:6px}.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}.exec-kv strong{color:var(--accent2)}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}.card,.info-card,.exec-summary{background:#f9f9f9;border-color:#ccc;color:#222}.card-val,.info-value,.section-title{color:#222}th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo"><h2>IntuneCanvas</h2><p>Developed by Santhosh Sivarajan</p><p style="margin-top:6px">Tenant: <strong style="color:#e2e8f0">$TenantName</strong></p></div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="#exec-summary">Executive Summary</a>
    <a href="#devices">Managed Devices</a>
    <div class="nav-group">Policies</div>
    <a href="#compliance">Compliance Policies</a>
    <a href="#config-profiles">Configuration Profiles</a>
    <a href="#settings-catalog">Settings Catalog</a>
    <a href="#endpoint-security">Endpoint Security</a>
    <a href="#update-rings">Windows Update Rings</a>
    <div class="nav-group">Applications</div>
    <a href="#apps">Mobile Apps</a>
    <a href="#app-protection">App Protection</a>
    <div class="nav-group">Enrollment</div>
    <a href="#autopilot">Autopilot</a>
    <a href="#enrollment">Enrollment Config</a>
    <a href="#device-categories">Device Categories</a>
    <div class="nav-group">Automation</div>
    <a href="#scripts">Scripts</a>
    <a href="#remediations">Remediations</a>
    <div class="nav-group">Administration</div>
    <a href="#rbac">RBAC Roles</a>
    <a href="#scope-tags">Scope Tags</a>
    <a href="#filters">Assignment Filters</a>
    <div class="nav-group">Visuals</div>
    <a href="#charts">Charts</a>
  </nav>
</aside>
<main class="main">

<div id="exec-summary" class="section">
  <div class="exec-summary">
    <h2>Executive Summary -- $TenantName</h2>
    <p>Point-in-time documentation of Microsoft Intune for tenant <strong>$TenantName</strong>, generated on <strong>$(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</strong>.</p>
    <p>
      <span class="exec-kv"><strong>Managed Devices:</strong> $TotalDevices</span>
      <span class="exec-kv"><strong>Compliant:</strong> $CompliantDevices</span>
      <span class="exec-kv"><strong>Non-Compliant:</strong> $NonCompliant</span>
      <span class="exec-kv"><strong>Compliance Policies:</strong> $($CompliancePolicies.Count)</span>
      <span class="exec-kv"><strong>Config Profiles:</strong> $($ConfigProfiles.Count)</span>
      <span class="exec-kv"><strong>Settings Catalog:</strong> $($SettingsCatalog.Count)</span>
      <span class="exec-kv"><strong>Endpoint Security:</strong> $($EndpointSecPolicies.Count)</span>
      <span class="exec-kv"><strong>Mobile Apps:</strong> $TotalApps</span>
      <span class="exec-kv"><strong>App Protection:</strong> $($AppProtectionAll.Count)</span>
      <span class="exec-kv"><strong>Autopilot Profiles:</strong> $($AutopilotProfiles.Count)</span>
      <span class="exec-kv"><strong>Autopilot Devices:</strong> $($AutopilotDevices.Count)</span>
      <span class="exec-kv"><strong>Scripts:</strong> $($DeviceScripts.Count)</span>
      <span class="exec-kv"><strong>Remediations:</strong> $($Remediations.Count)</span>
      <span class="exec-kv"><strong>RBAC Roles:</strong> $($RBACRoles.Count)</span>
      <span class="exec-kv"><strong>Filters:</strong> $($Filters.Count)</span>
    </p>
  </div>
</div>

<div id="devices" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128187;</span> Managed Devices</h2>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$TotalDevices</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$CompliantDevices</div><div class="card-label">Compliant</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$NonCompliant</div><div class="card-label">Non-Compliant</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$InGracePeriod</div><div class="card-label">Grace Period</div></div>
    <div class="card"><div class="card-val" style="color:var(--accent2)">$WindowsDevices</div><div class="card-label">Windows</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$iOSDevices</div><div class="card-label">iOS</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$AndroidDevices</div><div class="card-label">Android</div></div>
    <div class="card"><div class="card-val" style="color:var(--text-dim)">$macOSDevices</div><div class="card-label">macOS</div></div>
    <div class="card"><div class="card-val" style="color:var(--orange)">$CorporateDevices</div><div class="card-label">Corporate</div></div>
    <div class="card"><div class="card-val" style="color:var(--pink)">$PersonalDevices</div><div class="card-label">Personal</div></div>
  </div>
  <h3 class="sub-header">Device Inventory (last 100 synced)</h3>
  $DeviceTable
</div>

<div id="compliance" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#9989;</span> Compliance Policies ($($CompliancePolicies.Count))</h2>
  $CompPolicyTable
</div>

<div id="config-profiles" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#9881;</span> Configuration Profiles ($($ConfigProfiles.Count))</h2>
  $ConfigTable
</div>

<div id="settings-catalog" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128221;</span> Settings Catalog ($($SettingsCatalog.Count))</h2>
  $SettCatTable
</div>

<div id="endpoint-security" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128737;</span> Endpoint Security</h2>
  <h3 class="sub-header">Security Baseline Templates ($($SecurityBaselines.Count))</h3>
  $BaselineTable
  <h3 class="sub-header">Endpoint Security Policies ($($EndpointSecPolicies.Count))</h3>
  $EndpointSecTable
</div>

<div id="update-rings" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#128260;</span> Windows Update Rings ($(@($UpdateRings).Count))</h2>
  $UpdateRingTable
</div>

<div id="apps" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128230;</span> Mobile Apps ($TotalApps)</h2>
  $AppTable
</div>

<div id="app-protection" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(244,114,182,.15);color:var(--pink)">&#128274;</span> App Protection Policies ($($AppProtectionAll.Count))</h2>
  $AppProtTable
</div>

<div id="autopilot" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#9992;</span> Windows Autopilot</h2>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$($AutopilotProfiles.Count)</div><div class="card-label">Deployment Profiles</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$($AutopilotDevices.Count)</div><div class="card-label">Registered Devices</div></div>
  </div>
  <h3 class="sub-header">Deployment Profiles</h3>
  $AutopilotTable
</div>

<div id="enrollment" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#128241;</span> Enrollment Configurations ($($EnrollmentConfigs.Count))</h2>
  $EnrollTable
</div>

<div id="device-categories" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,146,60,.15);color:var(--orange)">&#128193;</span> Device Categories</h2>
  $DevCatTable
</div>

<div id="scripts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128221;</span> PowerShell Scripts ($($DeviceScripts.Count))</h2>
  $ScriptTable
</div>

<div id="remediations" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128296;</span> Remediation Scripts</h2>
  $RemediationTable
</div>

<div id="rbac" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128101;</span> RBAC Roles ($($RBACRoles.Count))</h2>
  $RBACTable
</div>

<div id="scope-tags" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#127991;</span> Scope Tags ($($ScopeTags.Count))</h2>
  $ScopeTagTable
</div>

<div id="filters" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128295;</span> Assignment Filters ($($Filters.Count))</h2>
  $FilterTable
</div>

<div id="charts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Charts</h2>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px"></div>
</div>

<div class="footer">
  IntuneCanvas v1.0 -- Intune Documentation Report -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="https://github.com/SanthoshSivarajan">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/IntuneCanvas">github.com/SanthoshSivarajan/IntuneCanvas</a>
</div>
</main>
</div>
<script>
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9'];
function buildBarChart(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8;font-style:italic">No data.</p>';c.appendChild(b);return}var g=document.createElement('div');g.style.cssText='display:flex;flex-direction:column;gap:6px';var e=Object.entries(d),ci=0;for(var i=0;i<e.length;i++){var p=((e[i][1]/tot)*100).toFixed(1);var r=document.createElement('div');r.style.cssText='display:flex;align-items:center;gap:8px';r.innerHTML='<span style="width:110px;font-size:.74rem;color:#94a3b8;text-align:right;flex-shrink:0">'+e[i][0]+'</span><div style="flex:1;height:20px;background:#273548;border-radius:4px;overflow:hidden;border:1px solid #334155"><div style="height:100%;border-radius:3px;width:'+p+'%;background:'+COLORS[ci%COLORS.length]+';display:flex;align-items:center;padding:0 6px;font-size:.66rem;font-weight:600;color:#fff;white-space:nowrap">'+p+'%</div></div><span style="width:44px;font-size:.74rem;color:#94a3b8;text-align:right">'+e[i][1]+'</span>';g.appendChild(r);ci++}b.appendChild(g);c.appendChild(b)}
function buildDonut(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8;font-style:italic">No data.</p>';c.appendChild(b);return}var dc=document.createElement('div');dc.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';var sz=130,cx=65,cy=65,r=48,cf=2*Math.PI*r;var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';var off=0,ci=0,e=Object.entries(d);for(var i=0;i<e.length;i++){var pc=e[i][1]/tot,da=pc*cf,ga=cf-da;s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[ci%COLORS.length]+'" stroke-width="14" stroke-dasharray="'+da.toFixed(2)+' '+ga.toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" />';off+=da;ci++}s+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="central" fill="#e2e8f0" font-size="18" font-weight="700">'+tot+'</text></svg>';dc.innerHTML=s;var lg=document.createElement('div');lg.style.cssText='display:flex;flex-direction:column;gap:3px';ci=0;for(var i=0;i<e.length;i++){var pc=((e[i][1]/tot)*100).toFixed(1);var it=document.createElement('div');it.style.cssText='display:flex;align-items:center;gap:6px;font-size:.74rem;color:#94a3b8';it.innerHTML='<span style="width:10px;height:10px;border-radius:2px;background:'+COLORS[ci%COLORS.length]+';flex-shrink:0"></span>'+e[i][0]+': '+e[i][1]+' ('+pc+'%)';lg.appendChild(it);ci++}dc.appendChild(lg);b.appendChild(dc);c.appendChild(b)}
(function(){var c=document.getElementById('chartsContainer');if(!c)return;
buildDonut('Device Compliance',$ComplianceJSON,c);
buildDonut('Device OS',$OSJSON,c);
buildDonut('Device Ownership',$OwnerJSON,c);
buildDonut('Management Type',$MgmtJSON,c);
buildBarChart('Policy Count by Type',$PolicyCountJSON,c);
buildBarChart('App Types (Top 10)',$AppTypeJSON,c);
})();
(function(){var lk=document.querySelectorAll('.sidebar nav a');var sc=[];for(var i=0;i<lk.length;i++){var id=lk[i].getAttribute('href');if(id&&id.charAt(0)==='#'){var el=document.querySelector(id);if(el)sc.push({el:el,link:lk[i]})}}window.addEventListener('scroll',function(){var cur=sc[0];for(var i=0;i<sc.length;i++){if(sc[i].el.getBoundingClientRect().top<=120)cur=sc[i]}for(var i=0;i<lk.length;i++)lk[i].classList.remove('active');if(cur)cur.link.classList.add('active')})})();
</script>
</body>
</html>
<!--
================================================================================
  IntuneCanvas -- Intune Documentation Report
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/IntuneCanvas
================================================================================
-->
"@

$HTML | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   IntuneCanvas -- Report Generation Complete               |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  INTUNE SUMMARY" -ForegroundColor White
Write-Host "  --------------" -ForegroundColor Gray
Write-Host "    Managed Devices    : $TotalDevices (Compliant: $CompliantDevices, Non-Compliant: $NonCompliant)" -ForegroundColor White
Write-Host "    Compliance         : $($CompliancePolicies.Count) policies" -ForegroundColor White
Write-Host "    Config Profiles    : $($ConfigProfiles.Count)" -ForegroundColor White
Write-Host "    Settings Catalog   : $($SettingsCatalog.Count)" -ForegroundColor White
Write-Host "    Endpoint Security  : $($EndpointSecPolicies.Count) policies" -ForegroundColor White
Write-Host "    Mobile Apps        : $TotalApps" -ForegroundColor White
Write-Host "    App Protection     : $($AppProtectionAll.Count)" -ForegroundColor White
Write-Host "    Autopilot          : $($AutopilotProfiles.Count) profiles, $($AutopilotDevices.Count) devices" -ForegroundColor White
Write-Host "    Scripts            : $($DeviceScripts.Count)" -ForegroundColor White
Write-Host "    Remediations       : $($Remediations.Count)" -ForegroundColor White
Write-Host "    RBAC Roles         : $($RBACRoles.Count)" -ForegroundColor White
Write-Host ""
Write-Host "  OUTPUT" -ForegroundColor White
Write-Host "  ------" -ForegroundColor Gray
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using IntuneCanvas v1.0         |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/IntuneCanvas         |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

<#
================================================================================
  IntuneCanvas v1.0 -- Intune Documentation Report Generator
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/IntuneCanvas
================================================================================
#>
