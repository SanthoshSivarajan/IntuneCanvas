# IntuneCanvas

### Paint the Full Picture of Your Intune Environment

**Author:** Santhosh Sivarajan, Microsoft MVP
**GitHub:** [https://github.com/SanthoshSivarajan/IntuneCanvas](https://github.com/SanthoshSivarajan/IntuneCanvas)

---

## Overview

IntuneCanvas is a single PowerShell script that queries your Microsoft Intune environment via Microsoft Graph and generates a **self-contained HTML report**. Covers managed devices, compliance policies, configuration profiles, apps, Autopilot, endpoint security, enrollment, RBAC, scripts, and more.

Run one script. Open one HTML file. See everything.

## Quick Start

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
.\IntuneCanvas.ps1
```

## What IntuneCanvas Collects

### Devices
- Total managed devices with compliance state (compliant, non-compliant, in grace period)
- OS breakdown (Windows, iOS, Android, macOS)
- Ownership (corporate vs personal)
- Management type (MDM, co-managed)
- Device inventory table (top 100 by last sync) with encryption status

### Policies
- **Compliance Policies** -- all policies with platform and dates
- **Configuration Profiles** -- all profiles with platform type
- **Settings Catalog** -- all policies with platforms and technologies
- **Endpoint Security** -- security baseline templates and policies
- **Windows Update Rings** -- all update ring configurations

### Applications
- **Mobile Apps** -- all apps categorized by type (Win32, MSI, iOS Store, web, etc.)
- **App Protection Policies** -- Android and iOS MAM policies

### Enrollment
- **Windows Autopilot** -- deployment profiles and registered device count
- **Enrollment Configurations** -- restrictions, ESP, limits
- **Device Categories** -- all configured categories

### Automation
- **PowerShell Scripts** -- deployed scripts with run-as and signature settings
- **Remediation Scripts** -- proactive remediation scripts (custom only)

### Administration
- **RBAC Roles** -- all role definitions (built-in and custom)
- **Scope Tags** -- all scope tags
- **Assignment Filters** -- all filters with platform and rules

### Charts (6)
- Device Compliance (donut)
- Device OS Distribution (donut)
- Device Ownership (donut)
- Management Type (donut)
- Policy Count by Type (bar)
- App Types (bar)

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- **Microsoft.Graph PowerShell module**
- Intune Administrator or Global Reader role

### Required Graph Permissions (all read-only)

```
DeviceManagementManagedDevices.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementApps.Read.All
DeviceManagementServiceConfig.Read.All
DeviceManagementRBAC.Read.All
Directory.Read.All
Organization.Read.All
```

## Usage

```powershell
.\IntuneCanvas.ps1
.\IntuneCanvas.ps1 -OutputPath C:\Reports
```

## Error Handling

- Each API call is independently wrapped -- partial failures produce partial reports
- Beta API endpoints used where v1.0 doesn't expose data (Autopilot, Settings Catalog, etc.)
- Console output shows exactly what was collected and what was skipped

## Related Projects

- [ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas) -- Active Directory documentation
- [EntraIDCanvas](https://github.com/SanthoshSivarajan/EntraIDCanvas) -- Entra ID documentation

## License

MIT -- Free to use, modify, and distribute.

---

*Developed by Santhosh Sivarajan, Microsoft MVP*
