---
title: "★ · Attack Decision Tree"
---

# ★ · Attack Decision Tree

> What's your starting position? Follow the branches.

!!! note "Phase overview"
    The complete map. Find your current state on the left and trace the chain to the right. Every leaf is a phase you can jump into.

### tree.1 · Complete Decision Tree

!!! info "Why this works / how it chains"

    Read this top-to-bottom by your current access level. Each branch is an exhaustive list of options at that stage; pick the one whose prerequisites match your enumeration data.

``` title="Decision tree"
START
│
├── No Creds
│   ├── DNS enum     → missing records → DNS spoofing (WSUS/SCCM/etc)
│   ├── LDAP anon    → description fields → cleartext pass
│   ├── SMB null     → shares → GPP passwords (SYSVOL) → CREDS
│   ├── SMB null     → shares → config files → CREDS
│   ├── Kerbrute     → valid users list
│   ├── ASREPRoast   → crack → CREDS
│   ├── Password spray (check policy first!) → CREDS
│   ├── Pre-2000 computer accounts              → default passwords
│   ├── PXE boot (SCCM) → NAA credentials  → CREDS
│   ├── IPv6 mitm6      → relay → CREDS/SHELL
│   └── NTLM relay (signing disabled) → SHELL
│
├── Low Priv CREDS
│   ├── BloodHound FIRST        → map all paths
│   ├── Snaffler                → share credential hunting
│   ├── GPP passwords (SYSVOL)  → local admin creds
│   ├── Kerberoast              → service accounts → crack
│   ├── LDAP descriptions       → more creds
│   ├── SMB                     → sensitive files, incident tickets
│   ├── ACL abuse → GenericAll/Write  → escalate
│   ├── Shadow Credentials (GenericWrite on user/computer/gMSA)
│   ├── RBCD (GenericWrite on computer)
│   ├── LAPS read (ReadLAPSPassword/AllExtendedRights on computer)
│   ├── Constrained/Unconstrained delegation
│   ├── Coercion → relay → LDAP/ADCS
│   ├── AD CS    → certipy find → ESC1-13
│   │   ├── ESC1 → EnrolleeSuppliesSubject → cert as admin
│   │   ├── ESC2 → Any Purpose EKU → enrollment agent
│   │   ├── ESC3 → Enrollment Agent → on-behalf-of
│   │   ├── ESC4 → WriteDACL on template → modify → ESC1
│   │   ├── ESC6 → CA flag → any template becomes ESC1
│   │   ├── ESC7 → CA Manager → approve/issue certs
│   │   ├── ESC8 → HTTP relay → machine cert → DCSync
│   │   ├── ESC9/10 → Weak mapping → UPN swap
│   │   ├── ESC11 → RPC relay
│   │   └── ESC13 → OID group link → PAC injection
│   ├── gMSA  → ReadGMSAPassword → derive keys
│   ├── SCCM  → NAA credentials → local admin everywhere
│   └── MSSQL → xp_cmdshell → SHELL
│
├── Code Execution (non-admin)
│   ├── Decompile binaries     → find DLL load patterns
│   ├── DLL hijack             → service/task user
│   ├── Check scheduled tasks  → what user/privilege
│   ├── Check WSUS config      → DNS missing → spoof → SYSTEM
│   ├── Log files              → service behavior clues
│   ├── PSReadLine history     → credentials
│   └── JEA endpoint           → stream bypass → credentials
│
├── Local Admin / Shell
│   ├── WinPEAS        → privesc paths
│   ├── SeImpersonate  → GodPotato/PrintSpoofer → SYSTEM
│   ├── Dump LSASS     → mimikatz → CREDS
│   ├── SCCM client    → NAA via DPAPI → CREDS
│   ├── Unquoted service path → SYSTEM
│   ├── AlwaysInstallElevated → SYSTEM
│   └── cmdkey stored creds   → CREDS
│
├── WSUS Present
│   ├── Check WUServer registry
│   ├── Check if DNS resolves
│   ├── No DNS      → bloodyAD add dnsRecord → fake WSUS
│   ├── HTTPS WSUS  → need CA-signed cert (ESC1)
│   ├── stunnel (HTTPS) + pyWSUS (HTTP)
│   └── Trigger wuauclt + usoclient → SYSTEM
│
├── SCCM Present
│   ├── Enumerate: sccmhunter find
│   ├── NAA via HTTP module (MAQ exploit)
│   ├── PXE boot abuse       → NAA/task sequence creds
│   ├── Client push capture  → local admin account
│   ├── Deploy application   → lateral movement
│   └── Site takeover via NTLM relay → DA
│
├── Cross-Forest
│   ├── Check trust type (bidirectional?)
│   ├── Child                → Parent via ExtraSids (Golden Ticket)
│   ├── Forest trust ticket  → cross-forest access
│   ├── MSSQL linked servers → cross-forest execution
│   ├── WriteDACL on templates   → ESC4 → ESC1
│   ├── gMSA Managers group type → add foreign SID
│   └── Chisel SOCKS pivot for internal subnets
│
├── Domain Admin
│   ├── DCSync → all hashes (krbtgt → Golden Ticket)
│   ├── Golden Ticket → 10-year persistence
│   ├── Silver Ticket → stealthy service access
│   ├── AdminSDHolder → ACL persistence
│   ├── DSRM          → local backdoor on DC
│   ├── Skeleton Key  → any-password backdoor
│   ├── DCShadow      → stealthy attribute modification
│   └── Cross-forest  → pivot to other forests
│
└── Azure AD Hybrid
    ├── Azure AD Connect server → adconnectdump → MSOL creds → DCSync
    ├── PTA Spy → intercept all Azure AD logons
    └── MSOL_ account → DCSync equivalent

... ADD MORE ...
```

