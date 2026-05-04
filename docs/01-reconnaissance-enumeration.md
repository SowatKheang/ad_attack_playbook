---
title: "01 · Reconnaissance & Enumeration"
---

# 01 · Reconnaissance & Enumeration

> Map the attack surface before touching anything. Every open port is a hypothesis about what the network runs and what attacks become possible.

!!! note "Phase overview"
    Recon is not a checklist; it's a hypothesis-building exercise. Each open port, DNS record, and SMB share narrows down which attack chains are viable. The Port → Attack Surface map below tells you which phase to jump to once you know what's running. Skip this phase and you'll waste hours brute-forcing a domain that has anonymous LDAP enabled.

### 1.1 · Network Discovery

!!! info "Why this works / how it chains"

    **Goal**: find live hosts and confirm you're looking at a Windows AD environment. Port 88 (Kerberos) is the giveaway, if it's open, you've found a Domain Controller and the entire AD attack surface unlocks. Run a fast TCP sweep first, then UDP top-100 separately because UDP scans are slow and you don't want to block on them.

```bash title="Live host + port discovery"

netdiscover -r <IP>/24

nmap -sn <IP>/24

nmap -sC -sV -p- --min-rate 5000 -T4 -oA nmap/full <IP>

nmap -sU --top-ports 100 -oA nmap/udp <IP>
```

!!! success "Leads to →"
    - For Example
        - Port **88** open         → Domain Controller confirmed → switch to AD attack mindset
        - Port **8530/8531** open  → `WSUS` present → check Phase 10 (Fake WSUS)
        - Port **80/443** open     → check /certsrv for ADCS web enrollment → Phase 5
        - Port **1433** open       → `MSSQL` → potential xp_cmdshell + SeImpersonate path → Phase 11/12


### 1.1b · Port → Attack Surface Map

!!! info "Why this works / how it chains"

    Use this as a lookup table. After your nmap scan, every open port maps to a specific later phase. Memorize the high-value ones: 88, 389, 445, 5985.

``` title="Port → next step"
Port 53        → DNS        → zone transfer, domain enum, missing records = DNS spoofing
Port 88        → Kerberos   → DC confirmed, AS-REP/Kerberoast, PKINIT
Port 135       → RPC        → rpcclient enum
Port 139/445   → SMB        → shares, relay, null session
Port 389/636   → LDAP       → domain enum, description fields
Port 464       → Kpasswd    → password change
Port 3268/3269 → GC         → forest info, cross-forest enum
Port 5985/5986 → WinRM      → shell if creds found, JEA endpoints
Port 3389      → RDP        → GUI if creds
Port 80/443    → Web        → ADCS /certsrv, IIS apps
Port 1433      → MSSQL      → xp_cmdshell, linked servers, SeImpersonate
Port 8530      → WSUS HTTP  → fake WSUS attack
Port 8531      → WSUS HTTPS → fake WSUS attack (needs CA-signed cert)
```

!!! tip "Thought process: for example"
    - Port 88         = DC confirmed → AD mindset. 
    - Port 8530/8531  = WSUS → check if DNS record exists. 
    - Port 80/443     = check /certsrv for ADCS. 
    - Port 1433       = MSSQL → check SeImpersonate after login.


### 1.2 · DNS Enumeration

!!! info "Why this works / how it chains"

    `DNS` gives you the domain name (needed for every Kerberos request) and reveals subdomains/services that nmap won't show. Zone transfers are rare in production but free wins when they work. The big payoff: if a service hostname (like wsus.domain.local) has NO DNS record and you can write to AD-integrated DNS later, you can spoof that service : see Phase 10.

```bash title="DNS recon"
nslookup -type=any domain.local <IP>

dig @<IP> domain.local ANY

dig @<IP> domain.local AXFR   # Zone transfer attempt

gobuster dns -d domain.local -r <IP> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

nslookup <IP> <IP>

echo "<IP> domain.local dc01.domain.local" >> /etc/hosts
```

!!! success "Leads to →"
    - Zone transfer works → full DNS map → all hostnames
    - DC hostname found → add to /etc/hosts → Kerberos attacks now resolve correctly
    - Missing DNS records → DNS spoofing opportunity (WSUS, SCCM, etc.)
    - Multiple DCs / forests → cross-forest attack surface (Phase 8/19)


### 1.3 · SMB Enumeration

!!! info "Why this works / how it chains"

    `SMB` is the most under-rated initial-access path. Two things to extract: signing status (signing:False = NTLM relay viable, see Phase 3.3) and share contents. Shares routinely contain GPP passwords, web.config files with DB connection strings, deployment scripts with hardcoded creds, and PowerShell history files. Always try null session and guest before assuming you need creds.

```bash title="SMB enum + share crawl"
# For example use nxc (former crackmapexec)

nxc smb <IP>
# Returns: hostname, domain, OS, SMB signing status

nxc smb <IP> -u '' -p '' --shares

nxc smb <IP> -u 'guest' -p '' --shares

smbmap -H <IP> -u '' -p ''

smbclient //<IP>/sharename -N

smbclient //<IP>/sharename -N -c 'recurse ON; prompt OFF; mget *'

smbmap -H <IP> -u '' -p '' -R --depth 5
```

!!! success "Leads to →"
    - config files → hardcoded credentials → Phase 4
    - scripts (.ps1/.bat) → credentials, domain info
    - web.config → DB connection strings → MSSQL access (Phase 11.4)
    - ticket/incident HTML → attack hints (WSUS endpoints, hostnames)
    - PSReadLine history → command history with credentials → Phase 7
    - SMB signing disabled → NTLM relay viable → Phase 3.3 / Phase 23


### 1.4 · LDAP Enumeration

!!! info "Why this works / how it chains"

    `LDAP` is the domain's internal phone book. The single most valuable attribute is description; admins routinely stash temporary passwords there and forget. Always check anonymous bind first; many environments allow it. Look for gMSA accounts (msDS-GroupManagedServiceAccount), they're often readable by groups you can reach (Phase 6). Group ownership matters more than membership: an owner has implicit WriteDACL.

```bash title="LDAP queries"
# Anonymous bind check
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local"

# All users + descriptions (CRITICAL - often has passwords)
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" \
  "(objectClass=user)" sAMAccountName description

# gMSA accounts
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" \
  "(objectClass=msDS-GroupManagedServiceAccount)" sAMAccountName

# With credentials
ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" \
  -D "user@domain.local" -w "pass" "(objectClass=user)"

windapsearch -m users --dc <IP> -d domain.local
windapsearch -m privileged-users --dc <IP> -d domain.local
```

!!! tip "Thought process"
    Always check description field, admins put temp passwords there. Look for gMSA accounts, they may be exploitable. Check group ownership vs membership.


### 1.5 · RPC Enumeration

!!! info "Why this works / how it chains"

    `RPC` null sessions still work surprisingly often, especially on legacy or misconfigured DCs. The crucial command is getdompwinfo; it returns the lockout threshold. You MUST run this before any password spraying or you'll lock out half the domain and get caught immediately.

```bash title="rpcclient session"
rpcclient -U "" -N <IP>
  > enumdomusers        # full user list
  > enumdomgroups       # all groups
  > getdompwinfo        # lockout policy - CRITICAL before spraying
  > querydispinfo       # user details
  > queryuser 0x1f4     # specific user by RID
  > lsaenumsid          # enumerate SIDs
```


### 1.6 · User Enumeration (No Creds)

!!! info "Why this works / how it chains"

    Kerberos preauth leaks user existence, sending an AS-REQ for a non-existent user returns a different error than for a real one. kerbrute exploits this without ever attempting a login, so it's silent and doesn't lock accounts. The output (a list of valid usernames) becomes your input for ASREPRoasting and password spraying.

```bash title="Username harvesting"
kerbrute userenum \
  -d domain.local --dc <IP> \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -o valid_users.txt

nxc smb <IP> -u '' -p '' --rid-brute 10000
impacket-lookupsid domain.local/guest@<IP> -no-pass | grep SidTypeUser

ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" \
  "(objectClass=user)" sAMAccountName | grep sAMAccountName
```

!!! success "Leads to →"
    - Valid user list → `ASREPRoasting` (Phase 3.1)
    - Valid user list → `Password spraying` (Phase 3.2)


### 1.7 · Kerberos Config (krb5.conf)

!!! info "Why this works / how it chains"

    Every Kerberos-aware tool reads /etc/krb5.conf. Get this wrong and you'll see opaque 'KDC not found' or 'realm unknown' errors. The realm MUST be uppercase. For multi-forest engagements (Phase 8 / Phase 19), add every realm here so you can request cross-realm referrals without hand-passing -dc-ip everywhere.

```bash title="Single-realm krb5.conf"
# /etc/krb5.conf
cat > /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
EOF
```

```ini title="Multi-forest realms"
# For multi-forest (PINGPONG style):
[realms]
    PING.HTB = {
        kdc = dc1.ping.htb
        admin_server = dc1.ping.htb
    }
    PONG.HTB = {
        kdc = dc2.pong.htb
        admin_server = dc2.pong.htb
    }
```

