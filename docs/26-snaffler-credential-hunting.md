---
title: "26 · Snaffler / Credential Hunting"
---

# 26 · Snaffler / Credential Hunting

> Automate the search for credentials hiding in shares.

!!! note "Phase overview"
    Once you have any domain user, point Snaffler at every share in the domain. It searches for files matching credential patterns (config files, private keys, KeePass DBs, RDP files, unattend.xml). Always faster and more thorough than manual share crawling.

### 26.1 · Snaffler (Automated Credential Search)

!!! info "Why this works / how it chains"

    Snaffler is a tuned regex/path engine for finding sensitive files at scale. Run it from a domain-joined machine for max coverage. The netexec snaffler module is the Linux-side equivalent.

```powershell title="Snaffler invocation + targets"
# Windows (from domain-joined machine)
.\Snaffler.exe -s -d domain.local -o snaffler_output.log -v data

# Kali (via NetExec)
nxc smb <IP>/24 -u user -p pass -M snaffler

# Look for:
# - web.config (DB connection strings)
# - *.config (app config files)
# - id_rsa, *.pem, *.pfx (private keys)
# - *.kdbx (KeePass databases)
# - *.rdp (RDP saved credentials)
# - *.ps1, *.bat with credentials
# - unattend.xml (sysprep credentials)
# - *.vnc (VNC passwords)
```


### 26.2 · Manual Share Credential Hunting

!!! info "Why this works / how it chains"

    When Snaffler isn't available or you want targeted hunting. netexec spider_plus and grep modules let you search file content for password strings. SYSVOL/NETLOGON are always worth crawling; GPP cpasswords (Phase 16) and login scripts.

```bash title="Spider + grep + targeted file hunts"
# Find all shares
nxc smb <IP>/24 -u user -p pass --shares

# Spider specific share
nxc smb <IP> -u user -p pass -M spider_plus \
  --share SHARENAME

# Search for password strings in files
nxc smb <IP> -u user -p pass -M grep \
  -o PATTERN="password" SHARE="SHARENAME"

# Common files to hunt:
# SYSVOL: groups.xml, scheduledtasks.xml (GPP passwords)
# NETLOGON: scripts with hardcoded creds
# IT shares: deployment scripts, config files
# Home drives: notes, scripts, KeePass databases

# Unattend.xml (sysprep leftover - often has admin password)
findstr /si password \\domain.local\netlogon\*.xml
findstr /si password C:\Windows\Panther\unattend.xml
findstr /si password C:\Windows\system32\sysprep\sysprep.xml
```

