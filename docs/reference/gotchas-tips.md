---
title: "★ · Gotchas & Tips"
---

# ★ · Gotchas & Tips

> The hard-won lessons from real boxes.

!!! note "Phase overview"
    Each item below is a footgun that costs hours when you discover it the hard way. Read this section before you start, not after you're stuck.

### gotchas.1 · LAPS gotchas

``` title="LAPS"
- BloodHound edge ReadLAPSPassword = direct read
- BloodHound edge SyncLAPSPassword = DirSync API (different!)
- Account that JOINED computer to domain = implicit AllExtendedRights
- Windows LAPS (2023+) uses msLAPS-* attributes, not ms-Mcs-AdmPwd
- LAPS on DC = DSRM password backup (msLAPS-EncryptedDSRMPassword)
```


### gotchas.2 · GPP gotchas

``` title="GPP"
- MS14-025 only prevents NEW cpasswords, doesn't remove existing
- AES key is publicly known = any domain user can decrypt
- Search: findstr /S /I cpassword \\domain\sysvol\domain\policies\*.xml
```


### gotchas.3 · SCCM gotchas

``` title="SCCM"
- NAA account often has local admin on ALL managed machines
- Even after removing NAA from SCCM, it's still cached on clients
- PXE without password = instant credential compromise
- Client push account = local admin on all clients
```


### gotchas.4 · DSRM gotchas

``` title="DSRM"
- Every DC has DSRM password - survives everything except explicit rotation
- DsrmAdminLogonBehavior=2 needed for network logon
- Use .\administrator (local) not domain\administrator
```


### gotchas.5 · Coercion gotchas

``` title="Coercion"
- PrinterBug = most reliable but requires Print Spooler running
- PetitPotam = works unauth on unpatched (<2021) systems
- coercer.py tests 12+ protocols automatically
- WebDAV coercion bypasses SMB signing (auth goes over HTTP)
```


### gotchas.6 · Trust gotchas

``` title="Trust"
- SID filtering OFF within same forest (ExtraSids works)
- SID filtering ON by default across forest trusts (may block)
- Trust keys are stored like regular secrets - DCSync extracts them
- MSSQL links work across ALL forest trusts
```


### gotchas.7 · LOGGING HTB lessons

``` title="LOGGING HTB"
- DLL must be 32-bit if process has "Prefer 32-bit" .NET flag
- certreq needs -f (force) and < NUL (no prompts) or hangs forever
- Error 193 = wrong arch, Error 126 = missing/wrong DLL
- Deliver DLL via ZIP if service extracts then loads
- WSUS HTTPS needs CA-signed cert (self-signed = SSL error)
```


### gotchas.8 · PINGPONG HTB lessons

``` title="PINGPONG HTB"
- Kerberos-only means faketime on EVERY ticket operation
- Cross-realm enrollment: stock Certipy fails → use 0xlazY/trust_fix
- Strong cert mapping (KB5014754): always use -sid for ESC1
- Pre-cache referral + service tickets for cross-forest tools
- JEA: Write-Warning stream often bypasses output filtering
- PSReadLine history = goldmine for credentials
- Group type: Global → Universal → DomainLocal for foreign SIDs
- BUILTIN\Administrators on DC = implicit DCSync rights
- Owner of object ≠ member, but owner has implicit WriteDACL
```

