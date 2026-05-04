---
title: "★ · Quick Reference: Tools & Hash Modes"
---

# ★ · Quick Reference: Tools & Hash Modes

> Tools by phase + hashcat hash modes.

!!! note "Phase overview"
    When you forget which mode is Kerberoast vs ASREPRoast, look here.

### ref.1 · Tools by Category


## Enumeration
`nmap`, `crackmapexec/netexec`, `bloodhound-python`, `ldapsearch`
`rpcclient`, `enum4linux-ng`, `kerbrute`, `windapsearch`
`sccmhunter`, `SharpSCCM`, `LAPSToolkit`, `Snaffler`

## Exploitation
`impacket suite`, `bloodyAD`, `certipy-ad`, `evil-winrm`
`PKINITtools` (gettgtpkinit, getnthash)
`pyWSUS`, `stunnel`, `chisel`, `proxychains4`
`PetitPotam`, `printerbug`, `coercer`
`PXEThief`, `SCCMSecrets`, `gMSADumper`

## Windows (on-box)
`mimikatz`, `Rubeus`, `SharpHound`, `PowerView`, `PowerUp`
`WinPEAS`, `GodPotato`, `PrintSpoofer`, `SharpSCCM`
`Snaffler.exe`, `SharpDump`

## Cracking
`hashcat`, `john`

... ADD MORE ...


### ref.2 · Hashcat Hash Modes

``` title="AD-relevant modes"
-m 13100 = Kerberoast (TGS-REP)
-m 18200 = ASREPRoast (AS-REP)
-m 5600  = NTLMv2 (Net-NTLMv2)
-m 1000  = NTLM hash
-m 19850 = PXE boot password (SCCM)
-m 7500  = Kerberos AS-REQ pre-auth
```

