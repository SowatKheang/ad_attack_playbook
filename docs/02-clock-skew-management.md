---
title: "02 · Clock Skew Management"
---

# 02 · Clock Skew Management

> **Kerberos** refuses tickets when clocks drift more than 5 minutes. faketime is the universal fix.

!!! note "Phase overview"
    `Kerberos` uses timestamps to prevent replay attacks. Your ATTACK box and the DC must agree on the time within 5 minutes and HTB/lab boxes are notorious for drifting hours off. Symptoms: `'KRB_AP_ERR_SKEW (Clock skew too great)'` or vague `'kerberos error'` messages. Don't change your system clock (it breaks everything else); use faketime to spoof time per-command.

```bash
# Sync The DateTime
sudo ntpdate <TARGET_IP>

# Or rdate (RFC 868) is a simplerolder protocol that does not 
# calculate network delay, making it less accurate than ntpdate. 
sudo rdate <TARGET_IP>
```

### 2.1 · Measuring & Applying Clock Skew

!!! info "Why this works / how it chains"

    - **Step 1** is to find the offset by asking the DC for any TGT (it returns its server time even on auth failure). 
    - **Step 2** is wrapping every Kerberos-touching command in faketime. Note that delegation/S4U attacks sometimes need a NEGATIVE offset of a few seconds, when forging tickets, you want the ticket's start time to be slightly in the past so it's already valid when the DC checks it.

```bash title="Measure offset"
# Some examples:
# Check ticket timestamps
klist
# Valid starting: 00:33:38  Expires: 04:33:38

# Measure DC time offset
DC_TIME=$(impacket-getTGT -debug 'domain.local/user:pass' \
  -dc-ip <IP> 2>&1 | grep -oP 'Server time \(UTC\): \K.*')
LOCAL_TIME=$(date -u +"%Y-%m-%d %H:%M:%S")
DELTA=$(( $(date -u -d "$DC_TIME" +%s) - $(date -u -d "$LOCAL_TIME" +%s) ))
echo "Offset: ${DELTA} seconds"
```

```bash title="Apply faketime"
# Apply with faketime
faketime -f "+7h" <command>      # positive offset
faketime '-7 seconds' <command>  # negative offset
faketime "+2h30m" <command>      # hours and minutes

# ALL Kerberos commands need faketime when skew exists
KRB5CCNAME=user.ccache faketime -f "+7h" \
  bloodyAD -u user -k -d domain.local --host dc01 <cmd>

faketime -f "+7h" certipy-ad <cmd> -k -no-pass
faketime -f "+7h" impacket-getTGT domain.local/user:pass -dc-ip <IP>
```

