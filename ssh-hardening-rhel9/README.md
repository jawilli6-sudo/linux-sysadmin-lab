# SSH Hardening Lab — RHEL 9 (DISA STIG)

![OS](https://img.shields.io/badge/OS-RHEL%209-red?style=flat-square&logo=redhat)
![Compliance](https://img.shields.io/badge/Compliance-DISA%20STIG-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)
![Last Updated](https://img.shields.io/badge/Updated-June%202026-lightgrey?style=flat-square)

## Overview

This lab hardens the OpenSSH daemon (`sshd`) on a baseline RHEL 9 system to meet
DISA STIG compliance requirements. The project begins with zero prior configuration —
a default post-install SSH state — and applies systematic hardening aligned to 13
STIG controls covering authentication, encryption, session management, and logging.

A before/after compliance delta is documented using `sshd -T` output comparison
and manual STIG control verification.

**Lab Environment**
- OS: Red Hat Enterprise Linux 9.x (VirtualBox)
- Starting state: Default post-install SSH configuration, no prior hardening
- Privilege model: Standard user account with `sudo` access

---

## Security Rationale

SSH is the primary remote administration vector on Linux systems and one of the
most frequently targeted attack surfaces. A default `sshd` configuration permits
several conditions that DISA explicitly prohibits for government systems:

- Root can log in directly over SSH (eliminates accountability — no audit trail)
- Weak cipher algorithms may be negotiated by a client
- Sessions have no idle timeout (persistent access if a session is abandoned)
- No legal warning banner is presented prior to authentication
- Failed authentication attempts are not bounded

This lab closes each of these gaps using FIPS 140-2 approved algorithms and
STIG-mandated configuration values.

---

## STIG Controls Implemented

| STIG ID | Control Title | Setting Applied |
|---|---|---|
| V-257778 | SSH must not permit root login | `PermitRootLogin no` |
| V-257757 | SSH must not permit empty passwords | `PermitEmptyPasswords no` |
| V-257758 | SSH must use only approved ciphers | `Ciphers aes128-ctr,aes192-ctr,aes256-ctr,...` |
| V-257759 | SSH must use only approved MACs | `MACs hmac-sha2-256,hmac-sha2-512,...` |
| V-257760 | SSH must use only approved key exchange | `KexAlgorithms ecdh-sha2-nistp256,...` |
| V-257761 | SSH idle timeout must be configured | `ClientAliveInterval 600` |
| V-257762 | SSH idle count must be set to zero | `ClientAliveCountMax 0` |
| V-257763 | SSH login grace time must be limited | `LoginGraceTime 60` |
| V-257764 | SSH max authentication attempts must be limited | `MaxAuthTries 3` |
| V-257765 | SSH must display a legal warning banner | `Banner /etc/issue` |
| V-257766 | SSH must not permit user environment | `PermitUserEnvironment no` |
| V-257767 | SSH X11 forwarding must be disabled | `X11Forwarding no` |
| V-257768 | SSH must use privilege separation | `UsePrivilegeSeparation sandbox` |
| V-257769 | SSH must log user connections | `LogLevel VERBOSE` |

> **Note:** Verify control IDs against the current DISA STIG for RHEL 9 at
> [public.cyber.mil/stigs](https://public.cyber.mil/stigs/) as IDs may be revised
> between STIG releases.

---

## Prerequisites

```bash
# Verify RHEL 9 and SSH version
cat /etc/redhat-release
ssh -V

# Confirm you have sudo access
sudo -l | grep -i ssh

# Confirm sshd is running
systemctl status sshd
```

Expected output confirms: RHEL 9.x, OpenSSH 8.7+, sshd active and running.

---

## Implementation

### Step 1 — Capture Baseline (Before State)

Before touching anything, document the current configuration. This is your audit
trail proving you started from a default state.

```bash
# Capture full sshd runtime configuration
sudo sshd -T | tee ~/ssh_baseline_before.txt

# Check current cipher configuration
sudo sshd -T | grep -E "ciphers|macs|kexalgorithms"

# Check authentication and session controls
sudo sshd -T | grep -E "permitrootlogin|permitemptypasswords|maxauthtries|logingracetime"

# Check timeout settings
sudo sshd -T | grep -E "clientalive|x11forwarding|banner|loglevel"

# Record current file state
sudo cp /etc/ssh/sshd_config ~/sshd_config_original_backup_$(date +%Y%m%d).bak
echo "Backup created: ~/sshd_config_original_backup_$(date +%Y%m%d).bak"
```

Save this output. It becomes your "before" documentation.

---

### Step 2 — Apply Hardening Script

```bash
# Download or copy the hardening script to your system
# Make it executable
chmod +x hardening_script.sh

# Review before executing (never run scripts you haven't read)
cat hardening_script.sh

# Execute with sudo
sudo bash hardening_script.sh
```

The script will:
1. Back up the current `/etc/ssh/sshd_config` with a timestamped copy
2. Apply all 14 STIG controls
3. Validate the configuration with `sshd -t`
4. Restart the `sshd` service
5. Confirm the service is running

---

### Step 3 — Verify Configuration (After State)

```bash
# Validate no syntax errors in the new config
sudo sshd -t && echo "CONFIG VALID" || echo "CONFIG ERROR — check syntax"

# Verify STIG controls applied
echo "=== ROOT LOGIN ===" && sudo sshd -T | grep permitrootlogin
echo "=== EMPTY PASSWORDS ===" && sudo sshd -T | grep permitemptypasswords
echo "=== CIPHERS ===" && sudo sshd -T | grep ciphers
echo "=== MACS ===" && sudo sshd -T | grep "^macs"
echo "=== KEX ALGORITHMS ===" && sudo sshd -T | grep kexalgorithms
echo "=== CLIENT ALIVE INTERVAL ===" && sudo sshd -T | grep clientaliveinterval
echo "=== CLIENT ALIVE COUNT ===" && sudo sshd -T | grep clientalivecountmax
echo "=== LOGIN GRACE TIME ===" && sudo sshd -T | grep logingracetime
echo "=== MAX AUTH TRIES ===" && sudo sshd -T | grep maxauthtries
echo "=== BANNER ===" && sudo sshd -T | grep banner
echo "=== X11 FORWARDING ===" && sudo sshd -T | grep x11forwarding
echo "=== LOG LEVEL ===" && sudo sshd -T | grep loglevel

# Confirm sshd is running after restart
systemctl status sshd --no-pager | head -20

# Verify banner file exists and has content
cat /etc/issue
```

---

### Step 4 — Functional Verification

Confirm SSH still accepts legitimate connections after hardening (critical —
locking yourself out defeats the purpose).

```bash
# From a DIFFERENT terminal or session — do not close current one
ssh -v localhost

# Should connect successfully; verify banner appears before authentication prompt
# Look for: "Authorized uses only..."
```

---

## Before vs. After Comparison

| Control | Before (Default) | After (STIG Hardened) |
|---|---|---|
| PermitRootLogin | `prohibit-password` | `no` |
| PermitEmptyPasswords | `no` *(default)* | `no` *(explicit)* |
| Ciphers | negotiated (includes weak) | FIPS-approved only |
| MACs | negotiated (includes hmac-sha1) | hmac-sha2-256, hmac-sha2-512 only |
| ClientAliveInterval | `0` (no timeout) | `600` (10 minutes) |
| ClientAliveCountMax | `3` | `0` |
| LoginGraceTime | `120` | `60` |
| MaxAuthTries | `6` | `3` |
| Banner | `none` | `/etc/issue` |
| X11Forwarding | `yes` | `no` |
| LogLevel | `INFO` | `VERBOSE` |
| PermitUserEnvironment | `no` *(default)* | `no` *(explicit)* |

**Key risk closures:**
- Root login blocked — all admin access now requires privilege escalation via `sudo`, creating a full audit trail
- Idle sessions terminated after 10 minutes — prevents abandoned session exploitation
- Authentication window cut in half (120s → 60s) — reduces automated brute-force window
- Only FIPS 140-2 approved algorithms accepted — eliminates weak cipher negotiation attacks

---

## Rollback Procedure

If hardening causes access issues, restore from backup:

```bash
# Restore original configuration
sudo cp ~/sshd_config_original_backup_YYYYMMDD.bak /etc/ssh/sshd_config

# Validate syntax
sudo sshd -t

# Restart service
sudo systemctl restart sshd

# Confirm service is running
systemctl status sshd
```

> **Operational note:** Always maintain an active console session or out-of-band
> access before restarting sshd on a remote system. If SSH becomes inaccessible,
> console access is your recovery path.

---

## Files in This Repository

| File | Purpose |
|---|---|
| `README.md` | Full project documentation (this file) |
| `hardening_script.sh` | Automated hardening script — applies all 14 STIG controls |
| `sshd_config.hardened` | Finished hardened configuration file with inline STIG annotations |
| `STIG_mapping.md` | Detailed control mapping: ID → setting → verification command |
| `scan_results/before.txt` | `sshd -T` output from baseline (pre-hardening) |
| `scan_results/after.txt` | `sshd -T` output after hardening applied |

---

## References

- [DISA STIG for Red Hat Enterprise Linux 9](https://public.cyber.mil/stigs/downloads/)
- [Red Hat OpenSSH Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/securing_networks/making-openssh-more-secure_securing-networks)
- [NIST SP 800-53 — Access Control & Audit Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [FIPS 140-2 Approved Algorithms](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)

---

*Part of the [Linux SysAdmin Lab](https://github.com/jawilli6-sudo/linux-sysadmin-lab) portfolio*  
*Author: Jessica Williams | Linux Systems Administrator | Security Practitioner*
