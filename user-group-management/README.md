# User & Group Management Automation — RHEL 9 (DISA STIG)

![OS](https://img.shields.io/badge/OS-RHEL%209-red?style=flat-square&logo=redhat)
![Compliance](https://img.shields.io/badge/Compliance-DISA%20STIG-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=flat-square)
![Updated](https://img.shields.io/badge/Updated-June%202026-lightgrey?style=flat-square)

## Overview

This project automates STIG-compliant user and group management on RHEL 9. It
delivers two production-ready scripts: one that creates standardized user accounts
with enforced password aging and security policy, and one that audits all existing
accounts against DISA STIG requirements.

Starting from a default RHEL 9 installation with no prior user policy enforcement,
this project applies system-wide password aging controls via `/etc/login.defs`,
enforces per-account policy with `chage`, and produces a compliance audit report
identifying accounts that violate STIG requirements.

**Lab Environment**
- OS: Red Hat Enterprise Linux 9.x (VirtualBox)
- Starting state: Default post-install user configuration
- Privilege model: Standard user with `sudo` access

---

## Security Rationale

Default RHEL 9 user configurations violate several STIG requirements:

- Passwords never expire by default — accounts with stale passwords are a persistent
  credential compromise risk
- No minimum password age — users can immediately reset passwords back to previous
  ones, defeating password history controls
- Inactive accounts remain enabled indefinitely — abandoned accounts with valid
  credentials are a common lateral movement vector
- No system-wide enforcement of password aging — each account's policy depends on
  whoever created it, leading to inconsistency

This project closes these gaps with automated, auditable, repeatable scripts that
enforce consistent policy across all accounts.

---

## STIG Controls Implemented

| STIG ID | Control Title | Implementation |
|---|---|---|
| V-257901 | Password max age must be 60 days or less | `PASS_MAX_DAYS 60` in `/etc/login.defs`; `chage -M 60` per account |
| V-257902 | Password min age must be 1 day or more | `PASS_MIN_DAYS 1` in `/etc/login.defs`; `chage -m 1` per account |
| V-257903 | Password warning must be 7 days or more | `PASS_WARN_AGE 7` in `/etc/login.defs`; `chage -W 7` per account |
| V-257904 | Inactive accounts must lock after 35 days | `chage -I 35` per account; `INACTIVE=35` in `/etc/default/useradd` |
| V-257905 | Password minimum length must be 14 characters | `PASS_MIN_LEN 14` in `/etc/login.defs` |
| V-257906 | Only root may have UID 0 | Audit check — flag any non-root UID 0 accounts |
| V-257907 | No duplicate UIDs permitted | Audit check — detect and report duplicates |
| V-257908 | No duplicate GIDs permitted | Audit check — detect and report duplicates |
| V-257909 | No accounts without passwords | Audit check — flag accounts with empty password field |
| V-257910 | Accounts must have valid login shells | Audit check — flag invalid shells for interactive accounts |

> **Note:** Verify control IDs against the current DISA STIG for RHEL 9 at
> [public.cyber.mil/stigs](https://public.cyber.mil/stigs/) as IDs may be revised
> between STIG releases.

---

## Scripts in This Project

### `create_user.sh`
Parameterized user creation script that enforces STIG-compliant password aging,
group assignment, and account configuration. Replaces manual `useradd` commands
with a standardized, auditable process.

**Usage:**
```bash
sudo bash create_user.sh -u <username> -g <primary_group> [-G <supplemental_groups>] [-e <expiry_date>] [-c <comment>]
```

**Example:**
```bash
# Create a standard user with STIG-compliant settings
sudo bash create_user.sh -u jsmith -g sysadmins -G wheel -c "John Smith"

# Create a temporary account expiring on a specific date
sudo bash create_user.sh -u contractor1 -g contractors -e 2026-12-31 -c "Contract Worker"
```

### `audit_accounts.sh`
Audits all local accounts against STIG requirements. Produces a formatted compliance
report identifying violations, flagging accounts for remediation.

**Usage:**
```bash
sudo bash audit_accounts.sh | tee ~/account_audit_$(date +%Y%m%d).txt
```

---

## Prerequisites

```bash
# Verify you have the required tools
getent --version
chage --help | head -3
useradd --version

# Confirm sudo access
sudo -l | head -5

# View current login.defs password policy
grep -E "^PASS_" /etc/login.defs
```

---

## Implementation

### Step 1 — Capture Baseline

Before making any changes, document the current state:

```bash
# Capture current password policy
echo "=== /etc/login.defs BEFORE ===" | tee ~/before.txt
grep -E "^PASS_|^INACTIVE|^EXPIRE" /etc/login.defs | tee -a ~/before.txt

# Capture all local accounts and their aging settings
echo "=== ACCOUNT AGING BEFORE ===" | tee -a ~/before.txt
while IFS=: read -r user _ uid _; do
    if [[ $uid -ge 1000 && $uid -lt 65534 ]]; then
        echo "--- ${user} ---" | tee -a ~/before.txt
        sudo chage -l "${user}" | tee -a ~/before.txt
    fi
done < /etc/passwd

# Capture current users and groups
echo "=== CURRENT USERS ===" | tee -a ~/before.txt
cat /etc/passwd | tee -a ~/before.txt
echo "=== CURRENT GROUPS ===" | tee -a ~/before.txt
cat /etc/group | tee -a ~/before.txt
```

### Step 2 — Apply System-Wide Password Policy

```bash
# Harden /etc/login.defs
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t60/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t14/' /etc/login.defs

# Set inactive account lockout default for new accounts
sudo sed -i 's/^INACTIVE=.*/INACTIVE=35/' /etc/default/useradd
grep -q "^INACTIVE=" /etc/default/useradd || echo "INACTIVE=35" | sudo tee -a /etc/default/useradd

# Verify changes
echo "=== UPDATED /etc/login.defs ==="
grep -E "^PASS_" /etc/login.defs
echo "=== UPDATED /etc/default/useradd ==="
grep "INACTIVE" /etc/default/useradd
```

### Step 3 — Execute User Creation Script

```bash
chmod +x create_user.sh

# Create a test sysadmin user
sudo bash create_user.sh -u stiguser1 -g wheel -c "STIG Test User 1"

# Create a test standard user
sudo bash create_user.sh -u stiguser2 -g users -c "STIG Test User 2"

# Verify created accounts
sudo chage -l stiguser1
sudo chage -l stiguser2
```

### Step 4 — Run Compliance Audit

```bash
chmod +x audit_accounts.sh
sudo bash audit_accounts.sh | tee ~/after.txt
```

---

## Before vs. After Comparison

| Setting | Before (Default) | After (STIG Hardened) |
|---|---|---|
| PASS_MAX_DAYS | 99999 (never expires) | 60 |
| PASS_MIN_DAYS | 0 | 1 |
| PASS_WARN_AGE | 7 *(may vary)* | 7 *(explicit)* |
| PASS_MIN_LEN | 5 or unset | 14 |
| INACTIVE | -1 (never locks) | 35 |
| New user aging | Not enforced | STIG-compliant by default |

**Key risk closures:**
- Passwords now expire every 60 days — stale credential window eliminated
- 1-day minimum age prevents immediate password cycling (defeats history controls)
- Accounts inactive for 35 days automatically lock — abandoned accounts closed
- 14-character minimum enforced at account creation — brute-force resistance improved

---

## Rollback Procedure

```bash
# Restore login.defs from backup
sudo cp /etc/login.defs.bak /etc/login.defs

# Remove test accounts created during lab
sudo userdel -r stiguser1
sudo userdel -r stiguser2

# Verify removal
id stiguser1 2>/dev/null && echo "User exists" || echo "User removed"
```

---

## Files in This Repository

| File | Purpose |
|---|---|
| `README.md` | Full project documentation (this file) |
| `create_user.sh` | STIG-compliant user creation script |
| `audit_accounts.sh` | Account compliance audit script |
| `STIG_mapping.md` | Detailed control mapping with verification commands |
| `scan_results/before.txt` | Baseline password policy and account state |
| `scan_results/after.txt` | Post-hardening audit report |

---

## References

- [DISA STIG for Red Hat Enterprise Linux 9](https://public.cyber.mil/stigs/downloads/)
- [Red Hat — Managing Users and Groups](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/managing-users-and-groups_configuring-basic-system-settings)
- [NIST SP 800-53 — Identification and Authentication Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Red Hat — Using the chage Command](https://access.redhat.com/solutions/179233)

---

*Part of the [Linux SysAdmin Lab](https://github.com/jawilli6-sudo/linux-sysadmin-lab) portfolio*
*Author: Jessica Williams | Linux Systems Administrator | Security Practitioner*
