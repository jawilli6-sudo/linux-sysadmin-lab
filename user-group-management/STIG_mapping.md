# STIG Control Mapping — User & Group Management (RHEL 9)

Full mapping of implemented controls to DISA STIG for Red Hat Enterprise Linux 9.
Reference: [public.cyber.mil/stigs](https://public.cyber.mil/stigs/downloads/)

---

## Control Mapping Table

| STIG ID | Severity | Control Title | Implementation | Location | Verification Command |
|---|---|---|---|---|---|
| V-257901 | CAT II | Password max age must be 60 days or less | `PASS_MAX_DAYS 60` + `chage -M 60` | `/etc/login.defs` + per account | `grep PASS_MAX_DAYS /etc/login.defs` + `chage -l <user>` |
| V-257902 | CAT II | Password min age must be 1 day or more | `PASS_MIN_DAYS 1` + `chage -m 1` | `/etc/login.defs` + per account | `grep PASS_MIN_DAYS /etc/login.defs` + `chage -l <user>` |
| V-257903 | CAT II | Password warning period must be 7 days or more | `PASS_WARN_AGE 7` + `chage -W 7` | `/etc/login.defs` + per account | `grep PASS_WARN_AGE /etc/login.defs` + `chage -l <user>` |
| V-257904 | CAT II | Inactive accounts must lock after 35 days | `chage -I 35` + `INACTIVE=35` | `/etc/default/useradd` + per account | `grep INACTIVE /etc/default/useradd` + `chage -l <user>` |
| V-257905 | CAT II | Password minimum length must be 14 characters | `PASS_MIN_LEN 14` | `/etc/login.defs` | `grep PASS_MIN_LEN /etc/login.defs` |
| V-257906 | CAT I | Only root may have UID 0 | Audit check + enforcement | `/etc/passwd` | `awk -F: '($3==0){print $1}' /etc/passwd` |
| V-257907 | CAT II | No duplicate UIDs permitted | Audit check | `/etc/passwd` | `awk -F: '{print $3}' /etc/passwd \| sort \| uniq -d` |
| V-257908 | CAT II | No duplicate GIDs permitted | Audit check | `/etc/group` | `awk -F: '{print $3}' /etc/group \| sort \| uniq -d` |
| V-257909 | CAT I | No accounts with empty passwords | Audit check | `/etc/shadow` | `awk -F: '($2==""){print $1}' /etc/shadow` |
| V-257910 | CAT II | Interactive accounts must have valid shells | Audit check | `/etc/passwd` | `awk -F: '$7!~/nologin\|false/{print $1,$7}' /etc/passwd` |

---

## Severity Definitions

| Category | Severity | Description |
|---|---|---|
| CAT I | High | Directly and immediately enables unauthorized access |
| CAT II | Medium | Has potential to lead to unauthorized access if exploited |
| CAT III | Low | Degrades measure used to protect system |

**CAT I controls (V-257906, V-257909)** are checked first — UID 0 violations and
empty passwords represent immediate unauthorized access risk.

---

## Key Files Modified

| File | Purpose | Controls |
|---|---|---|
| `/etc/login.defs` | System-wide password aging defaults for new accounts | V-257901, V-257902, V-257903, V-257905 |
| `/etc/default/useradd` | Default settings applied when useradd is run | V-257904 |
| `/etc/passwd` | User account database | V-257906, V-257907, V-257910 |
| `/etc/shadow` | Password hash and aging storage (per-account) | V-257901–V-257904, V-257909 |
| `/etc/group` | Group database | V-257908 |

---

## Bulk Verification Commands

```bash
# Verify system-wide password policy
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN" /etc/login.defs

# Verify inactive lockout default
grep "INACTIVE" /etc/default/useradd

# Check for UID 0 violations
awk -F: '($3 == 0) {print $1}' /etc/passwd

# Check for duplicate UIDs
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

# Check for duplicate GIDs
awk -F: '{print $3}' /etc/group | sort | uniq -d

# Check all interactive account aging settings at once
for user in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
    echo "=== $user ==="; chage -l $user; done

# Run full audit
sudo bash audit_accounts.sh
```

---

## Difference from Project 1 (SSH Hardening)

In Project 1, RHEL 9's system-wide crypto policy (`/etc/ssh/sshd_config.d/50-redhat.conf`)
overrode settings in `sshd_config`, requiring a drop-in file at
`/etc/ssh/sshd_config.d/01-stig-crypto.conf`.

In this project, `/etc/login.defs` sets **defaults for new accounts only** — existing
accounts are not retroactively affected. This is why `audit_accounts.sh` checks both the
system defaults and per-account `chage` values. A system that appears compliant at the
`login.defs` level may still have non-compliant individual accounts if they were created
before the policy was applied.

---

## Controls Out of Scope (This Lab)

| Category | Controls | Addressed In |
|---|---|---|
| SSH access controls | V-257778–V-257769 | Project 1: SSH Hardening |
| SELinux enforcement | V-257866–V-257870 | Project 3: SELinux Enforcing Mode |
| Audit logging (auditd) | V-257780–V-257820 | Project 5: System Logging & Log Analysis |
| PAM password complexity | V-257960–V-257980 | Covered by PAM/pwquality — separate project |

---

## References

- [DISA STIG Downloads — RHEL 9](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)
- [Red Hat — Managing Users and Groups](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/managing-users-and-groups_configuring-basic-system-settings)
- [Red Hat — chage Command Reference](https://access.redhat.com/solutions/179233)
- [NIST SP 800-53 Rev 5 — IA: Identification and Authentication](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
