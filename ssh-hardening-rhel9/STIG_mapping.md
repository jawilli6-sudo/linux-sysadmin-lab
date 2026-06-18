# STIG Control Mapping — SSH Hardening (RHEL 9)

Full mapping of implemented controls to DISA STIG for Red Hat Enterprise Linux 9.  
Reference: [public.cyber.mil/stigs](https://public.cyber.mil/stigs/downloads/)

---

## Control Mapping Table

| STIG ID | Severity | Control Title | Setting Applied | Config File | Verification Command |
|---|---|---|---|---|---|
| V-257778 | CAT II | SSH must not permit root login | `PermitRootLogin no` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep permitrootlogin` |
| V-257757 | CAT II | SSH must not permit empty passwords | `PermitEmptyPasswords no` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep permitemptypasswords` |
| V-257758 | CAT II | SSH must use only approved ciphers | FIPS-approved ciphers only | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep ciphers` |
| V-257759 | CAT II | SSH must use only approved MACs | SHA-2 MACs only | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep "^macs"` |
| V-257760 | CAT II | SSH must use only approved key exchange | ECDHE and DH with SHA-2 only | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep kexalgorithms` |
| V-257761 | CAT II | SSH idle timeout must be configured | `ClientAliveInterval 600` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep clientaliveinterval` |
| V-257762 | CAT II | SSH ClientAliveCountMax must be zero | `ClientAliveCountMax 0` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep clientalivecountmax` |
| V-257763 | CAT II | SSH login grace time must be limited | `LoginGraceTime 60` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep logingracetime` |
| V-257764 | CAT II | SSH max auth attempts must be limited | `MaxAuthTries 3` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep maxauthtries` |
| V-257765 | CAT II | SSH must display a legal warning banner | `Banner /etc/issue` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep banner` |
| V-257766 | CAT II | SSH must not permit user environment | `PermitUserEnvironment no` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep permituserenvironment` |
| V-257767 | CAT II | SSH X11 forwarding must be disabled | `X11Forwarding no` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep x11forwarding` |
| V-257768 | CAT II | SSH must use privilege separation | `UsePrivilegeSeparation sandbox` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep useprivilegeseparation` |
| V-257769 | CAT II | SSH must log at VERBOSE level | `LogLevel VERBOSE` | `/etc/ssh/sshd_config` | `sudo sshd -T \| grep loglevel` |

---

## Severity Definitions

| Category | Severity | Description |
|---|---|---|
| CAT I | High | Directly and immediately enables unauthorized access |
| CAT II | Medium | Has potential to lead to unauthorized access if exploited |
| CAT III | Low | Degrades measure used to protect system |

All controls implemented in this project are CAT II (Medium) severity.

---

## Bulk Verification Command

Run this single command to verify all implemented controls at once:

```bash
sudo sshd -T | grep -E \
  "^permitrootlogin |^permitemptypasswords |^ciphers |^macs |^kexalgorithms |\
^clientaliveinterval |^clientalivecountmax |^logingracetime |^maxauthtries |\
^banner |^permituserenvironment |^x11forwarding |^useprivilegeseparation |^loglevel "
```

Expected output on a fully hardened system:

```
permitrootlogin no
permitemptypasswords no
clientalivecountmax 0
clientaliveinterval 600
logingracetime 60
maxauthtries 3
banner /etc/issue
permituserenvironment no
x11forwarding no
loglevel VERBOSE
ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
kexalgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,...
useprivilegeseparation sandbox
```

---

## Controls Out of Scope (This Lab)

The following STIG categories are not covered in this specific lab but are documented
here for awareness. They are addressed in subsequent projects.

| Category | Controls | Addressed In |
|---|---|---|
| SELinux enforcement | V-257866–V-257870 | Project 3: SELinux Enforcing Mode |
| Audit logging (auditd) | V-257780–V-257820 | Project 5: System Logging & Log Analysis |
| User/group policy | V-257900–V-257950 | Project 2: User & Group Management |
| Filesystem separation | V-257231010 | Project 4: Storage & LVM Management |
| PAM password controls | V-257960–V-257980 | Project 2: User & Group Management |

---

## References

- [DISA STIG Downloads — RHEL 9](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems%2Cunix-linux)
- [STIG Viewer 2.x](https://public.cyber.mil/stigs/srg-stig-tools/)
- [Red Hat STIG Compliance Documentation](https://access.redhat.com/articles/compliance_activities)
- [NIST SP 800-131A Rev 2 — Transitioning the Use of Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [OpenSCAP Security Guide for RHEL 9](https://www.open-scap.org/security-policies/scap-security-guide/)
