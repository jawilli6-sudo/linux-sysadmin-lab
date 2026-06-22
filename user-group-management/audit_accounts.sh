#!/usr/bin/env bash
# =============================================================================
# Account Compliance Audit Script — RHEL 9 / DISA STIG
# =============================================================================
# Author:      Jessica Williams
# Description: Audits all local user accounts against DISA STIG requirements
#              for RHEL 9. Produces a formatted compliance report identifying
#              violations and accounts requiring remediation.
#
# STIG Controls Checked:
#   V-257901 — Password max age (must be <= 60 days)
#   V-257902 — Password min age (must be >= 1 day)
#   V-257903 — Password warning period (must be >= 7 days)
#   V-257904 — Inactive lockout (must be <= 35 days)
#   V-257905 — Password minimum length (must be >= 14)
#   V-257906 — Only root may have UID 0
#   V-257907 — No duplicate UIDs
#   V-257908 — No duplicate GIDs
#   V-257909 — No accounts with empty passwords
#   V-257910 — Interactive accounts must have valid shells
#
# Usage:
#   sudo bash audit_accounts.sh
#   sudo bash audit_accounts.sh | tee ~/account_audit_$(date +%Y%m%d).txt
#
# Tested on: RHEL 9.x
# =============================================================================

set -euo pipefail

# =============================================================================
# COLOR OUTPUT
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0
FAIL=0
WARN=0

# =============================================================================
# STIG THRESHOLDS
# =============================================================================

readonly MAX_PASS_AGE=60
readonly MIN_PASS_AGE=1
readonly MIN_WARN_DAYS=7
readonly MAX_INACTIVE=35
readonly MIN_PASS_LEN=14

# Valid shells for interactive accounts
readonly VALID_SHELLS=("/bin/bash" "/bin/sh" "/bin/zsh" "/usr/bin/bash" "/usr/bin/zsh")

# =============================================================================
# OUTPUT HELPERS
# =============================================================================

audit_pass()  { echo -e "    ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
audit_fail()  { echo -e "    ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
audit_warn()  { echo -e "    ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
audit_info()  { echo -e "    ${BLUE}[INFO]${NC} $*"; }
section()     { echo ""; echo -e "${CYAN}${BOLD}━━━ $* ━━━${NC}"; echo ""; }

# =============================================================================
# CHECK ROOT PRIVILEGES
# =============================================================================

if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root or with sudo."
    exit 1
fi

# =============================================================================
# REPORT HEADER
# =============================================================================

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     ACCOUNT COMPLIANCE AUDIT — RHEL 9 / DISA STIG           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Date:${NC}     $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "  ${BOLD}Host:${NC}     $(hostname)"
echo -e "  ${BOLD}OS:${NC}       $(cat /etc/redhat-release)"
echo -e "  ${BOLD}Auditor:${NC}  $(logname 2>/dev/null || echo 'root')"
echo ""

# =============================================================================
# SECTION 1: SYSTEM PASSWORD POLICY (/etc/login.defs)
# =============================================================================

section "SECTION 1 — SYSTEM PASSWORD POLICY (/etc/login.defs)"

# PASS_MAX_DAYS
max_days=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}' || echo "99999")
echo -e "  ${BOLD}V-257901:${NC} PASS_MAX_DAYS = ${max_days}"
if [[ "${max_days}" -le "${MAX_PASS_AGE}" ]]; then
    audit_pass "PASS_MAX_DAYS ${max_days} <= ${MAX_PASS_AGE} (required)"
else
    audit_fail "PASS_MAX_DAYS ${max_days} exceeds ${MAX_PASS_AGE} — set to ${MAX_PASS_AGE} in /etc/login.defs"
fi

# PASS_MIN_DAYS
min_days=$(grep -E "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}' || echo "0")
echo -e "  ${BOLD}V-257902:${NC} PASS_MIN_DAYS = ${min_days}"
if [[ "${min_days}" -ge "${MIN_PASS_AGE}" ]]; then
    audit_pass "PASS_MIN_DAYS ${min_days} >= ${MIN_PASS_AGE} (required)"
else
    audit_fail "PASS_MIN_DAYS ${min_days} is less than ${MIN_PASS_AGE} — set to ${MIN_PASS_AGE} in /etc/login.defs"
fi

# PASS_WARN_AGE
warn_age=$(grep -E "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}' || echo "0")
echo -e "  ${BOLD}V-257903:${NC} PASS_WARN_AGE = ${warn_age}"
if [[ "${warn_age}" -ge "${MIN_WARN_DAYS}" ]]; then
    audit_pass "PASS_WARN_AGE ${warn_age} >= ${MIN_WARN_DAYS} (required)"
else
    audit_fail "PASS_WARN_AGE ${warn_age} is less than ${MIN_WARN_DAYS} — set to ${MIN_WARN_DAYS} in /etc/login.defs"
fi

# PASS_MIN_LEN
min_len=$(grep -E "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}' || echo "0")
echo -e "  ${BOLD}V-257905:${NC} PASS_MIN_LEN = ${min_len}"
if [[ "${min_len}" -ge "${MIN_PASS_LEN}" ]]; then
    audit_pass "PASS_MIN_LEN ${min_len} >= ${MIN_PASS_LEN} (required)"
else
    audit_fail "PASS_MIN_LEN ${min_len} is less than ${MIN_PASS_LEN} — set to ${MIN_PASS_LEN} in /etc/login.defs"
fi

# =============================================================================
# SECTION 2: PER-ACCOUNT PASSWORD AGING AUDIT
# =============================================================================

section "SECTION 2 — PER-ACCOUNT PASSWORD AGING (Interactive Accounts)"

while IFS=: read -r username _ uid gid _ homedir shell; do
    # Only audit interactive accounts (UID >= 1000, not nfsnobody at 65534)
    if [[ "${uid}" -ge 1000 && "${uid}" -lt 65534 ]]; then
        echo -e "  ${BOLD}Account: ${username}${NC} (UID: ${uid})"

        # Get chage values
        chage_max=$(chage -l "${username}" 2>/dev/null | grep "Maximum" | awk -F: '{print $2}' | tr -d ' ')
        chage_min=$(chage -l "${username}" 2>/dev/null | grep "Minimum" | awk -F: '{print $2}' | tr -d ' ')
        chage_warn=$(chage -l "${username}" 2>/dev/null | grep "Password warning" | awk -F: '{print $2}' | tr -d ' ')
        chage_inactive=$(chage -l "${username}" 2>/dev/null | grep "Password inactive" | awk -F: '{print $2}' | tr -d ' ')
        chage_expire=$(chage -l "${username}" 2>/dev/null | grep "Account expires" | awk -F: '{print $2}' | tr -d ' ')

        # Max age check
        if [[ "${chage_max}" == "never" ]]; then
            audit_fail "V-257901: Max password age = never (must be <= ${MAX_PASS_AGE} days)"
            audit_info "Fix: sudo chage --maxdays ${MAX_PASS_AGE} ${username}"
        elif [[ "${chage_max}" -le "${MAX_PASS_AGE}" ]]; then
            audit_pass "V-257901: Max password age = ${chage_max} days"
        else
            audit_fail "V-257901: Max password age = ${chage_max} days (must be <= ${MAX_PASS_AGE})"
            audit_info "Fix: sudo chage --maxdays ${MAX_PASS_AGE} ${username}"
        fi

        # Min age check
        if [[ "${chage_min}" -ge "${MIN_PASS_AGE}" ]]; then
            audit_pass "V-257902: Min password age = ${chage_min} days"
        else
            audit_fail "V-257902: Min password age = ${chage_min} days (must be >= ${MIN_PASS_AGE})"
            audit_info "Fix: sudo chage --mindays ${MIN_PASS_AGE} ${username}"
        fi

        # Warning period check
        if [[ "${chage_warn}" -ge "${MIN_WARN_DAYS}" ]]; then
            audit_pass "V-257903: Warning period = ${chage_warn} days"
        else
            audit_fail "V-257903: Warning period = ${chage_warn} days (must be >= ${MIN_WARN_DAYS})"
            audit_info "Fix: sudo chage --warndays ${MIN_WARN_DAYS} ${username}"
        fi

        # Inactive lockout check
        if [[ "${chage_inactive}" == "never" || "${chage_inactive}" -lt 0 ]]; then
            audit_fail "V-257904: Inactive lockout = never (must be <= ${MAX_INACTIVE} days)"
            audit_info "Fix: sudo chage --inactive ${MAX_INACTIVE} ${username}"
        elif [[ "${chage_inactive}" -le "${MAX_INACTIVE}" ]]; then
            audit_pass "V-257904: Inactive lockout = ${chage_inactive} days"
        else
            audit_fail "V-257904: Inactive lockout = ${chage_inactive} days (must be <= ${MAX_INACTIVE})"
            audit_info "Fix: sudo chage --inactive ${MAX_INACTIVE} ${username}"
        fi

        echo ""
    fi
done < /etc/passwd

# =============================================================================
# SECTION 3: UID/GID INTEGRITY CHECKS
# =============================================================================

section "SECTION 3 — UID/GID INTEGRITY"

# Check for non-root UID 0 accounts (V-257906)
echo -e "  ${BOLD}V-257906:${NC} Accounts with UID 0 (only root permitted)"
uid0_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
uid0_count=$(echo "${uid0_accounts}" | wc -l)

if [[ "${uid0_count}" -eq 1 && "${uid0_accounts}" == "root" ]]; then
    audit_pass "Only root has UID 0"
else
    for acct in ${uid0_accounts}; do
        if [[ "${acct}" != "root" ]]; then
            audit_fail "Non-root account with UID 0: ${acct} — CRITICAL, investigate immediately"
        else
            audit_pass "root UID 0 — expected"
        fi
    done
fi

# Check for duplicate UIDs (V-257907)
echo ""
echo -e "  ${BOLD}V-257907:${NC} Duplicate UID check"
dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
if [[ -z "${dup_uids}" ]]; then
    audit_pass "No duplicate UIDs found"
else
    for uid in ${dup_uids}; do
        audit_fail "Duplicate UID ${uid} found — $(awk -F: -v u="${uid}" '$3==u {print $1}' /etc/passwd | tr '\n' ' ')"
    done
fi

# Check for duplicate GIDs (V-257908)
echo ""
echo -e "  ${BOLD}V-257908:${NC} Duplicate GID check"
dup_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
if [[ -z "${dup_gids}" ]]; then
    audit_pass "No duplicate GIDs found"
else
    for gid in ${dup_gids}; do
        audit_fail "Duplicate GID ${gid} found — $(awk -F: -v g="${gid}" '$3==g {print $1}' /etc/group | tr '\n' ' ')"
    done
fi

# =============================================================================
# SECTION 4: PASSWORD AND SHELL INTEGRITY
# =============================================================================

section "SECTION 4 — PASSWORD & SHELL INTEGRITY"

# Check for empty passwords (V-257909)
echo -e "  ${BOLD}V-257909:${NC} Accounts with empty passwords"
empty_pass=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || echo "")

# Filter out system accounts
interactive_empty=""
while IFS= read -r acct; do
    [[ -z "${acct}" ]] && continue
    uid=$(id -u "${acct}" 2>/dev/null || echo "0")
    if [[ "${uid}" -ge 1000 ]]; then
        interactive_empty="${interactive_empty} ${acct}"
    fi
done <<< "${empty_pass}"

if [[ -z "${interactive_empty// /}" ]]; then
    audit_pass "No interactive accounts with empty passwords"
else
    for acct in ${interactive_empty}; do
        audit_fail "V-257909: Interactive account with no/locked password: ${acct}"
    done
fi

# Check for valid shells on interactive accounts (V-257910)
echo ""
echo -e "  ${BOLD}V-257910:${NC} Interactive accounts with invalid login shells"
invalid_shell_found=false

while IFS=: read -r username _ uid _ _ _ shell; do
    if [[ "${uid}" -ge 1000 && "${uid}" -lt 65534 ]]; then
        shell_valid=false
        for valid in "${VALID_SHELLS[@]}"; do
            if [[ "${shell}" == "${valid}" ]]; then
                shell_valid=true
                break
            fi
        done

        if [[ "${shell_valid}" == false && "${shell}" != "/sbin/nologin" && "${shell}" != "/bin/false" ]]; then
            audit_warn "V-257910: ${username} has unusual shell: ${shell} — verify this is intentional"
            invalid_shell_found=true
        fi
    fi
done < /etc/passwd

if [[ "${invalid_shell_found}" == false ]]; then
    audit_pass "All interactive accounts have valid or nologin shells"
fi

# =============================================================================
# AUDIT SUMMARY
# =============================================================================

section "AUDIT SUMMARY"

total=$((PASS + FAIL + WARN))
echo -e "  ${BOLD}Total checks:${NC} ${total}"
echo -e "  ${GREEN}${BOLD}Passed:${NC}       ${PASS}"
echo -e "  ${RED}${BOLD}Failed:${NC}       ${FAIL}"
echo -e "  ${YELLOW}${BOLD}Warnings:${NC}     ${WARN}"
echo ""

if [[ ${FAIL} -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}RESULT: COMPLIANT — All checks passed.${NC}"
else
    echo -e "  ${RED}${BOLD}RESULT: NON-COMPLIANT — ${FAIL} finding(s) require remediation.${NC}"
    echo ""
    echo -e "  ${BOLD}Remediation priority:${NC}"
    echo "    1. Any UID 0 violations — investigate immediately"
    echo "    2. Empty password accounts — lock or set passwords now"
    echo "    3. Password aging violations — apply chage fixes shown above"
fi

echo ""
echo -e "  ${BOLD}Reference:${NC} DISA STIG for RHEL 9 — public.cyber.mil/stigs"
echo -e "  ${BOLD}Generated:${NC} $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
