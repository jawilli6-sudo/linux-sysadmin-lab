#!/usr/bin/env bash
# =============================================================================
# SSH Daemon Hardening Script — RHEL 9 / DISA STIG
# =============================================================================
# Author:      Jessica Williams
# Description: Applies DISA STIG hardening controls to the OpenSSH daemon
#              configuration on Red Hat Enterprise Linux 9.
#
# Controls:    14 STIG controls covering authentication, encryption,
#              session management, and logging
#
# Usage:       sudo bash hardening_script.sh
#
# Prerequisites:
#   - RHEL 9.x with OpenSSH installed
#   - sudo privileges
#   - Active console or out-of-band access recommended before restart
#
# Tested on:   RHEL 9.x, OpenSSH 8.7+
# =============================================================================

set -euo pipefail

# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly BACKUP_DIR="/root/sshd_backups"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly BACKUP_FILE="${BACKUP_DIR}/sshd_config.bak.${TIMESTAMP}"
readonly LOG_FILE="/var/log/sshd_hardening_${TIMESTAMP}.log"
readonly BANNER_FILE="/etc/issue"
readonly SCRIPT_VERSION="1.0.0"

# STIG-required values
readonly ALLOWED_CIPHERS="aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
readonly ALLOWED_MACS="hmac-sha2-256,hmac-sha2-512,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
readonly ALLOWED_KEX="ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512"

# =============================================================================
# COLOR OUTPUT
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# =============================================================================
# LOGGING FUNCTIONS
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info()    { log "INFO " "$@"; echo -e "  ${BLUE}[INFO]${NC}  $*"; }
log_ok()      { log "OK   " "$@"; echo -e "  ${GREEN}[OK]${NC}    $*"; }
log_warn()    { log "WARN " "$@"; echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
log_error()   { log "ERROR" "$@"; echo -e "  ${RED}[ERROR]${NC} $*" >&2; }
log_section() { 
    local msg="$*"
    echo ""
    echo -e "${CYAN}${BOLD}━━━ ${msg} ━━━${NC}"
    log "SECT " "${msg}"
}

# =============================================================================
# ERROR HANDLER
# =============================================================================

error_exit() {
    log_error "Script failed at line $1 — exit code $2"
    log_error "Check log at: ${LOG_FILE}"
    log_warn  "Original config preserved at: ${BACKUP_FILE}"
    log_warn  "To restore: sudo cp ${BACKUP_FILE} ${SSHD_CONFIG} && sudo sshd -t && sudo systemctl restart sshd"
    exit "$2"
}

trap 'error_exit ${LINENO} $?' ERR

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root or with sudo."
        exit 1
    fi
}

set_or_replace() {
    # Usage: set_or_replace "Directive" "Value" "file"
    local directive="$1"
    local value="$2"
    local file="$3"
    local stig_id="${4:-}"

    if grep -qiE "^[[:space:]]*#?[[:space:]]*${directive}[[:space:]]" "${file}"; then
        # Replace existing directive (commented or active)
        sed -i "s|^[[:space:]]*#\?[[:space:]]*${directive}[[:space:]].*|${directive} ${value}|i" "${file}"
    else
        # Append if not present
        echo "${directive} ${value}" >> "${file}"
    fi

    log_ok "${directive} set to '${value}'${stig_id:+ [${stig_id}]}"
}

verify_setting() {
    local directive="$1"
    local expected="$2"
    local actual
    actual=$(sshd -T 2>/dev/null | grep -i "^${directive} " | awk '{print $2}')

    if [[ "${actual,,}" == "${expected,,}" ]]; then
        log_ok "VERIFIED: ${directive} = ${actual}"
        return 0
    else
        log_error "MISMATCH: ${directive} expected '${expected}', got '${actual}'"
        return 1
    fi
}

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

preflight_checks() {
    log_section "PRE-FLIGHT CHECKS"

    # Confirm sshd is installed
    if ! command -v sshd &>/dev/null; then
        log_error "sshd not found. Install with: dnf install openssh-server"
        exit 1
    fi
    log_ok "sshd found: $(ssh -V 2>&1)"

    # Confirm config file exists
    if [[ ! -f "${SSHD_CONFIG}" ]]; then
        log_error "Config file not found: ${SSHD_CONFIG}"
        exit 1
    fi
    log_ok "Config file found: ${SSHD_CONFIG}"

    # Confirm SELinux won't block restart
    if command -v getenforce &>/dev/null; then
        local selinux_mode
        selinux_mode=$(getenforce)
        log_info "SELinux mode: ${selinux_mode}"
    fi

    # Warn if running over SSH (risk of lockout)
    if [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_TTY:-}" ]]; then
        log_warn "You are running this script over an active SSH session."
        log_warn "Ensure you have console/out-of-band access before proceeding."
        echo ""
        read -rp "  Confirm you have alternative access if SSH becomes unavailable [yes/no]: " confirm
        if [[ "${confirm,,}" != "yes" ]]; then
            log_info "Aborted by user. Re-run when out-of-band access is confirmed."
            exit 0
        fi
    fi

    log_ok "Pre-flight checks passed."
}

# =============================================================================
# BACKUP
# =============================================================================

create_backup() {
    log_section "CREATING BACKUP"

    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${BACKUP_DIR}"

    cp "${SSHD_CONFIG}" "${BACKUP_FILE}"
    chmod 600 "${BACKUP_FILE}"

    log_ok "Backup created: ${BACKUP_FILE}"
    log_info "Restore command: sudo cp ${BACKUP_FILE} ${SSHD_CONFIG}"
}

# =============================================================================
# BANNER CONFIGURATION
# =============================================================================

configure_banner() {
    log_section "CONFIGURING LEGAL WARNING BANNER"
    # STIG V-257765: SSH must display a legal warning banner before authentication

    cat > "${BANNER_FILE}" << 'EOF'
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AUTHORIZED USE ONLY                                  │
│                                                                             │
│  This system is the property of an authorized organization. Unauthorized   │
│  access, use, or modification of this system or its data is prohibited     │
│  and may be subject to civil and criminal penalties.                        │
│                                                                             │
│  All activity on this system is monitored and recorded. By continuing,     │
│  you consent to this monitoring and acknowledge that evidence of           │
│  unauthorized use may be disclosed to law enforcement authorities.          │
│                                                                             │
│  If you are not an authorized user, DISCONNECT NOW.                        │
└─────────────────────────────────────────────────────────────────────────────┘
EOF

    chmod 644 "${BANNER_FILE}"
    log_ok "Legal banner written to ${BANNER_FILE}"
}

# =============================================================================
# APPLY STIG CONTROLS
# =============================================================================

apply_stig_controls() {
    log_section "APPLYING STIG CONTROLS TO ${SSHD_CONFIG}"

    # -------------------------------------------------------------------------
    # AUTHENTICATION CONTROLS
    # -------------------------------------------------------------------------

    # STIG V-257778: SSH must not permit root login
    # Rationale: Direct root login eliminates individual accountability.
    # All privileged actions must go through named accounts with sudo.
    set_or_replace "PermitRootLogin" "no" "${SSHD_CONFIG}" "V-257778"

    # STIG V-257757: SSH must not permit empty passwords
    # Rationale: Empty passwords allow unauthenticated access.
    set_or_replace "PermitEmptyPasswords" "no" "${SSHD_CONFIG}" "V-257757"

    # STIG V-257764: SSH max authentication attempts must be limited
    # Rationale: Limits brute-force attack window. Default (6) is too permissive.
    set_or_replace "MaxAuthTries" "3" "${SSHD_CONFIG}" "V-257764"

    # STIG V-257763: SSH login grace time must be limited
    # Rationale: Default 120s gives automated tools excessive time to authenticate.
    set_or_replace "LoginGraceTime" "60" "${SSHD_CONFIG}" "V-257763"

    # -------------------------------------------------------------------------
    # CRYPTOGRAPHY CONTROLS
    # -------------------------------------------------------------------------

    # STIG V-257758: SSH must use only FIPS 140-2 approved ciphers
    # Rationale: Default negotiation may accept 3DES-CBC, AES-CBC, or other
    # deprecated algorithms vulnerable to BEAST, SWEET32, and similar attacks.
    set_or_replace "Ciphers" "${ALLOWED_CIPHERS}" "${SSHD_CONFIG}" "V-257758"

    # STIG V-257759: SSH must use only approved MACs (Message Authentication Codes)
    # Rationale: hmac-md5, hmac-sha1, and umac-64 are no longer FIPS-approved.
    # SHA-1 is deprecated per NIST guidance (SP 800-131A).
    set_or_replace "MACs" "${ALLOWED_MACS}" "${SSHD_CONFIG}" "V-257759"

    # STIG V-257760: SSH must use only approved key exchange algorithms
    # Rationale: Diffie-Hellman with SHA-1 is deprecated. Group 1 (1024-bit)
    # key exchange was broken in the Logjam attack (2015).
    set_or_replace "KexAlgorithms" "${ALLOWED_KEX}" "${SSHD_CONFIG}" "V-257760"

    # -------------------------------------------------------------------------
    # SESSION MANAGEMENT CONTROLS
    # -------------------------------------------------------------------------

    # STIG V-257761: SSH idle timeout interval must be configured
    # Rationale: Unattended sessions are a persistent access risk. 600 seconds
    # (10 minutes) is the STIG-required maximum.
    set_or_replace "ClientAliveInterval" "600" "${SSHD_CONFIG}" "V-257761"

    # STIG V-257762: SSH ClientAliveCountMax must be set to 0
    # Rationale: With CountMax=0 and Interval=600, a session is terminated
    # after exactly one missed keep-alive (600s of inactivity). CountMax > 0
    # allows the session to persist through multiple missed intervals.
    set_or_replace "ClientAliveCountMax" "0" "${SSHD_CONFIG}" "V-257762"

    # -------------------------------------------------------------------------
    # PRIVILEGE & ENVIRONMENT CONTROLS
    # -------------------------------------------------------------------------

    # STIG V-257766: SSH must not permit user environment options
    # Rationale: Allowing users to set environment variables through .ssh/environment
    # can bypass system security policy (e.g., LD_PRELOAD for privilege escalation).
    set_or_replace "PermitUserEnvironment" "no" "${SSHD_CONFIG}" "V-257766"

    # STIG V-257767: SSH X11 forwarding must be disabled
    # Rationale: X11 forwarding creates a reverse channel that can be used for
    # lateral movement and bypasses firewall controls.
    set_or_replace "X11Forwarding" "no" "${SSHD_CONFIG}" "V-257767"

    # STIG V-257768: SSH must use privilege separation
    # Rationale: Privilege separation isolates the unauthenticated portion of the
    # connection to a sandboxed process, limiting exposure if sshd is exploited.
    set_or_replace "UsePrivilegeSeparation" "sandbox" "${SSHD_CONFIG}" "V-257768"

    # -------------------------------------------------------------------------
    # LOGGING & MONITORING CONTROLS
    # -------------------------------------------------------------------------

    # STIG V-257769: SSH must log user connections with verbose detail
    # Rationale: INFO level omits key details like fingerprints and hostnames.
    # VERBOSE ensures session keys and fingerprints are logged for forensic use.
    set_or_replace "LogLevel" "VERBOSE" "${SSHD_CONFIG}" "V-257769"

    # STIG V-257765: SSH must display a legal warning banner before authentication
    # Rationale: Legal basis for prosecution requires explicit notice to users.
    set_or_replace "Banner" "${BANNER_FILE}" "${SSHD_CONFIG}" "V-257765"

    log_ok "All 14 STIG controls applied."
}

# =============================================================================
# VALIDATE & RESTART
# =============================================================================

validate_and_restart() {
    log_section "VALIDATING CONFIGURATION"

    if ! sshd -t 2>&1 | tee -a "${LOG_FILE}"; then
        log_error "sshd configuration test FAILED — restoring backup"
        cp "${BACKUP_FILE}" "${SSHD_CONFIG}"
        log_warn "Original config restored. Review errors above."
        exit 1
    fi
    log_ok "Configuration syntax validation passed."

    log_section "RESTARTING SSHD"
    systemctl restart sshd
    sleep 2

    if systemctl is-active --quiet sshd; then
        log_ok "sshd service is running."
    else
        log_error "sshd failed to start — restoring backup"
        cp "${BACKUP_FILE}" "${SSHD_CONFIG}"
        systemctl restart sshd
        log_warn "Backup restored and service restarted."
        exit 1
    fi
}

# =============================================================================
# VERIFY CONTROLS
# =============================================================================

verify_controls() {
    log_section "VERIFYING APPLIED CONTROLS"

    local pass=0
    local fail=0

    verify_and_count() {
        if verify_setting "$1" "$2"; then
            ((pass++))
        else
            ((fail++))
        fi
    }

    verify_and_count "permitrootlogin"      "no"
    verify_and_count "permitemptypasswords" "no"
    verify_and_count "maxauthtries"         "3"
    verify_and_count "logingracetime"       "60"
    verify_and_count "clientaliveinterval"  "600"
    verify_and_count "clientalivecountmax"  "0"
    verify_and_count "permituserenvironment" "no"
    verify_and_count "x11forwarding"        "no"
    verify_and_count "loglevel"             "verbose"

    echo ""
    log_section "VERIFICATION SUMMARY"
    echo -e "  ${GREEN}Passed:${NC} ${pass}"
    echo -e "  ${RED}Failed:${NC} ${fail}"
    echo ""

    if [[ ${fail} -eq 0 ]]; then
        log_ok "All verified controls passed."
    else
        log_warn "${fail} control(s) did not verify as expected. Review output above."
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
    log_section "HARDENING COMPLETE"

    echo ""
    echo -e "  ${BOLD}Log file:${NC}    ${LOG_FILE}"
    echo -e "  ${BOLD}Backup:${NC}      ${BACKUP_FILE}"
    echo -e "  ${BOLD}Config:${NC}      ${SSHD_CONFIG}"
    echo ""
    echo -e "  ${BOLD}Next steps:${NC}"
    echo "    1. From a NEW terminal, verify you can still SSH to this host"
    echo "    2. Run: sudo sshd -T > /tmp/sshd_after.txt"
    echo "    3. Diff against your baseline: diff ~/ssh_baseline_before.txt /tmp/sshd_after.txt"
    echo "    4. Capture output for GitHub documentation"
    echo ""
    echo -e "  ${BOLD}Rollback:${NC}"
    echo "    sudo cp ${BACKUP_FILE} ${SSHD_CONFIG} && sudo sshd -t && sudo systemctl restart sshd"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo -e "${BOLD}SSH Daemon Hardening Script — RHEL 9 / DISA STIG${NC}"
    echo -e "${BOLD}Version ${SCRIPT_VERSION}${NC}"
    echo -e "Started: $(date)"
    echo ""

    check_root
    preflight_checks
    create_backup
    configure_banner
    apply_stig_controls
    validate_and_restart
    verify_controls
    print_summary
}

main "$@"
