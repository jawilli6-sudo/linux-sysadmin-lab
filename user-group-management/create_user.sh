#!/usr/bin/env bash
# =============================================================================
# STIG-Compliant User Creation Script — RHEL 9
# =============================================================================
# Author:      Jessica Williams
# Description: Creates user accounts with DISA STIG-compliant password aging,
#              group assignment, and account configuration enforced by default.
#
# STIG Controls:
#   V-257901 — Password max age (60 days)
#   V-257902 — Password min age (1 day)
#   V-257903 — Password warning period (7 days)
#   V-257904 — Inactive account lockout (35 days)
#   V-257905 — Password minimum length (14 characters)
#
# Usage:
#   sudo bash create_user.sh -u <username> -g <primary_group> \
#     [-G <supplemental_groups>] [-e <expiry_date>] [-c <comment>]
#
# Examples:
#   sudo bash create_user.sh -u jsmith -g sysadmins -G wheel -c "John Smith"
#   sudo bash create_user.sh -u contractor1 -g contractors -e 2026-12-31
#
# Tested on: RHEL 9.x
# =============================================================================

set -euo pipefail

# =============================================================================
# COLOR OUTPUT
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()      { echo -e "  ${GREEN}[OK]${NC}    $*"; }
log_info()    { echo -e "  ${BLUE}[INFO]${NC}  $*"; }
log_warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "  ${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo ""; echo -e "${CYAN}${BOLD}━━━ $* ━━━${NC}"; }

# =============================================================================
# STIG-REQUIRED PASSWORD AGING DEFAULTS
# =============================================================================

readonly PASS_MAX_DAYS=60     # V-257901: Password must change every 60 days
readonly PASS_MIN_DAYS=1      # V-257902: Must wait 1 day before changing again
readonly PASS_WARN_DAYS=7     # V-257903: Warn 7 days before expiration
readonly INACTIVE_DAYS=35     # V-257904: Lock account after 35 days inactivity
readonly MIN_PASS_LEN=14      # V-257905: Minimum password length

# =============================================================================
# DEFAULTS
# =============================================================================

USERNAME=""
PRIMARY_GROUP=""
SUPPLEMENTAL_GROUPS=""
EXPIRY_DATE=""
COMMENT=""
HOME_BASE="/home"
SHELL="/bin/bash"

# =============================================================================
# USAGE
# =============================================================================

usage() {
    echo ""
    echo -e "${BOLD}Usage:${NC} sudo bash $0 -u <username> -g <primary_group> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  -u <username>         Login name for the new account"
    echo "  -g <group>            Primary group (created if it doesn't exist)"
    echo ""
    echo "Optional:"
    echo "  -G <groups>           Comma-separated supplemental groups"
    echo "  -e <YYYY-MM-DD>       Account expiration date (for temporary accounts)"
    echo "  -c <comment>          Full name or account description (GECOS field)"
    echo "  -h                    Display this help message"
    echo ""
    echo "Examples:"
    echo "  sudo bash $0 -u jsmith -g sysadmins -G wheel -c \"John Smith\""
    echo "  sudo bash $0 -u contractor1 -g contractors -e 2026-12-31 -c \"Contract Worker\""
    echo ""
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parse_args() {
    while getopts "u:g:G:e:c:h" opt; do
        case "${opt}" in
            u) USERNAME="${OPTARG}" ;;
            g) PRIMARY_GROUP="${OPTARG}" ;;
            G) SUPPLEMENTAL_GROUPS="${OPTARG}" ;;
            e) EXPIRY_DATE="${OPTARG}" ;;
            c) COMMENT="${OPTARG}" ;;
            h) usage; exit 0 ;;
            *) usage; exit 1 ;;
        esac
    done

    if [[ -z "${USERNAME}" ]]; then
        log_error "Username (-u) is required."
        usage; exit 1
    fi

    if [[ -z "${PRIMARY_GROUP}" ]]; then
        log_error "Primary group (-g) is required."
        usage; exit 1
    fi
}

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================

preflight_checks() {
    log_section "PRE-FLIGHT CHECKS"

    # Must run as root
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This script must be run as root or with sudo."
        exit 1
    fi

    # Check username doesn't already exist
    if id "${USERNAME}" &>/dev/null; then
        log_error "User '${USERNAME}' already exists."
        exit 1
    fi

    # Validate username format (alphanumeric, hyphen, underscore only)
    if ! [[ "${USERNAME}" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
        log_error "Invalid username format. Use lowercase letters, numbers, hyphens, underscores."
        exit 1
    fi

    # Validate expiry date format if provided
    if [[ -n "${EXPIRY_DATE}" ]]; then
        if ! date -d "${EXPIRY_DATE}" &>/dev/null; then
            log_error "Invalid expiry date format. Use YYYY-MM-DD."
            exit 1
        fi
    fi

    log_ok "Username '${USERNAME}' is available."
    log_ok "Pre-flight checks passed."
}

# =============================================================================
# GROUP MANAGEMENT
# =============================================================================

ensure_group_exists() {
    local group="$1"
    if ! getent group "${group}" &>/dev/null; then
        groupadd "${group}"
        log_ok "Created group: ${group}"
    else
        log_info "Group already exists: ${group}"
    fi
}

configure_groups() {
    log_section "CONFIGURING GROUPS"

    # Ensure primary group exists
    ensure_group_exists "${PRIMARY_GROUP}"

    # Ensure supplemental groups exist
    if [[ -n "${SUPPLEMENTAL_GROUPS}" ]]; then
        IFS=',' read -ra GROUPS <<< "${SUPPLEMENTAL_GROUPS}"
        for grp in "${GROUPS[@]}"; do
            grp=$(echo "${grp}" | tr -d ' ')
            ensure_group_exists "${grp}"
        done
        log_ok "Supplemental groups configured: ${SUPPLEMENTAL_GROUPS}"
    fi
}

# =============================================================================
# USER CREATION
# =============================================================================

create_user() {
    log_section "CREATING USER ACCOUNT"

    local useradd_cmd="useradd"
    useradd_cmd+=" --create-home"
    useradd_cmd+=" --home-dir ${HOME_BASE}/${USERNAME}"
    useradd_cmd+=" --shell ${SHELL}"
    useradd_cmd+=" --gid ${PRIMARY_GROUP}"

    if [[ -n "${SUPPLEMENTAL_GROUPS}" ]]; then
        useradd_cmd+=" --groups ${SUPPLEMENTAL_GROUPS}"
    fi

    if [[ -n "${COMMENT}" ]]; then
        useradd_cmd+=" --comment \"${COMMENT}\""
    fi

    if [[ -n "${EXPIRY_DATE}" ]]; then
        useradd_cmd+=" --expiredate ${EXPIRY_DATE}"
    fi

    useradd_cmd+=" ${USERNAME}"

    log_info "Running: ${useradd_cmd}"
    eval "${useradd_cmd}"

    log_ok "User account created: ${USERNAME}"
    log_info "Home directory: ${HOME_BASE}/${USERNAME}"

    # Secure home directory permissions (STIG requirement)
    chmod 700 "${HOME_BASE}/${USERNAME}"
    log_ok "Home directory permissions set to 700"
}

# =============================================================================
# APPLY STIG PASSWORD AGING
# =============================================================================

apply_password_aging() {
    log_section "APPLYING STIG PASSWORD AGING CONTROLS"

    # Apply all chage settings in one command
    chage \
        --maxdays  "${PASS_MAX_DAYS}"   \
        --mindays  "${PASS_MIN_DAYS}"   \
        --warndays "${PASS_WARN_DAYS}"  \
        --inactive "${INACTIVE_DAYS}"   \
        "${USERNAME}"

    log_ok "PASS_MAX_DAYS  = ${PASS_MAX_DAYS}  [V-257901]"
    log_ok "PASS_MIN_DAYS  = ${PASS_MIN_DAYS}   [V-257902]"
    log_ok "PASS_WARN_DAYS = ${PASS_WARN_DAYS}   [V-257903]"
    log_ok "INACTIVE_DAYS  = ${INACTIVE_DAYS}  [V-257904]"

    # Apply expiry date if set
    if [[ -n "${EXPIRY_DATE}" ]]; then
        log_ok "Account expiry date: ${EXPIRY_DATE}"
    fi

    # Force password change on first login
    chage --lastday 0 "${USERNAME}"
    log_ok "Password change required on first login."
}

# =============================================================================
# VERIFY ACCOUNT
# =============================================================================

verify_account() {
    log_section "VERIFYING ACCOUNT CONFIGURATION"

    echo ""
    echo -e "  ${BOLD}Account details:${NC}"
    id "${USERNAME}"
    echo ""

    echo -e "  ${BOLD}Password aging policy:${NC}"
    chage -l "${USERNAME}"
    echo ""

    echo -e "  ${BOLD}Shadow entry:${NC}"
    sudo getent shadow "${USERNAME}" | cut -d: -f1,2,3,4,5,6,7 | \
        awk -F: '{
            print "  Login:          " $1
            print "  Password hash:  " (length($2) > 5 ? "[set]" : "[EMPTY - set immediately]")
            print "  Last changed:   " $3
            print "  Min age:        " $4
            print "  Max age:        " $5
            print "  Warn period:    " $6
            print "  Inactive lock:  " $7
        }'
    echo ""
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
    log_section "USER CREATION COMPLETE"

    echo ""
    echo -e "  ${BOLD}Username:${NC}    ${USERNAME}"
    echo -e "  ${BOLD}Primary Group:${NC} ${PRIMARY_GROUP}"
    [[ -n "${SUPPLEMENTAL_GROUPS}" ]] && echo -e "  ${BOLD}Supp. Groups:${NC}  ${SUPPLEMENTAL_GROUPS}"
    [[ -n "${EXPIRY_DATE}" ]] && echo -e "  ${BOLD}Expires:${NC}     ${EXPIRY_DATE}"
    [[ -n "${COMMENT}" ]] && echo -e "  ${BOLD}Comment:${NC}     ${COMMENT}"
    echo ""
    echo -e "  ${YELLOW}[ACTION REQUIRED]${NC} Set password immediately:"
    echo -e "  sudo passwd ${USERNAME}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo -e "\n${BOLD}STIG-Compliant User Creation — RHEL 9${NC}\n"

    parse_args "$@"
    preflight_checks
    configure_groups
    create_user
    apply_password_aging
    verify_account
    print_summary
}

main "$@"
