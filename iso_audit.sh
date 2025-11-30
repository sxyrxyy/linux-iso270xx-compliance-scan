#!/usr/bin/env bash
#
# Linux ISO 2700x-style baseline audit (read-only)
# - Checks SSH, logging, auditd, ports, routes, perms, time sync, auto updates, disk encryption
# - NO firewall checks
# - NO password policy checks
# - Outputs findings to CSV (default: iso270xx_linux_audit.csv)
# - Suggests auditd / hardening steps and prints a summary at the end
#

########################
# Helpers & formatting #
########################

RED="$(tput setaf 1 2>/dev/null || echo '')"
GREEN="$(tput setaf 2 2>/dev/null || echo '')"
YELLOW="$(tput setaf 3 2>/dev/null || echo '')"
BLUE="$(tput setaf 4 2>/dev/null || echo '')"
BOLD="$(tput bold 2>/dev/null || echo '')"
NC="$(tput sgr0 2>/dev/null || echo '')"

CSV_FILE=""

SAFE_SUGGESTIONS=()
RISKY_SUGGESTIONS=()
PUBLIC_PORTS=()   # entries: "proto addr port"

section() {
  echo
  echo "${BLUE}${BOLD}== $1 ==${NC}"
}

ok() {
  echo "  ${GREEN}[OK]${NC} $1"
}

warn() {
  echo "  ${RED}[WARN]${NC} $1"
}

info() {
  echo "  ${YELLOW}[INFO]${NC} $1"
}

add_safe_suggestion() {
  SAFE_SUGGESTIONS+=("$1")
}

add_risky_suggestion() {
  RISKY_SUGGESTIONS+=("$1")
}

print_suggestions_summary() {
  echo
  echo "${BOLD}Hardening suggestions summary${NC}"

  if ((${#RISKY_SUGGESTIONS[@]})); then
    echo
    echo "${RED}Potentially disruptive changes (be careful in production):${NC}"
    for s in "${RISKY_SUGGESTIONS[@]}"; do
      echo "  - $s"
    done
  else
    echo
    echo "No high-risk change suggestions."
  fi

  if ((${#SAFE_SUGGESTIONS[@]})); then
    echo
    echo "${GREEN}Safer / incremental hardening suggestions:${NC}"
    for s in "${SAFE_SUGGESTIONS[@]}"; do
      echo "  - $s"
    done
  else
    echo
    echo "No additional low-risk suggestions."
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}[ERROR]${NC} Please run this script as root (sudo) for full checks."
    exit 1
  fi
}

# Add a row to CSV: category,item,status,severity,detail,recommendation
add_csv() {
  local category="$1"
  local item="$2"
  local status="$3"
  local severity="$4"
  local detail="$5"
  local recommendation="$6"

  # Sanitize: replace quotes and newlines
  detail="${detail//$'\n'/ }"
  recommendation="${recommendation//$'\n'/ }"
  detail="${detail//\"/\'}"
  recommendation="${recommendation//\"/\'}"

  echo "\"$category\",\"$item\",\"$status\",\"$severity\",\"$detail\",\"$recommendation\"" >> "$CSV_FILE"
}

########################
# Basic system info    #
########################

check_system_info() {
  section "System information (context only)"
  local host kernel osname time_utc
  host="$(hostname)"
  kernel="$(uname -r)"
  time_utc="$(date -u)"

  echo "  Hostname: $host"
  echo "  Kernel  : $kernel"
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    osname="$PRETTY_NAME"
    echo "  OS      : $osname"
  else
    osname="unknown"
  fi
  echo "  Time    : $time_utc (UTC)"

  add_csv "system" "hostname" "INFO" "low" "$host" "Record for context."
  add_csv "system" "kernel" "INFO" "low" "$kernel" "Record for context."
  add_csv "system" "os" "INFO" "low" "$osname" "Record for context."
  add_csv "system" "time_utc" "INFO" "low" "$time_utc" "Record for context."
}

###################################
# SSH hardening (ISO A.9 / A.13)  #
###################################

check_ssh_root_login() {
  section "SSH: root login"

  if ! command -v sshd >/dev/null 2>&1; then
    info "sshd not found (SSH server may not be installed)."
    add_csv "ssh" "PermitRootLogin" "INFO" "low" "sshd not installed" "No SSH daemon detected; skip."
    return
  fi

  if grep -iE '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -qi "PermitRootLogin"; then
    ok "PermitRootLogin is set to 'no' (root login via SSH disabled)."
    add_csv "ssh" "PermitRootLogin" "OK" "low" "PermitRootLogin no" "No change required."
  else
    warn "PermitRootLogin is not set to 'no' (root SSH login might be allowed; recommended: PermitRootLogin no)."
    add_csv "ssh" "PermitRootLogin" "WARN" "high" "PermitRootLogin not set to 'no'" \
      "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd."
    echo "    Recommendation: in /etc/ssh/sshd_config add or change:"
    echo "      PermitRootLogin no"
    echo "    Then reload SSH:"
    echo "      systemctl reload sshd  # or: systemctl reload ssh"
  fi
}

check_ssh_password_auth() {
  section "SSH: password authentication"

  if ! command -v sshd >/dev/null 2>&1; then
    info "sshd not found (SSH server may not be installed)."
    add_csv "ssh" "PasswordAuthentication" "INFO" "low" "sshd not installed" "No SSH daemon detected; skip."
    return
  fi

  if grep -iE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -qi "PasswordAuthentication"; then
    ok "PasswordAuthentication is set to 'no' (only key-based SSH logins allowed)."
    add_csv "ssh" "PasswordAuthentication" "OK" "medium" "PasswordAuthentication no" \
      "Use SSH keys; monitor key hygiene."
  else
    warn "PasswordAuthentication is not set to 'no' (password SSH logins allowed; recommended: PasswordAuthentication no)."
    add_csv "ssh" "PasswordAuthentication" "WARN" "medium" "PasswordAuthentication not set to 'no'" \
      "Enforce key-based auth: set 'PasswordAuthentication no' after configuring keys and reload sshd."
    echo "    Recommendation: in /etc/ssh/sshd_config add or change:"
    echo "      PasswordAuthentication no"
    echo "    Ensure you have SSH keys configured first!"
    echo "    Then reload SSH:"
    echo "      systemctl reload sshd  # or: systemctl reload ssh"
  fi
}

#########################################
# Shared: collect public-facing ports   #
#########################################

ensure_public_ports_collected() {
  # If already collected, skip
  if ((${#PUBLIC_PORTS[@]})); then
    return 0
  fi

  local cmd_output
  if command -v ss >/dev/null 2>&1; then
    cmd_output="$(ss -tuln 2>/dev/null | awk 'NR>1 {print $1,$5}')"
  elif command -v netstat >/dev/null 2>&1; then
    cmd_output="$(netstat -tuln 2>/dev/null | awk 'NR>2 {print $1,$4}')"
  else
    return 1
  fi

  [ -z "$cmd_output" ] && return 0

  while read -r proto addrport; do
    [ -z "$proto" ] && continue
    local addr port
    addr="${addrport%:*}"
    port="${addrport##*:}"

    [ "$addr" = "*" ] && addr="0.0.0.0"

    # Skip loopback-only ports: only care about public/non-loopback
    if [[ "$addr" == "127.0.0.1" || "$addr" == "::1" || "$addr" == "[::1]" || "$addr" == "localhost" ]]; then
      continue
    fi

    PUBLIC_PORTS+=("$proto $addr $port")
  done <<< "$cmd_output"

  return 0
}

#########################################
# Network: ports / routes               #
#########################################

check_listening_ports() {
  section "Network: listening TCP/UDP ports (public-facing only)"

  if ! ensure_public_ports_collected; then
    warn "Neither 'ss' nor 'netstat' found; cannot list listening ports (recommended: have one of these tools installed)."
    add_csv "network_port" "tool_missing" "WARN" "medium" "ss/netstat unavailable" \
      "Install iproute2 (ss) or net-tools (netstat) to inspect ports."
    return
  fi

  if ((${#PUBLIC_PORTS[@]} == 0)); then
    ok "No public-facing listening ports found (only localhost-bound or no services)."
    add_csv "network_port" "public_ports" "OK" "low" "No non-loopback listening ports detected" \
      "Confirm this matches the intended role of the server."
    return
  fi

  echo "  Public-facing listening ports (excluding localhost):"
  local p
  for p in "${PUBLIC_PORTS[@]}"; do
    local proto addr port status severity detail
    read -r proto addr port <<< "$p"

    status="INFO"
    severity="low"
    detail="Listening on $addr:$port via $proto (non-loopback)."

    if [[ "$addr" == "0.0.0.0" || "$addr" == "[::]" || "$addr" == "::" ]]; then
      status="WARN"
      severity="medium"
      detail="Listening on $addr:$port via $proto (all interfaces / potentially public-facing; recommended: bind to specific interface or protect with firewall)."
    fi

    echo "    $proto $addr:$port"
    add_csv "network_port" "${proto}_${port}" "$status" "$severity" \
      "$detail" \
      "If this service should not be publicly reachable, bind to localhost/internal IP or restrict via firewall."
  done
}

check_routes() {
  section "Network: routing table"

  if command -v ip >/dev/null 2>&1; then
    local rt
    rt="$(ip route show 2>/dev/null)"
    if [ -z "$rt" ]; then
      warn "'ip route show' returned no routes (recommended: confirm network configuration)."
      add_csv "route" "none" "WARN" "medium" "No routes visible from 'ip route show'" \
        "Check network configuration (interfaces, DHCP, static routes)."
      return
    fi

    echo "  Routing table:"
    echo "$rt" | sed 's/^/    /'

    local default_count
    default_count="$(echo "$rt" | awk '$1=="default" {c++} END {print c+0}')"

    if [ "$default_count" -gt 1 ]; then
      warn "Multiple default routes detected ($default_count; recommended: usually a single default gateway)."
      add_csv "route" "default_routes" "WARN" "medium" "$default_count default routes present" \
        "Review and clean up multiple default gateways unless intentionally configured."
    else
      ok "Single or zero default route detected (count=$default_count; typical for most hosts)."
      add_csv "route" "default_routes" "OK" "low" "$default_count default routes present" \
        "Ensure the default gateway matches network design."
    fi

    while read -r line; do
      [ -z "$line" ] && continue
      add_csv "route" "route_entry" "INFO" "low" "$line" "Verify this route is required and correct."
    done <<< "$rt"
  else
    warn "'ip' command not found (recommended: install iproute2 to manage routing)."
    add_csv "route" "tool_missing" "WARN" "medium" "ip(8) command missing" \
      "Install iproute2 to manage and inspect routing."
  fi
}

#########################################
# Logging & audit (ISO A.12.4 / A.12.7) #
#########################################

check_auditd() {
  section "Auditd (system auditing)"

  local audit_active=0
  local auditd_present=0

  if command -v auditctl >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -q auditd.service; then
    auditd_present=1
    if systemctl is-enabled auditd >/dev/null 2>&1 && systemctl is-active auditd >/dev/null 2>&1; then
      audit_active=1
    fi
  fi

  if [ "$auditd_present" -eq 1 ] && [ "$audit_active" -eq 1 ]; then
    ok "auditd is installed, enabled and running (system audit logging in place)."
    add_csv "audit" "auditd" "OK" "high" "auditd enabled and running" \
      "Review audit rules to ensure coverage of privileged operations & security events."

    echo
    echo "  Active audit rules (auditctl -l):"
    if command -v auditctl >/dev/null 2>&1; then
      local rules
      rules="$(auditctl -l 2>/dev/null)"
      if [ -n "$rules" ]; then
        echo "$rules" | sed 's/^/    /'
      else
        info "auditctl -l returned no rules (possible minimal or rules-file-based setup)."
      fi
    else
      info "auditctl command not found even though auditd appears active; cannot list rules automatically."
    fi

    # Even when active, it’s useful (but not mandatory) to suggest verifying baseline coverage.
    add_safe_suggestion "Review existing auditd rules (above) to ensure critical coverage: identity files, sudoers changes, audit config, and privileged binaries."
    return
  fi

  # If we’re here: auditd missing or not active -> show recommendations
  if [ "$auditd_present" -eq 1 ] && [ "$audit_active" -eq 0 ]; then
    warn "auditd is installed but not enabled/active (recommended: enable to have system auditing)."
    add_csv "audit" "auditd" "WARN" "high" "auditd installed but not enabled/active" \
      "Enable auditd and configure baseline rules."
    echo "    Recommendation:"
    echo "      apt install auditd audispd-plugins    # Debian/Ubuntu"
    echo "      or: dnf install audit                 # RHEL/CentOS"
    echo "      systemctl enable --now auditd"
  fi

  if [ "$auditd_present" -eq 0 ]; then
    warn "auditd is not installed (no dedicated audit trail; recommended: install and configure auditd)."
    add_csv "audit" "auditd" "WARN" "high" "auditd not installed" \
      "Install auditd and define audit rules for critical activities."
    echo "    Recommendation:"
    echo "      apt install auditd audispd-plugins    # Debian/Ubuntu"
    echo "      or: dnf install audit                 # RHEL/CentOS"
  fi

  echo
  echo "  Suggested baseline audit rules (Debian-style, /etc/audit/rules.d/99-hardening.rules):"
  echo "    # Watch account & identity files:"
  echo "    -w /etc/passwd -p wa -k identity"
  echo "    -w /etc/group  -p wa -k identity"
  echo "    -w /etc/shadow -p wa -k identity"
  echo
  echo "    # Watch sudoers configuration:"
  echo "    -w /etc/sudoers   -p wa -k scope"
  echo "    -w /etc/sudoers.d -p wa -k scope"
  echo
  echo "    # Watch changes to audit configuration itself:"
  echo "    -w /etc/audit/      -p wa -k auditconfig"
  echo "    -w /var/log/audit/  -p wa -k auditlog"
  echo
  echo "    # Track use of key privileged binaries:"
  echo "    -w /usr/bin/sudo    -p x -k priv_esc"
  echo "    -w /bin/su          -p x -k priv_esc"
  echo "    -w /usr/bin/passwd  -p x -k passwd_changes"
  echo
  echo "  To apply on most systems:"
  echo "    1) Create a file, e.g.:"
  echo "         /etc/audit/rules.d/99-hardening.rules"
  echo "       and put the rules above in it."
  echo "    2) Load rules:"
  echo "         augenrules --load"
  echo "       or restart auditd:"
  echo "         systemctl restart auditd"

  add_safe_suggestion "Define an auditd baseline (e.g. /etc/audit/rules.d/99-hardening.rules) and load it with 'augenrules --load'."
  add_risky_suggestion "Enabling auditd with a very verbose rule set on a busy production server can increase I/O and log volume significantly. Start with a focused baseline and monitor impact before expanding coverage."
}

check_syslog() {
  section "System logging"

  if systemctl is-active rsyslog >/dev/null 2>&1 || \
     systemctl is-active syslog-ng >/dev/null 2>&1 || \
     systemctl is-active systemd-journald >/dev/null 2>&1; then
    ok "System logging service is active (journald/rsyslog/syslog-ng)."
    add_csv "logging" "syslog" "OK" "high" "System logging active" \
      "Ensure central log forwarding, retention and protection as per policy."
  else
    warn "No active system logging service detected (recommended: enable journald/rsyslog/syslog-ng)."
    add_csv "logging" "syslog" "WARN" "high" "No active syslog/journald service detected" \
      "Enable rsyslog/syslog-ng/systemd-journald and configure log retention/forwarding."
    echo "    Recommendation: enable a logging service, e.g.:"
    echo "      systemctl enable --now rsyslog"
  fi
}

#########################################
# File permissions (ISO A.9 / A.11)     #
#########################################

check_world_writable_files() {
  section "World-writable files (non-root owner)"

  local ww
  ww=$(find / -xdev -type f -perm -0002 ! -user root 2>/dev/null | head -n 10)

  if [ -z "$ww" ]; then
    ok "No world-writable files (non-root) found on root filesystem (sample of up to 10)."
    add_csv "filesystem" "world_writable_nonroot" "OK" "medium" "None found (sample up to 10)" \
      "Periodically scan entire filesystem for world-writable files."
  else
    warn "Found world-writable files not owned by root (recommended: restrict 'other write' permission)."
    echo "$ww" | sed 's/^/    /'
    add_csv "filesystem" "world_writable_nonroot" "WARN" "high" "At least one world-writable non-root file detected" \
      "Restrict permissions/ownership on these files (e.g., chmod o-w <file>)."
    echo "    Example mitigation:"
    echo "      chmod o-w <file>"
  fi
}

check_home_permissions() {
  section "Home directory permissions"

  local issues=0
  for dir in /home/*; do
    [ -d "$dir" ] || continue
    perms=$(stat -c "%a" "$dir" 2>/dev/null || echo "")
    [ -z "$perms" ] && continue
    if [ "$perms" -gt 750 ]; then
      warn "Home directory $dir has permissive mode $perms (recommended: 750 or 700 for user privacy)."
      add_csv "filesystem" "home_perms" "WARN" "medium" "Home $dir perms=$perms (recommended: <= 750)" \
        "Set 'chmod 750 $dir' (or 700 for stricter isolation)."
      issues=1
    fi
  done

  if [ "$issues" -eq 0 ]; then
    ok "Home directory permissions are <= 750 (reasonable default for user isolation)."
    add_csv "filesystem" "home_perms" "OK" "low" "All checked homes <= 750" \
      "No change required; enforce via baseline/hardening script."
  else
    echo "    Example mitigation:"
    echo "      chmod 750 /home/<user>"
  fi
}

#########################################
# Time sync (ISO A.12.4.4)             #
#########################################

check_time_sync() {
  section "Time synchronization"

  if systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
    ok "systemd-timesyncd is active (time sync enabled)."
    add_csv "time_sync" "systemd-timesyncd" "OK" "medium" "systemd-timesyncd active" \
      "Ensure NTP servers are corporate-approved."
    return
  fi

  if systemctl is-active chronyd >/dev/null 2>&1; then
    ok "chronyd is active (time sync enabled)."
    add_csv "time_sync" "chronyd" "OK" "medium" "chronyd active" \
      "Ensure chrony config uses approved NTP servers."
    return
  fi

  if systemctl is-active ntpd >/dev/null 2>&1 || systemctl is-active ntp >/dev/null 2>&1; then
    ok "ntp/ntpd is active (time sync enabled)."
    add_csv "time_sync" "ntp" "OK" "medium" "ntp/ntpd active" \
      "Verify ntp.conf uses correct servers."
    return
  fi

  warn "No common time synchronization service detected (recommended: enable systemd-timesyncd/chronyd/ntpd)."
  add_csv "time_sync" "none" "WARN" "high" "No time sync service detected" \
    "Enable systemd-timesyncd, chronyd or ntpd to keep clocks accurate."
  echo "    Recommendation: enable one of:"
  echo "      systemctl enable --now systemd-timesyncd"
  echo "      or: apt install chrony && systemctl enable --now chronyd"
}

#########################################
# Automatic updates (patching)         #
#########################################

check_auto_updates() {
  section "Automatic security updates"

  if command -v apt >/dev/null 2>&1; then
    if dpkg -l | grep -q unattended-upgrades 2>/dev/null; then
      if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && \
         grep -q 'APT::Periodic::Unattended-Upgrade "1";' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
        ok "unattended-upgrades is installed and appears enabled (automatic security updates active)."
        add_csv "patching" "unattended-upgrades" "OK" "medium" "unattended-upgrades enabled" \
          "Verify only security updates are auto-applied if required."
      else
        warn "unattended-upgrades is installed but may not be enabled (recommended: enable for security updates)."
        add_csv "patching" "unattended-upgrades" "WARN" "medium" "unattended-upgrades not clearly enabled" \
          "Run 'dpkg-reconfigure unattended-upgrades' and verify config."
        echo "    Recommendation:"
        echo "      dpkg-reconfigure unattended-upgrades"
      fi
    else
      warn "unattended-upgrades is not installed (no automatic security updates; recommended: install)."
      add_csv "patching" "unattended-upgrades" "WARN" "medium" "Package not installed" \
        "Install 'unattended-upgrades' and configure automatic security updates."
      echo "    Recommendation:"
      echo "      apt install unattended-upgrades"
      echo "      dpkg-reconfigure unattended-upgrades"
    fi
    return
  fi

  if command -v dnf >/dev/null 2>&1; then
    if rpm -qa | grep -qi dnf-automatic; then
      ok "dnf-automatic is installed (verify timers are enabled for automatic updates)."
      add_csv "patching" "dnf-automatic" "INFO" "medium" "dnf-automatic installed" \
        "Check 'systemctl list-timers | grep dnf-automatic' to ensure it's active."
      echo "    Check timers with:"
      echo "      systemctl list-timers | grep dnf-automatic"
    else
      warn "dnf-automatic is not installed (no automatic patch timer; recommended: install if policy allows)."
      add_csv "patching" "dnf-automatic" "WARN" "medium" "dnf-automatic not installed" \
        "Install 'dnf install dnf-automatic' and enable its timer."
      echo "    Recommendation:"
      echo "      dnf install dnf-automatic"
      echo "      systemctl enable --now dnf-automatic.timer"
    fi
    return
  fi

  info "Auto-update status for this distro not automatically checked (non-apt/dnf system)."
  add_csv "patching" "auto_updates" "INFO" "medium" "Unknown (non-apt/dnf system)" \
    "Configure automatic security updates as per OS vendor guidance."
}

#########################################
# Disk encryption hint (very high-level)
#########################################

check_disk_encryption() {
  section "Disk encryption (very high-level)"

  if lsblk -o TYPE,FSTYPE 2>/dev/null | grep -qi "crypto_LUKS"; then
    ok "LUKS-encrypted volumes detected (at least some encrypted storage present)."
    add_csv "encryption" "LUKS" "OK" "high" "crypto_LUKS volumes present" \
      "Ensure all sensitive partitions and swap are encrypted."
  else
    info "No LUKS volumes detected by lsblk (disk may still be encrypted via other means)."
    add_csv "encryption" "LUKS" "INFO" "medium" "No crypto_LUKS seen in lsblk" \
      "Verify full-disk/volume encryption via LUKS, hardware encryption, or cloud provider features."
    echo "    Recommendation: verify full-disk or volume encryption for sensitive data."
  fi
}

########################
# Main                 #
########################

main() {
  require_root

  CSV_FILE="${1:-iso270xx_linux_audit.csv}"
  echo "category,item,status,severity,detail,recommendation" > "$CSV_FILE"

  echo "${BOLD}Linux ISO 2700x-style baseline audit (read-only)${NC}"
  echo "CSV output: $CSV_FILE"

  check_system_info

  check_ssh_root_login
  check_ssh_password_auth

  check_listening_ports
  check_routes

  check_auditd
  check_syslog
  check_world_writable_files
  check_home_permissions
  check_time_sync
  check_auto_updates
  check_disk_encryption

  print_suggestions_summary

  echo
  echo "${BOLD}Done.${NC} Findings written to: ${BOLD}$CSV_FILE${NC}"
}

main "$@"
