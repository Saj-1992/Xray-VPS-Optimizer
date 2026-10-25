# shellcheck shell=bash
# ============================================================================
# modules/security.sh — Layer 3 optional hardening: UFW, fail2ban, SSH.
#
# Everything here is consent-based (CLAUDE.md rule 1). fail2ban is the only
# resident service in the whole project and its cost is stated before the
# user agrees. The SSH allow rule always lands before any deny rule, and the
# sshd drop-in is validated with `sshd -t` before restart — no lockouts.
# ============================================================================

readonly ST_F2B_JAIL='/etc/fail2ban/jail.d/99-server-tools.local'
# sshd applies the FIRST value it sees for a keyword and reads the drop-in
# directory in lexical order, so a 99- file loses against the cloud-init
# 50-cloud-init.conf that ships with most images. 00- wins.
readonly ST_SSHD_DROPIN='/etc/ssh/sshd_config.d/00-server-tools.conf'
readonly ST_SSHD_DROPIN_LEGACY='/etc/ssh/sshd_config.d/99-server-tools.conf'

# detect_ssh_port — the port sshd really listens on. `sshd -T` is the only
# source that accounts for drop-ins; the config file and `ss` are fallbacks.
# Nothing is parsed through a pipe: an early-exiting awk would SIGPIPE the
# producer and pipefail would then discard a perfectly good answer — and
# guessing 22 here could lock the user out through the firewall rules.
detect_ssh_port() {
  local port='' out=''
  if has_cmd sshd; then
    out="$(sshd -T 2>/dev/null)" || out=''
    [[ -n $out ]] && port="$(awk '$1 == "port" {print $2; exit}' <<<"$out")"
  fi
  if [[ -z $port ]]; then
    port="$(awk '/^[[:space:]]*[Pp]ort[[:space:]]/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)" || port=''
  fi
  if [[ -z $port ]] && has_cmd ss; then
    out="$(ss -tnlp 2>/dev/null)" || out=''
    [[ -n $out ]] && port="$(awk '/sshd/ {sub(/.*:/, "", $4); print $4; exit}' <<<"$out")"
  fi
  [[ $port =~ ^[0-9]+$ ]] || port=22
  printf '%s' "$port"
}

# _ssh_session_port — the server-side port of the SSH session running this
# tool (from SSH_CONNECTION), empty when not run over SSH. It can differ from
# the configured port (NAT, port forwarding), and blocking it drops the user.
_ssh_session_port() {
  local port
  port="$(awk '{print $4}' <<<"${SSH_CONNECTION:-}")"
  [[ $port =~ ^[0-9]+$ ]] && printf '%s' "$port"
  return 0
}

security_ufw() {
  ui_section "UFW firewall"
  if ! has_cmd ufw; then
    ui_confirm "UFW is not installed. Install it now?" || return 0
    if ! pkg_install ufw; then
      log_error "UFW installation failed — see the log."
      return 0
    fi
  fi

  local ssh_port
  ssh_port="$(detect_ssh_port)"
  printf 'Detected SSH port: %s — it is allowed FIRST, so you cannot be locked out.\n' "$ssh_port"
  if ! ufw allow "${ssh_port}/tcp" >/dev/null 2>>"$ST_LOG_FILE"; then
    log_error "Could not add the SSH allow rule — aborting before any deny rule."
    return 0
  fi
  # Safety net 1: the port THIS session arrived on is always allowed too.
  local session_port
  session_port="$(_ssh_session_port)"
  if [[ -n $session_port && $session_port != "$ssh_port" ]]; then
    printf '%sYou are connected through port %s (sshd listens on %s) — allowing both.%s\n' \
      "$C_WARN" "$session_port" "$ssh_port" "$C_RESET"
    ufw allow "${session_port}/tcp" >/dev/null 2>>"$ST_LOG_FILE" ||
      log_warn "Could not allow your current session port ${session_port}."
  fi
  ufw default deny incoming >/dev/null 2>>"$ST_LOG_FILE" || log_warn "Could not set default deny incoming."
  ufw default allow outgoing >/dev/null 2>>"$ST_LOG_FILE" || log_warn "Could not set default allow outgoing."

  local ports p
  read -rp "Extra ports to allow (e.g. 443/tcp 80/tcp 51820/udp) [Enter=none]: " ports || ports=''
  if [[ -n $ports ]]; then
    local IFS=' ' # the global IFS has no space — restore word splitting here
    for p in $ports; do
      if [[ $p =~ ^[0-9]+(/(tcp|udp))?$ ]]; then
        ufw allow "$p" >/dev/null 2>>"$ST_LOG_FILE" || log_warn "Rule failed: ${p}"
      else
        log_warn "Skipped invalid port spec: ${p}"
      fi
    done
  fi

  # Safety net 2: services that listen publicly right now would go dark the
  # moment UFW denies by default. Show them and offer to keep them open.
  local open_ports='' lp
  while IFS= read -r lp; do
    [[ $lp =~ ^[0-9]+$ ]] || continue
    ufw status 2>/dev/null | grep -qE "^${lp}(/| )" && continue
    [[ $lp == "$ssh_port" || $lp == "$session_port" ]] && continue
    open_ports+="${lp} "
  done < <(listening_service_ports)
  if [[ -n $open_ports ]]; then
    printf '%sThese ports are serving clients right now but have no allow rule:%s %s\n' \
      "$C_WARN" "$C_RESET" "$open_ports"
    printf 'Enabling UFW without them would cut your users off.\n'
    if ui_confirm_yes "Allow them (tcp+udp) so nothing breaks?"; then
      for lp in $open_ports; do
        ufw allow "$lp" >/dev/null 2>>"$ST_LOG_FILE" || log_warn "Rule failed: ${lp}"
      done
    fi
  fi

  if has_cmd docker && docker ps -q 2>/dev/null | grep -q .; then
    printf '%sWarning:%s Docker publishes container ports directly in iptables and\n' "$C_WARN" "$C_RESET"
    printf 'BYPASSES UFW — published panel/node ports stay reachable regardless of\n'
    printf 'these rules (see Network tools > Docker+UFW audit).\n'
  fi

  if ui_confirm "Enable UFW now?"; then
    if ufw --force enable >/dev/null 2>>"$ST_LOG_FILE"; then
      printf '%sUFW enabled.%s\n' "$C_OK" "$C_RESET"
      ufw status verbose 2>/dev/null || log_warn "Could not print UFW status."
    else
      log_error "Enabling UFW failed — see the log."
      return 0
    fi
  fi
  printf '%sNote:%s firewall state is not covered by manifest rollback — revert with: ufw disable\n' \
    "$C_MUTED" "$C_RESET"
  log_info "UFW configured (SSH ${ssh_port}/tcp allowed)."
}

security_fail2ban() {
  ui_section "fail2ban (SSH brute-force protection)"
  printf 'fail2ban runs as a small resident service (~20 MB RAM) — the only\n'
  printf 'exception to the zero-footprint rule, and only with your consent.\n'
  ui_confirm "Install and enable fail2ban?" || return 0

  if ! has_cmd fail2ban-server && ! pkg_install fail2ban; then
    log_error "fail2ban installation failed — see the log."
    return 0
  fi

  local ssh_port
  ssh_port="$(detect_ssh_port)"
  st_track_file "$ST_F2B_JAIL"
  mkdir -p "$(dirname "$ST_F2B_JAIL")"
  cat >"$ST_F2B_JAIL" <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
[sshd]
enabled = true
port = ${ssh_port}
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF

  if has_cmd systemctl &&
    systemctl enable fail2ban >/dev/null 2>>"$ST_LOG_FILE" &&
    systemctl restart fail2ban 2>>"$ST_LOG_FILE"; then
    printf '%sfail2ban active%s (sshd jail on port %s, ban 1h after 5 tries).\n' \
      "$C_OK" "$C_RESET" "$ssh_port"
    log_info "fail2ban enabled (sshd jail, port ${ssh_port})."
  else
    log_error "fail2ban could not be enabled — see the log."
  fi
}

security_ssh() {
  ui_section "SSH hardening"
  if [[ ! -d /etc/ssh/sshd_config.d ]]; then
    log_warn "This system has no /etc/ssh/sshd_config.d — skipping (editing sshd_config in place is not safe enough)."
    return 0
  fi

  local lines=('UseDNS no')
  if [[ -s /root/.ssh/authorized_keys ]]; then
    printf 'An SSH key for root exists.\n'
    printf '%sVerify key login works in a second terminal BEFORE confirming.%s\n' "$C_WARN" "$C_RESET"
    printf 'Typing KEY-OK below means you tested it. Anything else keeps passwords on.
'
    local ack
    read -rp "Disable password authentication? [KEY-OK / Enter=no]: " ack || ack=''
    if [[ $ack == KEY-OK ]]; then
      lines+=('PasswordAuthentication no')
    fi
  else
    printf '%sNo /root/.ssh/authorized_keys found — password login stays enabled.%s\n' "$C_WARN" "$C_RESET"
  fi

  # A drop-in from an older version sorts after cloud-init and would keep
  # losing; remove it so only the winning file remains.
  if [[ -f $ST_SSHD_DROPIN_LEGACY ]]; then
    st_track_file "$ST_SSHD_DROPIN_LEGACY"
    rm -f "$ST_SSHD_DROPIN_LEGACY"
    log_info "Removed the superseded 99- SSH drop-in."
  fi

  st_track_file "$ST_SSHD_DROPIN"
  {
    printf '# Generated by %s v%s\n' "$ST_NAME" "$ST_VERSION"
    printf '%s\n' "${lines[@]}"
  } >"$ST_SSHD_DROPIN"

  if has_cmd sshd && ! sshd -t 2>>"$ST_LOG_FILE"; then
    rm -f "$ST_SSHD_DROPIN"
    log_error "sshd config validation failed — drop-in removed, nothing changed."
    return 1
  fi
  if has_cmd systemctl; then
    # Service name differs across distros (ssh on Debian/Ubuntu, sshd elsewhere).
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>>"$ST_LOG_FILE" ||
      log_warn "Could not restart sshd — settings apply on its next restart."
  fi

  # Verify against the effective configuration, not the file we wrote.
  local effective
  for effective in "${lines[@]}"; do
    ssh_effective_matches "$effective" || {
      log_warn "SSH setting '${effective}' is NOT in effect — another drop-in overrides it (check: sshd -T)."
      printf '%sWarning:%s "%s" did not take effect — see the log.\n' "$C_WARN" "$C_RESET" "$effective"
      return 3
    }
  done

  # "${lines[*]}" would join with the global IFS's newline and break this into
  # one line per setting; the entries contain spaces, so join with ", ".
  local summary
  summary="$(
    IFS=', '
    printf '%s' "${lines[*]}"
  )"
  printf '%sApplied and verified:%s %s\n' "$C_OK" "$C_RESET" "$summary"
  log_info "SSH hardening drop-in applied and verified: ${summary}"
  return 0
}

# ssh_effective_matches "Keyword value" — is that what sshd really uses?
ssh_effective_matches() {
  has_cmd sshd || return 0 # cannot check; do not claim failure
  local keyword value actual
  keyword="${1%% *}"
  value="${1#* }"
  actual="$(sshd -T 2>/dev/null | awk -v k="${keyword,,}" '$1 == k {print $2; exit}')" || actual=''
  [[ -z $actual ]] && return 0 # keyword unknown to this sshd build
  [[ ${actual,,} == "${value,,}" ]]
}

# ssh_verify — 0 when our drop-in exists and its settings are in effect.
ssh_verify() {
  [[ -f $ST_SSHD_DROPIN ]] || return 2
  local line
  while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    ssh_effective_matches "$line" || return 3
  done <"$ST_SSHD_DROPIN"
  return 0
}

# security_node_ports — a node's API port only ever talks to its panel.
security_node_api() {
  ui_section "Restrict node API ports to the panel"
  if ! has_cmd ufw; then
    log_error "UFW is not installed — set it up first (menu option 1)."
    return 2
  fi
  printf 'Marzban-node uses 62050/62051, pg-node 62050 by default. Leaving them\n'
  printf 'open to the internet exposes the service to every scanner.\n'
  local panel_ip ports port
  read -rp "Panel IP address (empty = cancel): " panel_ip || return 2
  [[ -n $panel_ip ]] || return 2
  if ! is_valid_ip "$panel_ip"; then
    log_error "'${panel_ip}' is not a valid IP address."
    return 1
  fi
  read -rp "API ports [62050,62051]: " ports || ports=''
  ports="${ports:-62050,62051}"

  local rc=0
  while IFS= read -r port; do
    [[ $port =~ ^[0-9]+$ ]] || {
      log_warn "Skipped invalid port '${port}'."
      continue
    }
    ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true # rule may simply not exist
    if ufw allow from "$panel_ip" to any port "$port" proto tcp >/dev/null 2>>"$ST_LOG_FILE"; then
      printf '  %s/tcp: only %s\n' "$port" "$panel_ip"
    else
      log_warn "Could not restrict port ${port}."
      rc=3
    fi
  done < <(ports_split "$ports")
  log_info "Node API ports restricted to ${panel_ip} (rc=${rc})."
  return "$rc"
}

security_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Security (Layer 3 — optional, consent-based)"
    ui_menu_item 1 "UFW firewall" "SSH-safe setup, extra ports, Docker warning"
    ui_menu_item 2 "fail2ban" "SSH brute-force bans (resident service ~20 MB)"
    ui_menu_item 3 "SSH hardening" "UseDNS off, optional key-only login (validated)"
    ui_menu_item 4 "Restrict node API" "panel-only access to 62050/62051"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        security_ufw
        ui_pause
        ;;
      2)
        security_fail2ban
        ui_pause
        ;;
      3)
        security_ssh || true # outcome already reported to the user
        ui_pause
        ;;
      4)
        security_node_api || true
        ui_pause
        ;;
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
