# shellcheck shell=bash
# ============================================================================
# modules/vpn.sh — VPN-aware non-sysctl fixes.
#
# Smart MTU/MSS: measures the real path MTU, then clamps MSS to it. A clamp is
# the most common fix for "WireGuard connects but pages
# don't load" behind NAT. Persistence uses a systemd ONESHOT unit: it runs
# once at boot and exits — no resident process, zero-footprint compliant.
# ============================================================================

readonly ST_MSS_UNIT='/etc/systemd/system/server-tools-mss.service'
readonly ST_MSS_UFW_MARK='# --- server-tools MSS clamping'

# _mss_rule FAMILY — the TCPMSS rule words for this host. A configured
# mss_value (measured path MTU − headers) wins over --clamp-mss-to-pmtu, which
# only knows the INTERFACE mtu and so does nothing when the real bottleneck is
# further along the path (tunnels, provider overlay, PPPoE).
# FAMILY is 4 or 6; the headers are 40 and 60 bytes. The value stored in
# config is the IPv4 MSS, so IPv6 subtracts 20 more.
_mss_rule() {
  local family="$1" value
  value="$(config_get mss_value 0)"
  [[ $value =~ ^[0-9]+$ ]] || value=0
  if ((value > 0)); then
    ((family == 6)) && value=$((value - 20))
    printf '%s\n' FORWARD -p tcp --tcp-flags 'SYN,RST' SYN -j TCPMSS --set-mss "$value"
  else
    printf '%s\n' FORWARD -p tcp --tcp-flags 'SYN,RST' SYN -j TCPMSS --clamp-mss-to-pmtu
  fi
}

# _mss_rule_words FAMILY — the rule as one space-joined string.
_mss_rule_words() {
  local -a words
  mapfile -t words < <(_mss_rule "$1")
  join_sp "${words[@]}"
}

# _mss_remove_live TOOL — delete every TCPMSS rule in FORWARD so a changed
# value replaces the old rule instead of stacking beside it.
_mss_remove_live() {
  local tool="$1" rule
  while IFS= read -r rule; do
    [[ $rule == -A\ FORWARD* ]] || continue
    # shellcheck disable=SC2086 # rule words are iptables syntax by design
    "$tool" -t mangle ${rule/-A /-D } 2>>"$ST_LOG_FILE" ||
      log_warn "Could not remove an old MSS rule from ${tool}."
  done < <("$tool" -t mangle -S FORWARD 2>/dev/null | grep -- '-j TCPMSS' || true) # no match is normal
}

# _mss_ufw_strip — remove our managed block from before.rules.
_mss_ufw_strip() {
  local rules="$1" tmp="${1}.st-tmp"
  awk -v mark="$ST_MSS_UFW_MARK" '
    index($0, mark) == 1 {skip = 1}
    skip {if ($0 == "COMMIT") {skip = 0}; next}
    {print}
  ' "$rules" >"$tmp" && cat "$tmp" >"$rules"
  rm -f "$tmp"
}

# _vpn_mss_ufw_persist — add the clamp to UFW's before.rules so `ufw reload`
# keeps it. The file is tracked first and restored if UFW refuses to reload.
_vpn_mss_ufw_persist() {
  local rules='/etc/ufw/before.rules' rule
  has_cmd ufw || return 2
  [[ -f $rules ]] || return 2
  rule="$(_mss_rule_words 4)"
  # Idempotent: the same rule already in place means nothing to do.
  grep -qF -- "-A ${rule}" "$rules" 2>/dev/null && return 0

  st_track_file "$rules"
  _mss_ufw_strip "$rules"
  cat >>"$rules" <<EOF

${ST_MSS_UFW_MARK} (managed block, safe to remove as a whole)
*mangle
:FORWARD - [0:0]
-A ${rule}
COMMIT
EOF

  if ufw status 2>/dev/null | grep -q '^Status: active'; then
    if ! ufw reload >/dev/null 2>>"$ST_LOG_FILE"; then
      cp -a "${ST_RUN_BACKUP_DIR}${rules}" "$rules"
      log_warn "UFW rejected the before.rules change — reverted; the clamp survives only until the next ufw reload."
      return 3
    fi
  fi
  log_info "MSS clamp persisted in ${rules}."
  return 0
}

# --- Path MTU measurement ---------------------------------------------------

# Public anycast resolvers answer ICMP everywhere and sit behind the same
# international path real users' traffic takes.
readonly -a ST_PMTU_TARGETS=(1.1.1.1 8.8.8.8)

# _pmtu_probe TARGET — largest IPv4 packet that crosses unfragmented, found by
# binary search with DF-flagged pings. Prints nothing and fails when the target
# does not answer a small ping or the ping tool lacks -M do.
_pmtu_probe() {
  local target="$1" lo=1200 hi=1500 mid
  has_cmd ping || return 1
  ping -c1 -W2 -s 56 "$target" >/dev/null 2>&1 || return 1
  ping -M "do" -c1 -W1 -s $((lo - 28)) "$target" >/dev/null 2>&1 || return 1
  while ((lo < hi)); do
    mid=$(((lo + hi + 1) / 2))
    if ping -M "do" -c1 -W1 -s $((mid - 28)) "$target" >/dev/null 2>&1; then
      lo=$mid
    else
      hi=$((mid - 1))
    fi
  done
  printf '%s' "$lo"
}

# Lowest measured path MTU (0 = unknown) and the default interface's MTU.
ST_PMTU=0
ST_IFACE_MTU=0

# vpn_measure_mtu — fill ST_PMTU and ST_IFACE_MTU and print the evidence.
vpn_measure_mtu() {
  ST_PMTU=0
  ST_IFACE_MTU=0
  local iface target value
  iface="$(net_default_iface)" || iface=''
  if [[ -n $iface ]] && has_cmd ip; then
    ST_IFACE_MTU="$(ip -o link show dev "$iface" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "mtu") {print $(i + 1); exit}}')"
    [[ $ST_IFACE_MTU =~ ^[0-9]+$ ]] || ST_IFACE_MTU=0
  fi
  printf 'Interface %s%s%s MTU: %s\n' "$C_KEY" "${iface:-?}" "$C_RESET" "$((ST_IFACE_MTU))"
  for target in "${ST_PMTU_TARGETS[@]}"; do
    if value="$(_pmtu_probe "$target")"; then
      printf '  path to %-9s %s bytes\n' "$target" "$value"
      if ((ST_PMTU == 0 || value < ST_PMTU)); then
        ST_PMTU="$value"
      fi
    else
      printf '  path to %-9s %sno answer%s\n' "$target" "$C_MUTED" "$C_RESET"
    fi
  done
  return 0
}

# _wg_mtu_advice — compare each WireGuard interface with what the path allows.
_wg_mtu_advice() {
  has_cmd wg || return 0
  ((ST_PMTU > 0)) || return 0
  local wg_if mtu want
  want=$((ST_PMTU - 80)) # 60 (IPv4) / 80 (IPv6) bytes of WireGuard overhead; use the safe one
  for wg_if in $(wg show interfaces 2>/dev/null); do
    mtu="$(ip -o link show dev "$wg_if" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "mtu") {print $(i + 1); exit}}')"
    [[ $mtu =~ ^[0-9]+$ ]] || continue
    if ((mtu > want)); then
      printf '  %s  %s has MTU %s but this path carries at most %s — set "MTU = %s" in its config\n' \
        "$(ui_badge warn)" "$wg_if" "$mtu" "$want" "$want"
    else
      printf '  %s  %s MTU %s fits the path\n' "$(ui_badge ok)" "$wg_if" "$mtu"
    fi
  done
}

vpn_mss_clamp() {
  local rc_ufw=0 tool mss=0
  ui_section "Smart MTU / MSS (TCP over tunnels/NAT)"
  printf 'Measures the real path MTU toward the internet, then clamps TCP MSS to what\n'
  printf 'actually fits. Fixes "VPN connects but sites do not load" and the slow,\n'
  printf 'stalling pages that come from silent packet fragmentation.\n\n'
  if ! has_cmd iptables; then
    log_error "iptables not available — cannot apply MSS clamping."
    return 0
  fi

  vpn_measure_mtu
  if ((ST_PMTU > 0 && ST_IFACE_MTU > 0 && ST_PMTU < ST_IFACE_MTU)); then
    mss=$((ST_PMTU - 40))
    printf '\n%sThe path is narrower than the interface%s (%s < %s): fixed MSS %s is the right fix.\n' \
      "$C_WARN" "$C_RESET" "$ST_PMTU" "$ST_IFACE_MTU" "$mss"
  elif ((ST_PMTU > 0)); then
    printf '\n%sThe path carries the full interface MTU.%s Automatic clamping to the route MTU is enough.\n' \
      "$C_OK" "$C_RESET"
  else
    printf '\n%sCould not measure the path%s (ICMP filtered or no connectivity) — using automatic clamping.\n' \
      "$C_WARN" "$C_RESET"
  fi
  _wg_mtu_advice
  ui_confirm_yes "Apply MSS clamping now?" || return 0

  config_set mss_value "$mss"
  for tool in iptables ip6tables; do
    has_cmd "$tool" || continue
    _mss_remove_live "$tool"
    local -a rule
    if [[ $tool == iptables ]]; then
      mapfile -t rule < <(_mss_rule 4)
    else
      mapfile -t rule < <(_mss_rule 6)
    fi
    if ! "$tool" -t mangle -A "${rule[@]}" 2>>"$ST_LOG_FILE"; then
      if [[ $tool == iptables ]]; then
        log_error "Could not add the IPv4 MSS rule — see the log."
        return 0
      fi
      log_warn "IPv6 MSS rule failed (IPv6 clamping skipped)."
    fi
  done

  # UFW rebuilds the whole ruleset on `ufw reload` and at boot, wiping rules
  # added with plain iptables. When UFW owns the firewall, the clamp belongs
  # in before.rules so it is restored with everything else.
  _vpn_mss_ufw_persist || rc_ufw=$?

  if [[ -d /etc/systemd/system ]] && has_cmd systemctl; then
    local ipt ip6t
    ipt="$(command -v iptables)"
    ip6t="$(command -v ip6tables)" || ip6t=''
    st_track_file "$ST_MSS_UNIT"
    {
      printf '# Generated by %s v%s\n' "$ST_NAME" "$ST_VERSION"
      printf '[Unit]\nDescription=ServerTools MSS clamping (oneshot, exits after boot)\nAfter=network-pre.target\nWants=network-pre.target\n\n'
      printf '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
      printf 'ExecStart=%s -t mangle -A %s\n' "$ipt" "$(_mss_rule_words 4)"
      [[ -n $ip6t ]] && printf 'ExecStart=%s -t mangle -A %s\n' "$ip6t" "$(_mss_rule_words 6)"
      printf '\n[Install]\nWantedBy=multi-user.target\n'
    } >"$ST_MSS_UNIT"
    systemctl daemon-reload 2>>"$ST_LOG_FILE" || log_warn "daemon-reload failed."
    if systemctl enable server-tools-mss.service >/dev/null 2>>"$ST_LOG_FILE"; then
      manifest_add unit server-tools-mss.service
    else
      log_warn "Could not enable boot persistence for the MSS rule."
    fi
  else
    log_warn "No systemd — the MSS rule is active now but will not survive a reboot."
  fi

  if ((rc_ufw == 0)); then
    printf '%sMSS clamping active%s (persisted for reboots and for "ufw reload").\n' \
      "$C_OK" "$C_RESET"
  else
    printf '%sMSS clamping active%s (persisted via oneshot unit — nothing stays running).\n' \
      "$C_OK" "$C_RESET"
  fi
  log_info "MSS clamping applied (mss_value=${mss}, ufw persistence rc=${rc_ufw})."
}

# mss_verify — 0 when the clamp rule is present in the live mangle table.
mss_verify() {
  has_cmd iptables || return 2
  local -a rule
  mapfile -t rule < <(_mss_rule 4)
  iptables -t mangle -C "${rule[@]}" 2>/dev/null && return 0
  # Only report drift when we were actually asked to set it up.
  [[ -f $ST_MSS_UNIT ]] && return 3
  return 2
}

# ---------------------------------------------------------------------------
# NOTRACK — exempt userspace-proxy data ports from connection tracking.
#
# A Reality/Xray/Trojan/Hysteria node terminates every inbound connection in
# userspace and opens its OWN outbound sockets; the kernel never NATs the
# inbound leg, so the conntrack entry it creates for each of the millions of
# short-lived client connections is pure overhead. Exempting the proxy data
# ports (raw table, both directions) keeps the conntrack table near-empty — it
# can no longer hit nf_conntrack_max under load — and removes the per-packet
# tracking cost on the hottest path on the box.
#
# Never applied to a WireGuard/NAT port (that genuinely needs conntrack) or to
# SSH (kept tracked for fail2ban/stateful rules); both are excluded below.
# ---------------------------------------------------------------------------
readonly ST_NOTRACK_UNIT='/etc/systemd/system/server-tools-notrack.service'
# Filled by _notrack_detect_target: the working "no-track" target for this
# kernel — modern "-j CT --notrack" or the legacy "-j NOTRACK" alias.
ST_NOTRACK_TARGET=()

# _notrack_detect_target — probe which raw NOTRACK target this kernel accepts,
# by adding then removing one harmless rule on an unused high port.
_notrack_detect_target() {
  has_cmd iptables || return 1
  local probe=65533 form
  local -a probe_args=()
  for form in 'CT --notrack' 'NOTRACK'; do
    # Split explicitly: with the global IFS ($'\n\t') an unquoted $form does NOT
    # word-split, so iptables would receive "-j CT --notrack" as a single
    # argument and reject every rule.
    IFS=' ' read -ra probe_args <<<"-j ${form}"
    if iptables -t raw -A OUTPUT -p tcp --dport "$probe" "${probe_args[@]}" 2>/dev/null; then
      iptables -t raw -D OUTPUT -p tcp --dport "$probe" "${probe_args[@]}" 2>/dev/null ||
        log_warn "Could not remove the NOTRACK probe rule (port ${probe})."
      ST_NOTRACK_TARGET=("${probe_args[@]}")
      return 0
    fi
  done
  return 1
}

# _notrack_specs PORT — the rule bodies (everything after "-A") for one port,
# one per line. Single source of truth shared by apply, persist and verify.
_notrack_specs() {
  local port="$1" proto
  for proto in tcp udp; do
    printf 'PREROUTING -p %s --dport %s\n' "$proto" "$port"
    printf 'OUTPUT -p %s --sport %s\n' "$proto" "$port"
  done
}

# _notrack_dnat_ports — host ports that a DNAT/REDIRECT rule forwards (Docker
# `-p`, manual port-forwards). NOTRACK skips the nat table, so exempting one of
# these silently breaks its forwarding — fatal with docker userland-proxy off.
_notrack_dnat_ports() {
  has_cmd iptables || return 0
  local out out6=''
  out="$(iptables -t nat -S 2>/dev/null)" || out=''
  if has_cmd ip6tables; then
    out6="$(ip6tables -t nat -S 2>/dev/null)" || out6=''
  fi
  printf '%s\n%s\n' "$out" "$out6" |
    grep -E -- '-j (DNAT|REDIRECT)' |
    grep -oE -- '--dport [0-9]+' |
    awk '{print $2}' | sort -un
}

# _notrack_candidates SSH WG DNAT — listening TCP ports worth exempting:
# everything with a listener, minus the ports that must keep conntrack
# (SSH, WireGuard, and any DNAT/Docker-forwarded port).
_notrack_candidates() {
  has_cmd ss || return 0
  local excl listeners
  excl="$(printf '%s\n%s\n%s\n' "$1" "$2" "$3" | grep -E '^[0-9]+$' | sort -un)"
  listeners="$(ss -tln 2>/dev/null)" || return 0
  # Same reachability rule as the reserved-ports logic: a loopback-only listener
  # is internal plumbing, so exempting it from conntrack would buy nothing.
  _ss_listen_ports "$listeners" | _ports_subtract "$excl" | paste -sd, -
}

# _notrack_sanitize LIST — keep valid 1..65535 ports, dedup, comma-join.
_notrack_sanitize() {
  local tok out=()
  while IFS= read -r tok; do
    if [[ $tok =~ ^[0-9]+$ ]] && ((tok >= 1 && tok <= 65535)); then out+=("$tok"); fi
  done < <(ports_split "$1")
  ((${#out[@]})) || return 0
  printf '%s\n' "${out[@]}" | sort -un | paste -sd, -
}

# _notrack_drop_ports LIST DROP — LIST minus DROP (either comma- or newline-
# separated), dedup, comma-join. Empty output is a valid result.
_notrack_drop_ports() {
  local drop
  drop="$(tr ',' '\n' <<<"$2" | grep -E '^[0-9]+$' | sort -un)"
  tr ',' '\n' <<<"$1" | grep -E '^[0-9]+$' | sort -un | _ports_subtract "$drop" | paste -sd, -
}

# _notrack_apply_live PORTS... — add the rules idempotently to IPv4 (+IPv6).
_notrack_apply_live() {
  local port spec bin
  local -a rule=()
  for bin in iptables ip6tables; do
    has_cmd "$bin" || continue
    for port in "$@"; do
      while IFS= read -r spec; do
        # Each token must be its own argv entry (the global IFS would not split
        # an unquoted $spec, handing iptables one nonsense argument).
        IFS=' ' read -ra rule <<<"$spec"
        "$bin" -t raw -C "${rule[@]}" "${ST_NOTRACK_TARGET[@]}" 2>/dev/null && continue
        "$bin" -t raw -A "${rule[@]}" "${ST_NOTRACK_TARGET[@]}" 2>>"$ST_LOG_FILE" ||
          log_warn "Could not add NOTRACK rule (${bin}): ${spec}"
      done < <(_notrack_specs "$port")
    done
  done
  return 0
}

# _notrack_write_unit PORTS... — a oneshot unit that re-adds the rules at boot
# and removes them on `systemctl disable --now` (so rollback clears them live).
_notrack_write_unit() {
  local port spec ipt ip6t tgt
  ipt="$(command -v iptables)"
  ip6t="$(command -v ip6tables)" || ip6t=''
  # join_sp, not "${arr[*]}": the global IFS would join with newlines and split
  # every ExecStart= across several broken lines.
  tgt="$(join_sp "${ST_NOTRACK_TARGET[@]}")"
  st_track_file "$ST_NOTRACK_UNIT"
  {
    printf '# Generated by %s v%s\n' "$ST_NAME" "$ST_VERSION"
    printf '[Unit]\nDescription=ServerTools conntrack NOTRACK for proxy ports (oneshot, exits after boot)\n'
    printf 'After=network-pre.target\nWants=network-pre.target\n\n'
    printf '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
    for port in "$@"; do
      while IFS= read -r spec; do
        printf 'ExecStart=%s -t raw -A %s %s\n' "$ipt" "$spec" "$tgt"
        [[ -n $ip6t ]] && printf 'ExecStart=%s -t raw -A %s %s\n' "$ip6t" "$spec" "$tgt"
      done < <(_notrack_specs "$port")
    done
    for port in "$@"; do
      while IFS= read -r spec; do
        # "-" prefix: a rule already gone at stop time is not an error.
        printf 'ExecStop=-%s -t raw -D %s %s\n' "$ipt" "$spec" "$tgt"
        [[ -n $ip6t ]] && printf 'ExecStop=-%s -t raw -D %s %s\n' "$ip6t" "$spec" "$tgt"
      done < <(_notrack_specs "$port")
    done
    printf '\n[Install]\nWantedBy=multi-user.target\n'
  } >"$ST_NOTRACK_UNIT"
  return 0
}

# _notrack_unit_ports — ports the persisted unit covers (self-describing, so
# verify needs no config state and reports "not configured" after rollback).
_notrack_unit_ports() {
  [[ -f $ST_NOTRACK_UNIT ]] || return 0
  grep -oE -- '--dport [0-9]+' "$ST_NOTRACK_UNIT" | awk '{print $2}' | sort -un
}

vpn_conntrack_bypass() {
  ui_section "NOTRACK — take proxy ports out of connection tracking"
  printf 'On a userspace-proxy node (Xray/Reality, VLESS/VMess/Trojan, Hysteria)\n'
  printf 'every inbound connection creates a conntrack entry the proxy never needs:\n'
  printf 'it terminates traffic in userspace and opens its own outbound sockets.\n'
  printf 'Exempting the proxy data ports keeps the conntrack table near-empty, so\n'
  printf 'it cannot fill under load and the per-packet tracking cost disappears.\n\n'
  printf '%sTrade-off:%s the exempted ports lose stateful (ESTABLISHED/RELATED)\n' "$C_WARN" "$C_RESET"
  printf 'firewall matching, so they must be allowed by an explicit port rule —\n'
  printf 'which a proxy inbound always has. WireGuard/NAT and SSH ports are\n'
  printf 'excluded automatically because they genuinely need conntrack.\n\n'

  if ! has_cmd iptables; then
    log_error "iptables is not available — cannot manage NOTRACK rules."
    return 0
  fi
  if ! _notrack_detect_target; then
    log_error "This kernel's iptables has no usable raw NOTRACK target — skipped."
    return 0
  fi

  local ssh_port wg_ports dnat_ports suggested
  ssh_port="$(detect_ssh_port)" || ssh_port=22
  # WireGuard must keep conntrack: it relies on NAT for client routing.
  wg_ports="$(wg_listen_ports)" || wg_ports=''
  dnat_ports="$(_notrack_dnat_ports)" || dnat_ports=''
  suggested="$(_notrack_candidates "$ssh_port" "$wg_ports" "$dnat_ports")" || suggested=''

  if [[ -n $wg_ports ]]; then
    printf '%sWireGuard detected%s on port(s) %s — excluded (NAT needs conntrack).\n' \
      "$C_KEY" "$C_RESET" "$(paste -sd, - <<<"$wg_ports")"
  fi
  if [[ -n $dnat_ports ]]; then
    printf '%sDocker/DNAT-forwarded port(s)%s %s — excluded: NOTRACK skips the nat\n' \
      "$C_KEY" "$C_RESET" "$(paste -sd, - <<<"$dnat_ports")"
    printf 'table, which would break their port forwarding.\n'
  fi
  if [[ -z $suggested ]]; then
    printf 'No proxy data ports were detected to exempt (nothing is listening\n'
    printf 'outside SSH/WireGuard/Docker). Nothing to do.\n'
    return 0
  fi
  printf '%sDetected proxy port(s):%s %s\n\n' "$C_KEY" "$C_RESET" "$suggested"

  local answer ports
  read -rp "Ports to exempt [Enter=detected, space/comma separated]: " answer || return 0
  ports="$(_notrack_sanitize "${answer:-$suggested}")" || ports=''
  # Hard rule, even against manual input: a DNAT-forwarded port must never be
  # NOTRACK'd (it would break forwarding), so drop any that slipped in.
  if [[ -n $ports && -n $dnat_ports ]]; then
    local kept
    kept="$(_notrack_drop_ports "$ports" "$dnat_ports")"
    if [[ $kept != "$ports" ]]; then
      printf '%sRemoved Docker/DNAT port(s)%s from the selection — NOTRACK would break their forwarding.\n' \
        "$C_WARN" "$C_RESET"
      ports="$kept"
    fi
  fi
  if [[ -z $ports ]]; then
    printf 'No valid ports given — nothing to do.\n'
    return 0
  fi

  printf '\n%sWill exempt%s tcp+udp on port(s) %s, both directions, IPv4%s.\n' \
    "$C_KEY" "$C_RESET" "$ports" "$(has_cmd ip6tables && printf '+IPv6' || printf '')"
  ui_confirm "Apply NOTRACK now and persist it for reboots?" || return 0

  local -a plist=()
  mapfile -t plist < <(ports_split "$ports")
  _notrack_apply_live "${plist[@]}"

  if [[ -d /etc/systemd/system ]] && has_cmd systemctl; then
    _notrack_write_unit "${plist[@]}"
    systemctl daemon-reload 2>>"$ST_LOG_FILE" || log_warn "daemon-reload failed."
    if systemctl enable server-tools-notrack.service >/dev/null 2>>"$ST_LOG_FILE"; then
      manifest_add unit server-tools-notrack.service
    else
      log_warn "Could not enable boot persistence for the NOTRACK rules."
    fi
  else
    log_warn "No systemd — NOTRACK is active now but will not survive a reboot."
  fi

  if notrack_verify; then
    printf '%sNOTRACK active%s on %s — those flows no longer touch conntrack.\n' \
      "$C_OK" "$C_RESET" "$ports"
  else
    printf '%sNOTRACK rules did not all verify%s — see the log.\n' "$C_WARN" "$C_RESET"
  fi
  log_info "NOTRACK applied on ports: ${ports}."
  return 0
}

# notrack_verify — 0 when every persisted rule is live, 3 on drift, 2 when the
# feature was never configured on this host.
notrack_verify() {
  has_cmd iptables || return 2
  [[ -f $ST_NOTRACK_UNIT ]] || return 2
  local ports port spec
  local -a rule=()
  ports="$(_notrack_unit_ports)" || return 2
  [[ -n $ports ]] || return 2
  while IFS= read -r port; do
    [[ $port =~ ^[0-9]+$ ]] || continue
    while IFS= read -r spec; do
      # One argv entry per token — an unquoted $spec does not split under the
      # global IFS, so iptables would answer "no such rule" for every port.
      IFS=' ' read -ra rule <<<"$spec"
      iptables -t raw -C "${rule[@]}" -j CT --notrack 2>/dev/null && continue
      iptables -t raw -C "${rule[@]}" -j NOTRACK 2>/dev/null && continue
      return 3
    done < <(_notrack_specs "$port")
  done <<<"$ports"
  return 0
}

vpn_docker_ufw_audit() {
  ui_section "Docker + UFW audit"
  local docker_on=0 ufw_on=0
  if has_cmd docker && docker ps -q 2>/dev/null | grep -q .; then
    docker_on=1
  fi
  if has_cmd ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw_on=1
  fi

  if ((docker_on == 0)); then
    printf 'No running Docker containers — no bypass risk.\n'
    return 0
  fi
  if ((ufw_on == 0)); then
    printf 'Docker is running but UFW is inactive — nothing to bypass (no firewall).\n'
    return 0
  fi

  printf '%sBoth Docker and UFW are active.%s Docker inserts its own iptables rules,\n' "$C_WARN" "$C_RESET"
  printf 'so ports published with -p/ports: are reachable EVEN IF UFW blocks them.\n'
  printf '\n%sPublished ports right now:%s\n' "$C_KEY" "$C_RESET"
  docker ps --format '  {{.Names}}: {{.Ports}}' 2>/dev/null ||
    log_warn "Could not list container ports."
  printf '\nMitigations: bind sensitive ports to 127.0.0.1 in compose, or use the\n'
  printf 'ufw-docker approach (planned in ROADMAP.md backlog).\n'
}
