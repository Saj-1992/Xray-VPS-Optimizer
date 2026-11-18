# shellcheck shell=bash
# ============================================================================
# modules/isp_fw.sh — the Iran ISP blocker's kernel side: ipsets, iptables /
# ip6tables chains, the boot unit, apply / restore / verify, and ending the
# sessions of a newly blocked ISP. Part of the ISP blocker; see isp.sh for the
# overview and isp_lists.sh for the address lists.
# ============================================================================

# _isp_v6_active — IPv6 is worth enforcing: ip6tables exists, IPv6 is switched
# on, and a blocked ISP has IPv6 ranges.
_isp_v6_active() {
  local f=/proc/sys/net/ipv6/conf/all/disable_ipv6
  has_cmd ip6tables || return 1
  [[ -r $f && "$(<"$f")" == 0 ]] || return 1
  [[ -n "$(_isp_ranges 6 | sed -n '1p')" ]]
}

# _isp_wl_items FAMILY — addresses that are never blocked: the saved exempt
# list, the IP of this SSH session, and loopback (so the set is never empty).
_isp_wl_items() {
  local fam="$1" item session
  while IFS= read -r item; do
    if [[ -n $item ]] && _isp_in_family "$fam" "$item"; then
      printf '%s\n' "$item"
    fi
  done < <(ports_split "$(config_get isp_wl '')")
  session="$(_isp_session_ip)"
  if [[ -n $session ]] && _isp_in_family "$fam" "$session"; then
    printf '%s\n' "$session"
  fi
  if [[ $fam == 6 ]]; then
    printf '::1/128\n'
  else
    printf '127.0.0.0/8\n'
  fi
}

# --- Kernel objects ----------------------------------------------------------

# _isp_load_set NAME [FAMILY] < ranges — replace a set's content atomically: fill
# a scratch set, swap it in, destroy the scratch. Packets never see a half-empty
# set. FAMILY is inet (default) or inet6.
_isp_load_set() {
  local name="$1" scratch="${1}-new" family="${2:-inet}"
  ipset create "$name" hash:net family "$family" maxelem 262144 -exist 2>>"$ST_LOG_FILE" || return 1
  ipset create "$scratch" hash:net family "$family" maxelem 262144 -exist 2>>"$ST_LOG_FILE" || return 1
  ipset flush "$scratch" 2>>"$ST_LOG_FILE" || return 1
  local line
  {
    while IFS= read -r line; do
      if [[ -n $line ]]; then
        printf 'add %s %s\n' "$scratch" "$line"
      fi
    done
  } | ipset restore -exist 2>>"$ST_LOG_FILE" || {
    ipset destroy "$scratch" 2>>"$ST_LOG_FILE"
    return 1
  }
  ipset swap "$scratch" "$name" 2>>"$ST_LOG_FILE" || return 1
  ipset destroy "$scratch" 2>>"$ST_LOG_FILE" || log_warn "Could not remove the scratch set ${scratch}."
  return 0
}

# _isp_set_count NAME — live number of entries in a set (0 when it is missing).
_isp_set_count() {
  local n
  n="$(ipset list "$1" -t 2>/dev/null | awk -F': ' '/Number of entries/ {print $2}')" || n=0
  printf '%s' "${n:-0}"
}

# _isp_fingerprint — the blocked lists as loaded: a checksum of every range plus
# the live set sizes. Compared by isp_verify, so a list that changed on disk, or
# a set someone emptied or edited by hand, shows up as drift instead of being
# trusted just because the rules still exist.
_isp_fingerprint() {
  local c4 c6=0 n6=0
  c4="$(_isp_ranges 4 | cksum | awk '{print $1}')"
  if _isp_v6_active; then
    c6="$(_isp_ranges 6 | cksum | awk '{print $1}')"
    n6="$(_isp_set_count "$ST_ISP_SET6")"
  fi
  printf '%s %s %s %s\n' "$c4" "$(_isp_set_count "$ST_ISP_SET")" "$c6" "$n6"
}

# _isp_load_all — rebuild the sets from the lists and the saved settings.
_isp_load_all() {
  _isp_prepare_lists
  _isp_ranges 4 | _isp_load_set "$ST_ISP_SET" || return 1
  _isp_wl_items 4 | _isp_load_set "$ST_ISP_WL" || return 1
  if _isp_v6_active; then
    _isp_ranges 6 | _isp_load_set "$ST_ISP_SET6" inet6 || return 1
    _isp_wl_items 6 | _isp_load_set "$ST_ISP_WL6" inet6 || return 1
  else
    _isp_teardown_family 6
  fi
  _isp_fingerprint >"${ST_ISP_DIR}/.loaded"
}

# _isp_render_chain CHAIN FLAVOR LISTSET WLSET — the iptables-restore lines for
# one chain. FLAVOR "in" matches the destination port as seen on INPUT; "fwd"
# matches the ORIGINAL destination port via conntrack, because Docker has
# already rewritten it to the container's port by the time DOCKER-USER sees the
# packet. The same text serves iptables and ip6tables.
_isp_render_chain() {
  local chain="$1" flavor="$2" lset="$3" wset="$4"
  local ports proto wports ssh_port port p match
  ports="$(config_get isp_ports all)"
  proto="$(config_get isp_proto both)"
  wports="$(config_get isp_wports '')"
  ssh_port="$(detect_ssh_port)"

  printf -- '-F %s\n' "$chain"
  printf -- '-A %s -m set --match-set %s src -j RETURN\n' "$chain" "$wset"
  if [[ $flavor == in ]]; then
    printf -- '-A %s -p tcp --dport %s -j RETURN\n' "$chain" "$ssh_port"
  fi

  if [[ $ports == all ]]; then
    # Ports kept open for everyone even though ALL ports are blocked.
    while IFS= read -r port; do
      if [[ -z $port ]]; then
        continue
      fi
      for p in tcp udp; do
        if [[ $flavor == in ]]; then
          printf -- '-A %s -p %s --dport %s -j RETURN\n' "$chain" "$p" "${port//-/:}"
        else
          printf -- '-A %s -p %s -m conntrack --ctorigdstport %s -j RETURN\n' "$chain" "$p" "${port//-/:}"
        fi
      done
    done < <(ports_split "$wports")
    printf -- '-A %s -m set --match-set %s src -j DROP\n' "$chain" "$lset"
    return 0
  fi

  local -a protos=()
  case "$proto" in
    tcp) protos=(tcp) ;;
    udp) protos=(udp) ;;
    *) protos=(tcp udp) ;;
  esac
  while IFS= read -r port; do
    if [[ -z $port ]]; then
      continue
    fi
    for p in "${protos[@]}"; do
      if [[ $flavor == in ]]; then
        match="-p ${p} --dport ${port//-/:}"
      else
        match="-p ${p} -m conntrack --ctorigdstport ${port//-/:}"
      fi
      printf -- '-A %s %s -m set --match-set %s src -j DROP\n' "$chain" "$match" "$lset"
    done
  done < <(ports_split "$ports")
  return 0
}

# _isp_hook_first TOOL PARENT CHAIN — make PARENT jump to CHAIN as its FIRST
# rule. A jump that merely exists is not enough: an earlier "ACCEPT
# ESTABLISHED" (UFW, Docker, a saved ruleset) would let a blocked ISP's
# connections through unseen. The `-S` listing starts with the policy / chain
# line, so the first rule is line 2.
_isp_hook_first() {
  local tool="$1" parent="$2" chain="$3"
  if [[ "$("$tool" -S "$parent" 2>/dev/null | sed -n '2p')" == "-A ${parent} -j ${chain}" ]]; then
    return 0
  fi
  while "$tool" -D "$parent" -j "$chain" 2>/dev/null; do
    :
  done
  "$tool" -I "$parent" 1 -j "$chain" 2>>"$ST_LOG_FILE"
}

# _isp_install_family FAMILY — (re)create both chains for IPv4 (4) or IPv6 (6)
# from the saved settings and hook them in: INPUT, and DOCKER-USER when Docker
# is present.
_isp_install_family() {
  local fam="$1" tool=iptables restore=iptables-restore lset="$ST_ISP_SET" wset="$ST_ISP_WL" chain
  if [[ $fam == 6 ]]; then
    tool=ip6tables
    restore=ip6tables-restore
    lset="$ST_ISP_SET6"
    wset="$ST_ISP_WL6"
  fi
  for chain in "$ST_ISP_CHAIN_IN" "$ST_ISP_CHAIN_FWD"; do
    "$tool" -n -L "$chain" >/dev/null 2>&1 || "$tool" -N "$chain" 2>>"$ST_LOG_FILE" || return 1
  done

  {
    printf '*filter\n'
    _isp_render_chain "$ST_ISP_CHAIN_IN" in "$lset" "$wset"
    _isp_render_chain "$ST_ISP_CHAIN_FWD" fwd "$lset" "$wset"
    printf 'COMMIT\n'
  } | "$restore" --noflush 2>>"$ST_LOG_FILE" || return 1

  _isp_hook_first "$tool" INPUT "$ST_ISP_CHAIN_IN" || return 1
  if "$tool" -n -L DOCKER-USER >/dev/null 2>&1; then
    _isp_hook_first "$tool" DOCKER-USER "$ST_ISP_CHAIN_FWD" ||
      log_warn "Could not hook DOCKER-USER (IPv${fam}) — containers' published ports are not covered."
  fi
  return 0
}

# _isp_install_rules — IPv4 always, IPv6 when the host has it switched on.
_isp_install_rules() {
  _isp_install_family 4 || return 1
  if _isp_v6_active; then
    _isp_install_family 6 || return 1
  fi
  return 0
}

# _isp_teardown_family FAMILY — remove the hooks, chains and set of one family.
# The hooks go first, so there is never a moment with a chain that is jumped
# to while half deleted.
_isp_teardown_family() {
  local fam="$1" tool=iptables lset="$ST_ISP_SET" wset="$ST_ISP_WL" chain set_name
  if [[ $fam == 6 ]]; then
    tool=ip6tables
    lset="$ST_ISP_SET6"
    wset="$ST_ISP_WL6"
  fi
  if has_cmd "$tool"; then
    # Either hook may already be gone, or Docker may not exist at all.
    while "$tool" -D INPUT -j "$ST_ISP_CHAIN_IN" 2>/dev/null; do
      :
    done
    while "$tool" -D DOCKER-USER -j "$ST_ISP_CHAIN_FWD" 2>/dev/null; do
      :
    done
    for chain in "$ST_ISP_CHAIN_IN" "$ST_ISP_CHAIN_FWD"; do
      if "$tool" -n -L "$chain" >/dev/null 2>&1; then
        "$tool" -F "$chain" 2>>"$ST_LOG_FILE"
        "$tool" -X "$chain" 2>>"$ST_LOG_FILE" || log_warn "Could not delete chain ${chain} (IPv${fam})."
      fi
    done
  fi
  if has_cmd ipset; then
    for set_name in "$lset" "$wset"; do
      if ipset list -n 2>/dev/null | grep -qx "$set_name"; then
        ipset destroy "$set_name" 2>>"$ST_LOG_FILE" || log_warn "Could not destroy set ${set_name}."
      fi
    done
  fi
}

# _isp_teardown — remove everything the blocker put into the kernel (both
# families) and its boot unit. The saved settings stay.
_isp_teardown() {
  _isp_teardown_family 4
  _isp_teardown_family 6
  rm -f "${ST_ISP_DIR}/.loaded"
  if [[ -f $ST_ISP_UNIT ]] && has_cmd systemctl; then
    systemctl disable server-tools-isp.service >/dev/null 2>>"$ST_LOG_FILE" ||
      log_warn "Could not disable the boot unit."
  fi
}

# _isp_write_unit — restore the blocker at boot (oneshot, exits at once). It
# runs after Docker so DOCKER-USER exists, and needs no network.
_isp_write_unit() {
  has_cmd systemctl || return 2
  # The unit calls `st isp-restore`, so `st` has to exist.
  persist_ensure_st || return 3
  if [[ ! -f $ST_ISP_UNIT ]]; then
    st_track_file "$ST_ISP_UNIT"
    cat >"$ST_ISP_UNIT" <<EOF
# Generated by ${ST_NAME} v${ST_VERSION}
[Unit]
Description=ServerTools Iran ISP blocker (oneshot, exits after boot)
After=network-pre.target docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${ST_INSTALL_PATH} isp-restore

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>>"$ST_LOG_FILE" || log_warn "daemon-reload failed."
  fi
  if systemctl enable server-tools-isp.service >/dev/null 2>>"$ST_LOG_FILE"; then
    manifest_add unit server-tools-isp.service
  else
    log_warn "Could not enable boot persistence for the ISP blocker."
    return 3
  fi
}

# _isp_saved_rules_file — a saved firewall file (netfilter-persistent, iptables-
# services) that contains our rules. It is loaded at boot BEFORE the ipsets
# exist, which makes the whole restore fail; the blocker brings itself back via
# its own unit and needs no such copy.
_isp_saved_rules_file() {
  local f
  for f in /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/sysconfig/iptables /etc/sysconfig/ip6tables; do
    if [[ -f $f ]] && grep -q 'st-isp' "$f"; then
      printf '%s' "$f"
      return 0
    fi
  done
  return 1
}

_isp_saved_rules_warn() {
  local f
  f="$(_isp_saved_rules_file)" || return 0
  log_warn "${f} contains ServerTools rules (st-isp-*). At boot it is loaded before the ipsets exist and the whole saved firewall can fail to load. Remove those lines, or save the firewall again while nothing is blocked (st isp none)."
}

# _isp_kill_sessions — end the connections a blocked ISP opened BEFORE the
# block. The rules already drop their packets, but an idle socket stays
# ESTABLISHED for hours (and shows up in `st isp live` and in the connection
# count) until a keepalive finally gives up. Only done when ALL ports are
# blocked, never touches the SSH port or exempt addresses, and needs `ss -K`
# (kernel INET_DIAG_DESTROY) — without it the sockets simply time out.
_isp_kill_sessions() {
  [[ "$(config_get isp_ports all)" == all && -z "$(config_get isp_wports '')" ]] || return 0
  has_cmd ss && has_cmd ipset || return 0
  local ip ssh_port n=0 left=0
  ssh_port="$(detect_ssh_port)"
  while IFS= read -r ip; do
    [[ -n $ip ]] || continue
    if ipset test "$ST_ISP_WL" "$ip" >/dev/null 2>&1; then
      continue
    fi
    if ipset test "$ST_ISP_SET" "$ip" >/dev/null 2>&1; then
      # ss prints a harmless "Invalid argument" for the IPv4-in-IPv6 twin of a
      # socket it has just destroyed, so its messages are not shown; success is
      # judged by whether any socket of that address is left.
      ss -K state established "( dst ${ip} and sport != :${ssh_port} )" >/dev/null 2>&1 || log_debug "ss -K reported an error for ${ip}."
      if [[ -z "$(ss -Htn state established "( dst ${ip} and sport != :${ssh_port} )" 2>/dev/null)" ]]; then
        n=$((n + 1))
      else
        left=$((left + 1))
      fi
    fi
  done < <(_live_peers | sort -u)
  if ((n > 0)); then
    printf 'Ended the existing connections of %d blocked address(es).\n' "$n"
    log_info "ISP blocker: ended existing connections of ${n} blocked address(es)."
  fi
  if ((left > 0)); then
    printf '%s%d blocked address(es) still have connections (this kernel cannot end them); they time out on their own.%s\n' "$C_MUTED" "$left" "$C_RESET"
  fi
  return 0
}

# isp_apply — make the host match the saved settings. Empty set = no blocking.
# 0 ok, 3 applied with a warning, 1 failed.
isp_apply() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_apply
    return
  fi
  local rc=0
  _isp_migrate
  if [[ -z "$(config_get isp_ids '')" ]]; then
    _isp_teardown
    log_info "ISP blocker: nothing blocked, rules removed."
    return 0
  fi
  has_cmd iptables || {
    log_error "iptables is not available."
    return 1
  }
  if ! has_cmd ipset; then
    # Asked for interactively; a CLI call (st isp ...) is already the consent.
    if ((ST_OPT_BATCH == 0)); then
      ui_confirm_yes "ipset is not installed (a small package). Install it now?" || return 1
    fi
    pkg_install ipset || {
      log_error "ipset installation failed — see the log."
      return 1
    }
  fi
  _isp_load_all || {
    log_error "Could not load the address sets — see the log."
    return 1
  }
  _isp_install_rules || {
    log_error "Could not install the firewall rules — see the log."
    return 1
  }
  _isp_write_unit || rc=3
  if [[ -n "$(_isp_ranges 6 | sed -n '1p')" ]] && ! _isp_v6_active; then
    log_info "IPv6 is not enabled on this host — only the IPv4 ranges are enforced."
  fi
  _isp_saved_rules_warn
  _isp_kill_sessions
  isp_verify || rc=3
  log_info "ISP blocker applied (isps=$(config_get isp_ids ''), ports=$(config_get isp_ports all), rc=${rc})."
  return "$rc"
}

# isp_restore — `st isp-restore`: what the boot unit runs. No downloads.
isp_restore() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_restore
    return
  fi
  _isp_migrate
  [[ -n "$(config_get isp_ids '')" ]] || return 0
  has_cmd ipset && has_cmd iptables || return 1
  _isp_load_all && _isp_install_rules
}

# _isp_verify_family FAMILY — 0 when this family's rules are in effect, else 3.
# "In effect" means more than "the chain exists": the jump must be the FIRST
# rule of INPUT (and of DOCKER-USER when Docker is there), the chain must
# really DROP on the set, and the set must hold entries.
_isp_verify_family() {
  local fam="$1" tool=iptables lset="$ST_ISP_SET" out
  if [[ $fam == 6 ]]; then
    tool=ip6tables
    lset="$ST_ISP_SET6"
  fi
  has_cmd "$tool" || return 3
  "$tool" -n -L "$ST_ISP_CHAIN_IN" >/dev/null 2>&1 || return 3
  out="$("$tool" -S INPUT 2>/dev/null | sed -n '2p')"
  [[ $out == "-A INPUT -j ${ST_ISP_CHAIN_IN}" ]] || return 3
  out="$("$tool" -S "$ST_ISP_CHAIN_IN" 2>/dev/null)"
  [[ $out == *"--match-set ${lset} src -j DROP"* ]] || return 3
  if "$tool" -n -L DOCKER-USER >/dev/null 2>&1; then
    out="$("$tool" -S DOCKER-USER 2>/dev/null | sed -n '2p')"
    [[ $out == "-A DOCKER-USER -j ${ST_ISP_CHAIN_FWD}" ]] || return 3
  fi
  (($(_isp_set_count "$lset") > 0)) || return 3
  return 0
}

# isp_verify — 0 in effect, 2 not configured, 3 drifted (Doctor contract).
isp_verify() {
  local saved
  [[ -n "$(config_get isp_ids '')" ]] || return 2
  has_cmd iptables && has_cmd ipset || return 3
  _isp_verify_family 4 || return 3
  if _isp_v6_active; then
    _isp_verify_family 6 || return 3
  fi
  # The lists on disk and the live sets must still be what was loaded.
  saved="$(cat "${ST_ISP_DIR}/.loaded" 2>/dev/null)" || saved=''
  [[ $saved == "$(_isp_fingerprint)" ]] || return 3
  return 0
}

# --- Counters ---------------------------------------------------------------

# _isp_chain_drops TOOL CHAIN — packets dropped by one chain. A chain that does
# not exist (IPv6 is not enforced on this host, or nothing is blocked yet) is
# not an error: it has dropped nothing. Listing failing must not fail the
# pipeline, so the listing is captured first and only counted afterwards.
_isp_chain_drops() {
  local out
  out="$("$1" -nvxL "$2" 2>/dev/null)" || out=''
  awk '/DROP/ {p += $1} END {print p + 0}' <<<"$out"
}

_isp_drops() {
  local n
  n=$(($(_isp_chain_drops iptables "$ST_ISP_CHAIN_IN") + $(_isp_chain_drops iptables "$ST_ISP_CHAIN_FWD")))
  if has_cmd ip6tables; then
    n=$((n + $(_isp_chain_drops ip6tables "$ST_ISP_CHAIN_IN") + $(_isp_chain_drops ip6tables "$ST_ISP_CHAIN_FWD")))
  fi
  printf '%s' "$n"
}
