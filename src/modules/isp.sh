# shellcheck shell=bash
# ============================================================================
# modules/isp.sh — Iran ISP blocker: keep the address ranges of chosen Iranian
# ISPs away from your ports.
#
# Model: a SET of blocked ISPs plus a scope (all ports, or a list). Toggling an
# ISP adds it to or removes it from the set and re-applies — run it as often as
# you like, block several, open some again, the result always matches the set.
#
# The address lists live in this repository (data/isp, see NOTICE.md there),
# are embedded into the built script, and need no network. Idea and original
# lists: Kiya6955/IR-ISP-Blocker (https://github.com/Kiya6955/IR-ISP-Blocker).
#
#   · one hash:net ipset holds every blocked range — a single lookup per
#     packet instead of a walk through thousands of rules;
#   · Docker-published ports are covered too (DOCKER-USER), they never touch
#     INPUT — the usual hole when a node runs in a container;
#   · your SSH port and the IP of the session applying it are always exempt;
#   · persistence is a oneshot unit that exits after restoring — no daemon.
#
# IPv4 only: the published lists contain IPv4 ranges.
# ============================================================================

readonly ST_ISP_DIR="${ST_LIB_DIR}/isp"
readonly ST_ISP_UNIT='/etc/systemd/system/server-tools-isp.service'
readonly ST_ISP_URL='https://raw.githubusercontent.com/Saj-1992/Xray-VPS-Optimizer/main/data/isp'
readonly ST_ISP_SET='st-isp-list'
readonly ST_ISP_WL='st-isp-wl'
readonly ST_ISP_CHAIN_IN='st-isp-in'
readonly ST_ISP_CHAIN_FWD='st-isp-fwd'
readonly -a ST_ISP_IDS=(mci mtn tci rightel shatel asiatech pishgaman mobinnet parsonline)

_isp_label() {
  case "$1" in
    mci) printf 'MCI (Hamrah Aval)' ;;
    mtn) printf 'MTN (Irancell)' ;;
    tci) printf 'TCI (Mokhaberat)' ;;
    rightel) printf 'Rightel' ;;
    shatel) printf 'Shatel' ;;
    asiatech) printf 'AsiaTech' ;;
    pishgaman) printf 'Pishgaman' ;;
    mobinnet) printf 'MobinNet' ;;
    parsonline) printf 'ParsOnline' ;;
    *) printf '%s' "$1" ;;
  esac
}

# _isp_resolve WORD — map what a person might type (a number, an id, a common
# name) to an ISP id. Prints nothing and fails for an unknown word.
_isp_resolve() {
  local w="${1,,}" id
  if [[ $w =~ ^[1-9]$ ]] && ((w <= ${#ST_ISP_IDS[@]})); then
    printf '%s' "${ST_ISP_IDS[$((w - 1))]}"
    return 0
  fi
  case "$w" in
    hamrah | hamrahaval | mci) printf 'mci' ;;
    irancell | mtn) printf 'mtn' ;;
    mokhaberat | tci) printf 'tci' ;;
    parsan | parsonline | pars) printf 'parsonline' ;;
    *)
      for id in "${ST_ISP_IDS[@]}"; do
        if [[ $w == "$id" ]]; then
          printf '%s' "$id"
          return 0
        fi
      done
      return 1
      ;;
  esac
}

# _isp_valid_cidr VALUE — an IPv4 address or IPv4 CIDR.
_isp_valid_cidr() {
  local ip="${1%%/*}" mask=''
  [[ $1 == */* ]] && mask="${1#*/}"
  is_valid_ipv4 "$ip" || return 1
  [[ -z $mask ]] && return 0
  [[ $mask =~ ^[0-9]+$ ]] && ((mask <= 32))
}

# _isp_valid_port VALUE — 1-65535 or an a-b range.
_isp_valid_port() {
  local v="$1" lo hi
  if [[ $v =~ ^[0-9]+$ ]]; then
    ((v >= 1 && v <= 65535))
  elif [[ $v =~ ^[0-9]+-[0-9]+$ ]]; then
    lo="${v%-*}"
    hi="${v#*-}"
    ((lo >= 1 && hi <= 65535 && lo <= hi))
  else
    return 1
  fi
}

# _isp_csv_valid KIND CSV — every item must pass the validator for KIND.
_isp_csv_valid() {
  local kind="$1" item
  while IFS= read -r item; do
    if [[ -z $item ]]; then
      continue
    fi
    case "$kind" in
      port) _isp_valid_port "$item" || return 1 ;;
      cidr) _isp_valid_cidr "$item" || return 1 ;;
    esac
  done < <(ports_split "$2")
  return 0
}

# _isp_session_ip — the client IP of the SSH session running this tool.
_isp_session_ip() {
  local ip
  ip="$(awk '{print $1}' <<<"${SSH_CONNECTION:-}")"
  if is_valid_ipv4 "$ip"; then
    printf '%s' "$ip"
  fi
  return 0
}

# --- Blocked set (the single source of truth is the config key isp_ids) ------

# _isp_blocked_ids — one id per line, in the canonical order.
_isp_blocked_ids() {
  local id csv
  csv=",$(config_get isp_ids ''),"
  for id in "${ST_ISP_IDS[@]}"; do
    if [[ $csv == *",${id},"* ]]; then
      printf '%s\n' "$id"
    fi
  done
}

_isp_is_blocked() {
  [[ ",$(config_get isp_ids '')," == *",${1},"* ]]
}

# _isp_store_ids ID... — save the blocked set (canonical order, no duplicates).
_isp_store_ids() {
  local id want="," out=''
  for id in "$@"; do
    want+="${id},"
  done
  for id in "${ST_ISP_IDS[@]}"; do
    if [[ $want == *",${id},"* ]]; then
      out+="${out:+,}${id}"
    fi
  done
  config_set isp_ids "$out"
}

# --- Address lists: embedded in the script, refreshable from this repo -------

# _isp_prepare_lists — make sure every list is on disk. A new ServerTools
# version re-seeds the cache from its embedded data (newer than any older
# download); `isp update` can then refresh it again.
_isp_prepare_lists() {
  local id stamp="${ST_ISP_DIR}/.seeded-by"
  mkdir -p "$ST_ISP_DIR"
  local reseed=0
  if [[ ! -f $stamp || "$(<"$stamp")" != "$ST_VERSION" ]]; then
    reseed=1
  fi
  for id in "${ST_ISP_IDS[@]}"; do
    if ((reseed)) || [[ ! -s ${ST_ISP_DIR}/${id}.ipv4 ]]; then
      _isp_embedded "$id" >"${ST_ISP_DIR}/${id}.ipv4"
    fi
  done
  printf '%s\n' "$ST_VERSION" >"$stamp"
}

# isp_update_lists — refresh the cached lists from this project's repository.
# Every line is validated; a failed or empty download keeps what is there.
isp_update_lists() {
  has_cmd curl || {
    log_error "curl is required to update the lists."
    return 1
  }
  _isp_prepare_lists
  local id tmp line n ok=0 failed=0 total=0
  for id in "${ST_ISP_IDS[@]}"; do
    tmp="${ST_ISP_DIR}/${id}.ipv4.new"
    if curl -fsSL --max-time 30 "${ST_ISP_URL}/${id}.ipv4" -o "$tmp" 2>>"$ST_LOG_FILE"; then
      : >"${tmp}.clean"
      while IFS= read -r line; do
        line="${line//[$'\r ']/}"
        if [[ -n $line ]] && _isp_valid_cidr "$line"; then
          printf '%s\n' "$line" >>"${tmp}.clean"
        fi
      done <"$tmp"
      rm -f "$tmp"
      if [[ -s ${tmp}.clean ]]; then
        mv -f "${tmp}.clean" "${ST_ISP_DIR}/${id}.ipv4"
        ok=$((ok + 1))
        n="$(wc -l <"${ST_ISP_DIR}/${id}.ipv4" | tr -d '[:space:]')"
        total=$((total + n))
        continue
      fi
      rm -f "${tmp}.clean"
    fi
    rm -f "$tmp"
    failed=$((failed + 1))
    log_warn "Could not refresh the $(_isp_label "$id") list — keeping the current one."
  done
  printf 'Lists refreshed: %d of %d (%d ranges).\n' "$ok" "${#ST_ISP_IDS[@]}" "$total"
  ((failed == 0)) || return 3
}

_isp_count() {
  local f="${ST_ISP_DIR}/${1}.ipv4"
  if [[ -s $f ]]; then
    wc -l <"$f" | tr -d '[:space:]'
  else
    _isp_embedded "$1" | wc -l | tr -d '[:space:]'
  fi
}

# --- Kernel objects ----------------------------------------------------------

# _isp_load_set NAME < ranges — replace a set's content atomically: fill a
# scratch set, swap it in, destroy the scratch. Packets never see a half-empty set.
_isp_load_set() {
  local name="$1" scratch="${1}-new"
  ipset create "$name" hash:net family inet maxelem 262144 -exist 2>>"$ST_LOG_FILE" || return 1
  ipset create "$scratch" hash:net family inet maxelem 262144 -exist 2>>"$ST_LOG_FILE" || return 1
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

# _isp_load_all — rebuild both sets from the lists and the saved settings.
_isp_load_all() {
  local id wl session
  _isp_prepare_lists
  {
    while IFS= read -r id; do
      if [[ -s ${ST_ISP_DIR}/${id}.ipv4 ]]; then
        cat "${ST_ISP_DIR}/${id}.ipv4"
      fi
    done < <(_isp_blocked_ids)
  } | sort -u | _isp_load_set "$ST_ISP_SET" || return 1

  wl="$(config_get isp_wl '')"
  session="$(_isp_session_ip)"
  {
    ports_split "$wl"
    if [[ -n $session ]]; then
      printf '%s\n' "$session"
    fi
    # Never leave the set empty by accident: loopback is harmless to exempt.
    printf '127.0.0.0/8\n'
  } | _isp_load_set "$ST_ISP_WL"
}

# _isp_render_chain CHAIN FLAVOR — the iptables-restore lines for one chain.
# FLAVOR "in" matches the destination port as seen on INPUT; "fwd" matches the
# ORIGINAL destination port via conntrack, because Docker has already rewritten
# it to the container's port by the time DOCKER-USER sees the packet.
_isp_render_chain() {
  local chain="$1" flavor="$2"
  local ports proto wports ssh_port port p match
  ports="$(config_get isp_ports all)"
  proto="$(config_get isp_proto both)"
  wports="$(config_get isp_wports '')"
  ssh_port="$(detect_ssh_port)"

  printf -- '-F %s\n' "$chain"
  printf -- '-A %s -m set --match-set %s src -j RETURN\n' "$chain" "$ST_ISP_WL"
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
    printf -- '-A %s -m set --match-set %s src -j DROP\n' "$chain" "$ST_ISP_SET"
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
      printf -- '-A %s %s -m set --match-set %s src -j DROP\n' "$chain" "$match" "$ST_ISP_SET"
    done
  done < <(ports_split "$ports")
  return 0
}

# _isp_install_rules — (re)create both chains from the saved settings and make
# sure they are reached from INPUT and, when Docker is present, DOCKER-USER.
_isp_install_rules() {
  local chain
  for chain in "$ST_ISP_CHAIN_IN" "$ST_ISP_CHAIN_FWD"; do
    iptables -n -L "$chain" >/dev/null 2>&1 || iptables -N "$chain" 2>>"$ST_LOG_FILE" || return 1
  done

  {
    printf '*filter\n'
    _isp_render_chain "$ST_ISP_CHAIN_IN" in
    _isp_render_chain "$ST_ISP_CHAIN_FWD" fwd
    printf 'COMMIT\n'
  } | iptables-restore --noflush 2>>"$ST_LOG_FILE" || return 1

  iptables -C INPUT -j "$ST_ISP_CHAIN_IN" 2>/dev/null ||
    iptables -I INPUT 1 -j "$ST_ISP_CHAIN_IN" 2>>"$ST_LOG_FILE" || return 1
  if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
    iptables -C DOCKER-USER -j "$ST_ISP_CHAIN_FWD" 2>/dev/null ||
      iptables -I DOCKER-USER 1 -j "$ST_ISP_CHAIN_FWD" 2>>"$ST_LOG_FILE" ||
      log_warn "Could not hook DOCKER-USER — containers' published ports are not covered."
  fi
  return 0
}

# _isp_teardown — remove the hooks, chains and sets (the settings stay).
_isp_teardown() {
  local chain set_name
  if has_cmd iptables; then
    # Either hook may already be gone, or Docker may not exist at all.
    iptables -D INPUT -j "$ST_ISP_CHAIN_IN" 2>/dev/null || true
    iptables -D DOCKER-USER -j "$ST_ISP_CHAIN_FWD" 2>/dev/null || true
    for chain in "$ST_ISP_CHAIN_IN" "$ST_ISP_CHAIN_FWD"; do
      if iptables -n -L "$chain" >/dev/null 2>&1; then
        iptables -F "$chain" 2>>"$ST_LOG_FILE"
        iptables -X "$chain" 2>>"$ST_LOG_FILE" || log_warn "Could not delete chain ${chain}."
      fi
    done
  fi
  if has_cmd ipset; then
    for set_name in "$ST_ISP_SET" "$ST_ISP_WL"; do
      if ipset list -n 2>/dev/null | grep -qx "$set_name"; then
        ipset destroy "$set_name" 2>>"$ST_LOG_FILE" || log_warn "Could not destroy set ${set_name}."
      fi
    done
  fi
  if [[ -f $ST_ISP_UNIT ]] && has_cmd systemctl; then
    systemctl disable server-tools-isp.service >/dev/null 2>>"$ST_LOG_FILE" ||
      log_warn "Could not disable the boot unit."
  fi
}

# _isp_write_unit — restore the blocker at boot (oneshot, exits at once). It
# runs after Docker so DOCKER-USER exists, and needs no network.
_isp_write_unit() {
  if [[ ! -x $ST_INSTALL_PATH ]]; then
    log_warn "'st' is not installed (st --install) — the blocker will not return after a reboot."
    return 3
  fi
  has_cmd systemctl || return 2
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

# --- Apply / restore / verify --------------------------------------------------

# _isp_migrate — settings written by 2.10.0 carried a mode key. "block" is the
# only behaviour left and needs nothing. "allow only these ISPs" was retired in
# favour of the toggle model (to keep one ISP out of a blocked set, simply leave
# it open); silently reading it as "block" would invert its meaning, so it is
# switched off with a clear warning instead.
_isp_migrate() {
  local mode
  mode="$(config_get isp_mode '')"
  [[ -n $mode ]] || return 0
  if [[ $mode == allow ]]; then
    log_warn "The 'allow only these ISPs' mode was retired — the old setting is switched off. Block the ISPs you want kept out instead."
    config_set isp_ids ''
  fi
  config_set isp_mode ''
}

# isp_apply — make the host match the saved settings. Empty set = no blocking.
# 0 ok, 3 applied with a warning, 1 failed.
isp_apply() {
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
  isp_verify || rc=3
  log_info "ISP blocker applied (isps=$(config_get isp_ids ''), ports=$(config_get isp_ports all), rc=${rc})."
  return "$rc"
}

# isp_restore — `st isp-restore`: what the boot unit runs. No downloads.
isp_restore() {
  _isp_migrate
  [[ -n "$(config_get isp_ids '')" ]] || return 0
  has_cmd ipset && has_cmd iptables || return 1
  _isp_load_all && _isp_install_rules
}

# isp_verify — 0 in effect, 2 not configured, 3 drifted (Doctor contract).
isp_verify() {
  [[ -n "$(config_get isp_ids '')" ]] || return 2
  has_cmd iptables && has_cmd ipset || return 3
  iptables -C INPUT -j "$ST_ISP_CHAIN_IN" 2>/dev/null || return 3
  iptables -n -L "$ST_ISP_CHAIN_IN" >/dev/null 2>&1 || return 3
  local count
  count="$(ipset list "$ST_ISP_SET" -t 2>/dev/null | awk -F': ' '/Number of entries/ {print $2}')" || count=0
  [[ $count =~ ^[0-9]+$ ]] && ((count > 0)) || return 3
  return 0
}

# isp_set_blocked ID... — replace the blocked set and apply. Used by the menu
# and the CLI, so both always behave the same.
isp_set_blocked() {
  _isp_store_ids "$@"
  isp_apply
}

# isp_block ID... / isp_unblock ID... — add to / remove from the blocked set.
isp_block() {
  local -a cur=() id
  mapfile -t cur < <(_isp_blocked_ids)
  for id in "$@"; do
    _isp_is_blocked "$id" || cur+=("$id")
  done
  isp_set_blocked "${cur[@]}"
}

isp_unblock() {
  local -a keep=()
  local id x drop
  while IFS= read -r id; do
    drop=0
    for x in "$@"; do
      if [[ $x == "$id" ]]; then
        drop=1
      fi
    done
    if ((drop == 0)); then
      keep+=("$id")
    fi
  done < <(_isp_blocked_ids)
  isp_set_blocked "${keep[@]}"
}

# _isp_toggled ID... — the blocked set after flipping each given id; one id per
# line, canonical order. Naming an id twice flips it back, as typed.
_isp_toggled() {
  local csv id
  csv=",$(config_get isp_ids ''),"
  for id in "$@"; do
    if [[ $csv == *",${id},"* ]]; then
      csv="${csv/,${id},/,}"
    else
      csv+="${id},"
    fi
  done
  for id in "${ST_ISP_IDS[@]}"; do
    if [[ $csv == *",${id},"* ]]; then
      printf '%s
' "$id"
    fi
  done
}

# isp_remove — unblock everything and forget the settings.
isp_remove() {
  _isp_teardown
  local key
  for key in isp_ids isp_ports isp_proto isp_wl isp_wports; do
    config_set "$key" ''
  done
  log_info "ISP blocker removed."
}

# --- Status ------------------------------------------------------------------

_isp_drops() {
  local n
  n="$(iptables -nvxL "$ST_ISP_CHAIN_IN" 2>/dev/null | awk '/DROP/ {p += $1} END {print p + 0}')"
  n=$((n + $(iptables -nvxL "$ST_ISP_CHAIN_FWD" 2>/dev/null | awk '/DROP/ {p += $1} END {print p + 0}')))
  printf '%s' "$n"
}

# _isp_scope_text — "all ports" or "tcp+udp 443,8443" in plain words.
_isp_scope_text() {
  local ports
  ports="$(config_get isp_ports all)"
  if [[ $ports == all ]]; then
    local w
    w="$(config_get isp_wports '')"
    printf 'all ports%s' "${w:+ (except ${w})}"
  else
    local proto
    proto="$(config_get isp_proto both)"
    printf '%s %s' "$([[ $proto == both ]] && printf 'tcp+udp' || printf '%s' "$proto")" "$ports"
  fi
}

# isp_status — what is blocked, how widely, and proof that it works.
isp_status() {
  ui_section "Iran ISP blocker — status"
  local id names=''
  while IFS= read -r id; do
    names+="$(_isp_label "$id"), "
  done < <(_isp_blocked_ids)
  if [[ -z $names ]]; then
    printf 'Nothing blocked.\n'
    return 0
  fi
  ui_kv "Blocked" "${names%, }"
  ui_kv "Scope" "$(_isp_scope_text)"
  ui_kv "Always allowed" "SSH port $(detect_ssh_port), $(config_get isp_wl 'no extra IPs')"
  ui_kv "Packets dropped" "$(_isp_drops)"
  if isp_verify; then
    printf '%s  rules in effect%s\n' "$C_OK" "$C_RESET"
  else
    printf '%s  rules are NOT fully in effect — pick any ISP number to re-apply%s\n' "$C_WARN" "$C_RESET"
  fi
}

# --- Menu --------------------------------------------------------------------

# _isp_edit_scope — ports (and protocol) the blocked ISPs are kept away from.
_isp_edit_scope() {
  local ports proto_choice proto wports=''
  printf '\nWhich ports? "all" blocks every port (SSH stays open), or list them\n'
  read -rp "e.g. 443,8443 or 10000-20000 [Enter=keep $(config_get isp_ports all)]: " ports || return 0
  ports="${ports// /}"
  [[ -n $ports ]] || return 0
  [[ ${ports,,} == all ]] && ports=all
  if [[ $ports != all ]] && ! _isp_csv_valid port "$ports"; then
    log_error "Invalid port list '${ports}'."
    return 1
  fi
  if [[ $ports == all ]]; then
    proto=both
    read -rp "Ports that stay OPEN to these ISPs even so (e.g. 443, or empty): " wports || return 0
    wports="${wports// /}"
    if [[ -n $wports ]] && ! _isp_csv_valid port "$wports"; then
      log_error "Invalid port list '${wports}'."
      return 1
    fi
  else
    read -rp "Protocol: 1 TCP+UDP, 2 TCP, 3 UDP [1]: " proto_choice || return 0
    case "${proto_choice:-1}" in
      2) proto=tcp ;;
      3) proto=udp ;;
      *) proto=both ;;
    esac
  fi
  config_set isp_ports "$ports"
  config_set isp_proto "$proto"
  config_set isp_wports "$wports"
}

# _isp_edit_whitelist — IPs/CIDRs that are never blocked (panel, other nodes).
_isp_edit_whitelist() {
  local wl session
  session="$(_isp_session_ip)"
  printf '\nAlways exempt: SSH port %s' "$(detect_ssh_port)"
  [[ -n $session ]] && printf ' and your current IP %s' "$session"
  printf '.\nCurrent extra list: %s\n' "$(config_get isp_wl none)"
  read -rp "Extra IPs/CIDRs that must never be blocked (panel, other nodes) [Enter=keep, - = clear]: " wl || return 0
  wl="${wl// /}"
  [[ -n $wl ]] || return 0
  [[ $wl == - ]] && wl=''
  if [[ -n $wl ]] && ! _isp_csv_valid cidr "$wl"; then
    log_error "Invalid IP list '${wl}'."
    return 1
  fi
  # Saved with the settings so the exemption also survives a reboot.
  if [[ -n $session && ",${wl}," != *",${session},"* ]]; then
    wl="${wl:+${wl},}${session}"
  fi
  config_set isp_wl "$wl"
}

_isp_draw_menu() {
  ui_logo
  ui_title "Iran ISP blocker"
  printf '  %sScope%s  %s%s%s   %sSSH port and your IP are always allowed%s\n\n' \
    "$C_KEY" "$C_RESET" "$C_ACCENT" "$(_isp_scope_text)" "$C_RESET" "$C_MUTED" "$C_RESET"
  local i=1 id state
  for id in "${ST_ISP_IDS[@]}"; do
    if _isp_is_blocked "$id"; then
      state="${C_ERR}BLOCKED${C_RESET}"
      printf '  %s  %s%d%s  %-20s %s  %s%5s ranges%s\n' "$(ui_badge err)" "$C_KEY" "$i" "$C_RESET" \
        "$(_isp_label "$id")" "$state" "$C_MUTED" "$(_isp_count "$id")" "$C_RESET"
    else
      printf '  %s  %s%d%s  %-20s %sopen%s     %s%5s ranges%s\n' "$(ui_badge idle)" "$C_KEY" "$i" "$C_RESET" \
        "$(_isp_label "$id")" "$C_MUTED" "$C_RESET" "$C_MUTED" "$(_isp_count "$id")" "$C_RESET"
    fi
    i=$((i + 1))
  done
  local drops=0
  if [[ -n "$(config_get isp_ids '')" ]]; then
    drops="$(_isp_drops)"
  fi
  printf '\n  %sDropped so far:%s %s\n' "$C_MUTED" "$C_RESET" "$drops"
  ui_hr
  printf '  %sType numbers to flip them%s (e.g. %s1 3 5%s) — each one toggles blocked/open.\n' \
    "$C_MUTED" "$C_RESET" "$C_KEY" "$C_RESET"
  printf '  %sa%s block all   %sn%s open all   %sp%s ports   %sw%s exempt IPs   %su%s update lists   %s0%s back\n' \
    "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET"
}

# _isp_report_change BEFORE AFTER — one friendly line about what changed.
_isp_report_change() {
  local before=",$1," after=",$2," id opened='' blocked=''
  for id in "${ST_ISP_IDS[@]}"; do
    if [[ $after == *",${id},"* && $before != *",${id},"* ]]; then
      blocked+="$(_isp_label "$id"), "
    elif [[ $before == *",${id},"* && $after != *",${id},"* ]]; then
      opened+="$(_isp_label "$id"), "
    fi
  done
  [[ -n $blocked ]] && printf '  %s+ blocked:%s %s\n' "$C_ERR" "$C_RESET" "${blocked%, }"
  [[ -n $opened ]] && printf '  %s- opened:%s  %s\n' "$C_OK" "$C_RESET" "${opened%, }"
  return 0
}

isp_menu() {
  local input before after tok id rc
  local -a flip=() next=()
  while true; do
    _isp_draw_menu
    read -rp "$(_ui_prompt)" input || return 0
    input="${input,,}"
    input="${input//,/ }"
    case "${input// /}" in
      0 | q | '') return 0 ;;
      # In these three, errors and outcomes are printed where they happen.
      p)
        _isp_edit_scope || true
        isp_apply || true
        continue
        ;;
      w)
        _isp_edit_whitelist || true
        isp_apply || true
        continue
        ;;
      u)
        isp_update_lists || true
        isp_apply || true
        ui_pause
        continue
        ;;
    esac

    before="$(config_get isp_ids '')"
    rc=0
    case "${input// /}" in
      a) isp_set_blocked "${ST_ISP_IDS[@]}" || rc=$? ;;
      n) isp_set_blocked || rc=$? ;;
      *)
        flip=()
        for tok in $input; do
          if id="$(_isp_resolve "$tok")"; then
            flip+=("$id")
          else
            printf '%sUnknown choice "%s" — ignored.%s
' "$C_WARN" "$tok" "$C_RESET"
          fi
        done
        if ((${#flip[@]} == 0)); then
          sleep 1
          continue
        fi
        mapfile -t next < <(_isp_toggled "${flip[@]}")
        isp_set_blocked "${next[@]}" || rc=$?
        ;;
    esac
    after="$(config_get isp_ids '')"
    _isp_report_change "$before" "$after"
    if ((rc == 1)); then
      printf '%sCould not apply — see the message above. The choice is saved; pick any ISP to retry.%s
' "$C_ERR" "$C_RESET"
    elif ((rc == 3)); then
      printf '%sApplied, with a warning (see above).%s
' "$C_WARN" "$C_RESET"
    fi
    sleep 1
  done
}

# --- CLI: st isp ... -----------------------------------------------------------

ST_ISP_SUB='status'
ST_ISP_LIST=''

# isp_cli SUBCOMMAND [LIST] — non-interactive control.
#   st isp status | block mci,mtn | unblock mtn | set mci | all | none | update
isp_cli() {
  local sub="${1:-status}" list="${2:-}" word id
  local -a ids=()
  case "$sub" in
    block | unblock | set)
      [[ -n $list ]] || die "Usage: st isp ${sub} mci,mtn,... (ids: ${ST_ISP_IDS[*]})"
      while IFS= read -r word; do
        id="$(_isp_resolve "$word")" || die "Unknown ISP '${word}' (ids: ${ST_ISP_IDS[*]})."
        ids+=("$id")
      done < <(ports_split "$list")
      ;;
  esac
  case "$sub" in
    status) isp_status ;;
    block) isp_block "${ids[@]}" ;;
    unblock) isp_unblock "${ids[@]}" ;;
    set) isp_set_blocked "${ids[@]}" ;;
    all) isp_set_blocked "${ST_ISP_IDS[@]}" ;;
    none) isp_set_blocked ;;
    reset) isp_remove ;;
    update)
      isp_update_lists
      if [[ -n "$(config_get isp_ids '')" ]]; then
        isp_apply
      fi
      ;;
    *) die "Usage: st isp status | block LIST | unblock LIST | set LIST | all | none | reset | update" ;;
  esac
}
