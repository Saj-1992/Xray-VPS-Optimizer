# shellcheck shell=bash
# ============================================================================
# modules/isp.sh — Iran ISP blocker: keep the address ranges of chosen Iranian
# ISPs away from your ports (or let ONLY them in), so a node that carries
# foreign-bound traffic is not probed or reported from inside the country.
#
# The idea and the ISP address lists come from Kiya6955/IR-ISP-Blocker
# (https://github.com/Kiya6955/IR-ISP-Blocker). The lists are downloaded from
# there at use time, so they stay current; this module is a fresh
# implementation built on ipset instead of thousands of single iptables rules:
#
#   · one hash:net set holds every selected range — a single O(1) lookup per
#     packet, not a linear walk through ~3000 rules on the hot path;
#   · it also guards Docker-published ports (DOCKER-USER), which never touch
#     the INPUT chain — the common hole when a node runs in a container;
#   · your SSH port and the IP of the session running the tool are always
#     exempt, so applying it cannot lock you out;
#   · persistence is a oneshot unit that exits after restoring — no daemon.
#
# IPv4 only: the published lists contain IPv4 ranges.
# ============================================================================

readonly ST_ISP_DIR="${ST_LIB_DIR}/isp"
readonly ST_ISP_UNIT='/etc/systemd/system/server-tools-isp.service'
readonly ST_ISP_URL='https://raw.githubusercontent.com/Kiya6955/IR-ISP-Blocker/main'
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

# _isp_file ID — the list's file stem in the upstream repository.
_isp_file() {
  case "$1" in
    parsonline) printf 'parsan' ;;
    *) printf '%s' "$1" ;;
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
    [[ -n $item ]] || continue
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

# _isp_fetch ID — refresh the cached list. A failed download keeps the old
# cache (stale beats empty); with no cache at all it fails.
_isp_fetch() {
  local id="$1" stem tmp dest
  stem="$(_isp_file "$id")"
  dest="${ST_ISP_DIR}/${id}.ipv4"
  tmp="${dest}.new"
  mkdir -p "$ST_ISP_DIR"
  if has_cmd curl && curl -fsSL --max-time 30 "${ST_ISP_URL}/${stem}-ips.ipv4" -o "$tmp" 2>>"$ST_LOG_FILE"; then
    # Keep only well-formed ranges; a truncated or hijacked download must not
    # turn into firewall rules.
    local clean="${tmp}.clean" line
    : >"$clean"
    while IFS= read -r line; do
      line="${line//[$'\r ']/}"
      if [[ -n $line ]] && _isp_valid_cidr "$line"; then
        printf '%s\n' "$line" >>"$clean"
      fi
    done <"$tmp"
    rm -f "$tmp"
    if [[ -s $clean ]]; then
      mv -f "$clean" "$dest"
      return 0
    fi
    rm -f "$clean"
    log_warn "The downloaded $(_isp_label "$id") list was empty or malformed."
  fi
  if [[ -s $dest ]]; then
    log_warn "Could not refresh $(_isp_label "$id") — using the cached copy."
    return 0
  fi
  log_error "Could not download the $(_isp_label "$id") list."
  return 1
}

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

# _isp_render_chain CHAIN FLAVOR — the iptables-restore lines for one chain.
# FLAVOR "in" matches the destination port as seen on INPUT; "fwd" matches the
# ORIGINAL destination port via conntrack, because Docker has already rewritten
# it to the container's port by the time DOCKER-USER sees the packet.
_isp_render_chain() {
  local chain="$1" flavor="$2"
  local mode ports proto wports ssh_port port p match
  mode="$(config_get isp_mode '')"
  ports="$(config_get isp_ports '')"
  proto="$(config_get isp_proto both)"
  wports="$(config_get isp_wports '')"
  ssh_port="$(detect_ssh_port)"

  printf -- '-F %s\n' "$chain"
  printf -- '-A %s -m set --match-set %s src -j RETURN\n' "$chain" "$ST_ISP_WL"
  if [[ $flavor == in ]]; then
    printf -- '-A %s -p tcp --dport %s -j RETURN\n' "$chain" "$ssh_port"
  fi

  local -a protos=()
  case "$proto" in
    tcp) protos=(tcp) ;;
    udp) protos=(udp) ;;
    *) protos=(tcp udp) ;;
  esac

  # Ports kept open for everyone even when ALL ports are blocked.
  if [[ $mode == block && $ports == all ]]; then
    while IFS= read -r port; do
      [[ -n $port ]] || continue
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

  while IFS= read -r port; do
    [[ -n $port ]] || continue
    for p in "${protos[@]}"; do
      if [[ $flavor == in ]]; then
        match="-p ${p} --dport ${port//-/:}"
      else
        match="-p ${p} -m conntrack --ctorigdstport ${port//-/:}"
      fi
      if [[ $mode == allow ]]; then
        printf -- '-A %s %s -m set ! --match-set %s src -j DROP\n' "$chain" "$match" "$ST_ISP_SET"
      else
        printf -- '-A %s %s -m set --match-set %s src -j DROP\n' "$chain" "$match" "$ST_ISP_SET"
      fi
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

# _isp_write_unit — restore the blocker at boot (oneshot, exits at once). It
# runs after Docker so DOCKER-USER exists, and needs no network: it uses the
# cached lists.
_isp_write_unit() {
  if [[ ! -x $ST_INSTALL_PATH ]]; then
    log_warn "'st' is not installed (st --install) — the blocker will not return after a reboot."
    return 3
  fi
  has_cmd systemctl || return 2
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
  if systemctl enable server-tools-isp.service >/dev/null 2>>"$ST_LOG_FILE"; then
    manifest_add unit server-tools-isp.service
  else
    log_warn "Could not enable boot persistence for the ISP blocker."
    return 3
  fi
}

# _isp_load_all — rebuild both sets from the cached lists and saved settings.
_isp_load_all() {
  local ids id wl session
  ids="$(config_get isp_ids '')"
  {
    while IFS= read -r id; do
      if [[ -s ${ST_ISP_DIR}/${id}.ipv4 ]]; then
        cat "${ST_ISP_DIR}/${id}.ipv4"
      fi
    done < <(ports_split "$ids")
  } | sort -u | _isp_load_set "$ST_ISP_SET" || return 1

  wl="$(config_get isp_wl '')"
  session="$(_isp_session_ip)"
  {
    ports_split "$wl"
    if [[ -n $session ]]; then
      printf '%s\n' "$session"
    fi
    # A set must never be empty-by-accident of syntax: 127.0.0.0/8 is harmless.
    printf '127.0.0.0/8\n'
  } | _isp_load_set "$ST_ISP_WL"
}

# isp_apply — download, load, install, persist, verify. Settings are already in
# the config; this makes the host match them.
isp_apply() {
  local id rc=0
  has_cmd iptables || {
    log_error "iptables is not available."
    return 1
  }
  has_cmd ipset || {
    log_error "ipset is not available."
    return 1
  }
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    _isp_fetch "$id" || rc=1
  done < <(ports_split "$(config_get isp_ids '')")
  ((rc == 0)) || return 1

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
  log_info "ISP blocker applied (mode=$(config_get isp_mode ''), isps=$(config_get isp_ids ''), ports=$(config_get isp_ports ''), rc=${rc})."
  return "$rc"
}

# isp_restore — `st isp-restore`: what the boot unit runs. No downloads.
isp_restore() {
  [[ -n "$(config_get isp_mode '')" ]] || return 0
  has_cmd ipset && has_cmd iptables || return 1
  _isp_load_all && _isp_install_rules
}

# isp_remove — take the blocker out completely.
isp_remove() {
  local chain
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
    local set_name
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
  local key
  for key in isp_mode isp_ids isp_ports isp_proto isp_wl isp_wports; do
    config_set "$key" ''
  done
  log_info "ISP blocker removed."
}

# isp_verify — 0 in effect, 2 not configured, 3 drifted (Doctor contract).
isp_verify() {
  [[ -n "$(config_get isp_mode '')" ]] || return 2
  has_cmd iptables && has_cmd ipset || return 3
  iptables -C INPUT -j "$ST_ISP_CHAIN_IN" 2>/dev/null || return 3
  iptables -n -L "$ST_ISP_CHAIN_IN" >/dev/null 2>&1 || return 3
  local count
  count="$(ipset list "$ST_ISP_SET" -t 2>/dev/null | awk -F': ' '/Number of entries/ {print $2}')" || count=0
  [[ $count =~ ^[0-9]+$ ]] && ((count > 0)) || return 3
  return 0
}

# isp_status — what is blocked, how many ranges, and how many packets were
# actually dropped (the counters prove it works).
isp_status() {
  ui_section "Iran ISP blocker — status"
  local mode
  mode="$(config_get isp_mode '')"
  if [[ -z $mode ]]; then
    printf 'Not active.\n'
    return 0
  fi
  local id names=''
  while IFS= read -r id; do
    if [[ -n $id ]]; then
      names+="$(_isp_label "$id"), "
    fi
  done < <(ports_split "$(config_get isp_ids '')")
  ui_kv "Mode" "$([[ $mode == allow ]] && printf 'ONLY these ISPs may reach the ports' || printf 'block these ISPs')"
  ui_kv "ISPs" "${names%, }"
  ui_kv "Ports" "$(config_get isp_ports '') · $(config_get isp_proto both)"
  ui_kv "Always allowed" "SSH port $(detect_ssh_port), $(config_get isp_wl 'no extra IPs')"
  local count
  count="$(ipset list "$ST_ISP_SET" -t 2>/dev/null | awk -F': ' '/Number of entries/ {print $2}')" || count='?'
  ui_kv "Address ranges" "${count:-?}"
  local hits
  hits="$(iptables -nvxL "$ST_ISP_CHAIN_IN" 2>/dev/null | awk '/DROP/ {p += $1} END {print p + 0}')"
  hits=$((hits + $(iptables -nvxL "$ST_ISP_CHAIN_FWD" 2>/dev/null | awk '/DROP/ {p += $1} END {print p + 0}')))
  ui_kv "Packets dropped" "$hits"
  if isp_verify; then
    printf '%s  rules in effect%s\n' "$C_OK" "$C_RESET"
  else
    printf '%s  rules are NOT fully in effect — run "Apply again"%s\n' "$C_WARN" "$C_RESET"
  fi
}

# _isp_pick_isps — numbered multi-select; prints the chosen ids comma-joined.
_isp_pick_isps() {
  local i=1 id choice picked=() item
  for id in "${ST_ISP_IDS[@]}"; do
    ui_menu_item "$i" "$(_isp_label "$id")" "" >&2
    i=$((i + 1))
  done
  ui_menu_item a "All of them" "" >&2
  read -rp "ISPs (numbers separated by commas, or a): " choice || return 1
  if [[ ${choice,,} == a ]]; then
    picked=("${ST_ISP_IDS[@]}")
  else
    while IFS= read -r item; do
      if ! [[ $item =~ ^[1-9]$ ]] || ((item > ${#ST_ISP_IDS[@]})); then
        continue
      fi
      picked+=("${ST_ISP_IDS[$((item - 1))]}")
    done < <(ports_split "$choice")
  fi
  ((${#picked[@]} > 0)) || return 1
  local IFS=','
  printf '%s' "${picked[*]}"
}

# isp_configure — the guided setup.
isp_configure() {
  ui_section "Iran ISP blocker — setup"
  printf 'Keeps the chosen Iranian ISPs'"'"' address ranges away from your ports.\n'
  printf 'Lists come from Kiya6955/IR-ISP-Blocker; rules use ipset (fast) and also\n'
  printf 'cover Docker-published ports. IPv4 only.\n\n'

  if ! has_cmd iptables; then
    log_error "iptables is required."
    return 1
  fi
  if ! has_cmd ipset; then
    ui_confirm_yes "ipset is not installed (a small package). Install it now?" || return 0
    pkg_install ipset || {
      log_error "ipset installation failed — see the log."
      return 1
    }
  fi

  local ids mode_choice mode ports proto_choice proto wl wports=''
  ids="$(_isp_pick_isps)" || {
    printf 'No ISP selected.\n'
    return 0
  }

  printf '\n  1  Block these ISPs on the ports I choose\n'
  printf '  2  ONLY these ISPs may reach the ports I choose (everyone else blocked)\n'
  read -rp "Mode [1/2]: " mode_choice || return 0
  case "$mode_choice" in
    1) mode=block ;;
    2) mode=allow ;;
    *)
      printf 'Cancelled.\n'
      return 0
      ;;
  esac

  if [[ $mode == block ]]; then
    read -rp "Ports to block (e.g. 443,8443 or 10000-20000), or 'all': " ports || return 0
    ports="${ports// /}"
    [[ ${ports,,} == all ]] && ports=all
  else
    read -rp "Ports that only these ISPs may reach (e.g. 443,8443): " ports || return 0
    ports="${ports// /}"
  fi
  if [[ -z $ports ]]; then
    printf 'No ports given — cancelled.\n'
    return 0
  fi
  if [[ $ports != all ]] && ! _isp_csv_valid port "$ports"; then
    log_error "Invalid port list '${ports}'."
    return 1
  fi
  if [[ $mode == allow && $ports == all ]]; then
    log_error "'all' is only valid when blocking. List the ports for the allow-only mode."
    return 1
  fi

  if [[ $ports != all ]]; then
    printf '\n  1  TCP and UDP\n  2  TCP only\n  3  UDP only\n'
    read -rp "Protocol [1]: " proto_choice || return 0
    case "${proto_choice:-1}" in
      2) proto=tcp ;;
      3) proto=udp ;;
      *) proto=both ;;
    esac
  else
    proto=both
    read -rp "Ports that stay OPEN for these ISPs even so (e.g. 443, or empty): " wports || return 0
    wports="${wports// /}"
    if [[ -n $wports ]] && ! _isp_csv_valid port "$wports"; then
      log_error "Invalid port list '${wports}'."
      return 1
    fi
  fi

  local session
  session="$(_isp_session_ip)"
  printf '\nAlways exempt: SSH port %s' "$(detect_ssh_port)"
  [[ -n $session ]] && printf ' and your current IP %s' "$session"
  printf '.\n'
  read -rp "Extra IPs/CIDRs that must never be blocked (panel, other nodes; or empty): " wl || return 0
  wl="${wl// /}"
  if [[ -n $wl ]] && ! _isp_csv_valid cidr "$wl"; then
    log_error "Invalid IP list '${wl}'."
    return 1
  fi
  # Saved with the settings so the exemption also survives a reboot.
  if [[ -n $session && ",${wl}," != *",${session},"* ]]; then
    wl="${wl:+${wl},}${session}"
  fi

  if [[ $mode == allow ]]; then
    printf '\n%sAllow-only mode drops EVERYONE else on these ports — your panel,\n' "$C_WARN"
    printf 'other nodes and every foreign user — unless listed above.%s\n' "$C_RESET"
  fi
  printf '\nSummary: %s · ISPs: %s · ports: %s · %s\n' "$mode" "$ids" "$ports" "$proto"
  ui_confirm "Apply now?" || {
    printf 'Cancelled.\n'
    return 0
  }

  config_set isp_mode "$mode"
  config_set isp_ids "$ids"
  config_set isp_ports "$ports"
  config_set isp_proto "$proto"
  config_set isp_wl "$wl"
  config_set isp_wports "$wports"

  local rc=0
  isp_apply || rc=$?
  if ((rc == 1)); then
    log_error "The blocker could not be applied — removing the partial setup."
    isp_remove
    return 1
  fi
  printf '\n%sISP blocker active.%s Check hits any time with Status.\n' "$C_OK" "$C_RESET"
  printf '%sNote:%s firewall rules are not covered by manifest rollback — remove them with "Remove" here.\n' \
    "$C_MUTED" "$C_RESET"
  return 0
}

isp_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Iran ISP blocker"
    ui_menu_item 1 "Set up / change" "choose ISPs, ports and mode"
    ui_menu_item 2 "Status" "what is blocked, packets dropped"
    ui_menu_item 3 "Update lists" "re-download the ranges and reload"
    ui_menu_item 4 "Remove" "unblock everything"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        isp_configure || true # outcome already reported
        ui_pause
        ;;
      2)
        isp_status
        ui_pause
        ;;
      3)
        if [[ -z "$(config_get isp_mode '')" ]]; then
          printf 'Nothing to update — the blocker is not set up.\n'
        else
          isp_apply || true # outcome already reported
        fi
        ui_pause
        ;;
      4)
        if ui_confirm "Remove the ISP blocker and unblock everything?"; then
          isp_remove
          printf '%sRemoved.%s\n' "$C_OK" "$C_RESET"
        fi
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
