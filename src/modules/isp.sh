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
# IPv6: MCI and Irancell carry IPv6 ranges (data/isp/<id>.ipv6). They are
# enforced through ip6tables and a second set when the host has IPv6 enabled.
#
# The blocker is spread over four files:
#   isp.sh        this file — names, validation, the saved settings, the
#                 blocked set, status, the menu and `st isp ...`
#   isp_lists.sh  the address lists: seed, refresh (checksum-verified), read
#   isp_fw.sh     ipsets, iptables/ip6tables chains, boot unit, apply / verify
#   isplive.sh    `st isp live` — connections per ISP right now
# ============================================================================

readonly ST_ISP_DIR="${ST_LIB_DIR}/isp"
readonly ST_ISP_UNIT='/etc/systemd/system/server-tools-isp.service'
readonly ST_ISP_URL='https://raw.githubusercontent.com/Saj-1992/Xray-VPS-Optimizer/main/data/isp'
readonly ST_ISP_SET='st-isp-list'
readonly ST_ISP_WL='st-isp-wl'
readonly ST_ISP_SET6='st-isp-list6'
readonly ST_ISP_WL6='st-isp-wl6'
readonly ST_ISP_CHAIN_IN='st-isp-in'
readonly ST_ISP_CHAIN_FWD='st-isp-fwd'
# The published SHA256SUMS of the lists (filled by isp_update_lists).
ST_ISP_SUMS=''
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

# _isp_valid_cidr VALUE — an IPv4/IPv6 address or CIDR.
_isp_valid_cidr() {
  local ip="${1%%/*}" mask='' max=32
  [[ $1 == */* ]] && mask="${1#*/}"
  if [[ $ip == *:* ]]; then
    is_valid_ipv6 "$ip" || return 1
    max=128
  else
    is_valid_ipv4 "$ip" || return 1
  fi
  [[ -z $mask ]] && return 0
  [[ $mask =~ ^[0-9]+$ ]] && ((mask <= max))
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

# _isp_session_ip — the client IP (v4 or v6) of the SSH session running this tool.
_isp_session_ip() {
  local ip
  ip="$(awk '{print $1}' <<<"${SSH_CONNECTION:-}")"
  if is_valid_ipv4 "$ip" || is_valid_ipv6 "$ip"; then
    printf '%s' "$ip"
  fi
  return 0
}

# _isp_in_family FAMILY ITEM — does the address/CIDR belong to IPv4 (4) or IPv6 (6)?
_isp_in_family() {
  if [[ $1 == 6 ]]; then
    [[ $2 == *:* ]]
  else
    [[ $2 != *:* ]]
  fi
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

# --- Changing the blocked set ------------------------------------------------

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

# _isp_scope_is_ssh_only PORTS — true when the scope names nothing but the SSH
# port. That port is always exempt, so such a scope blocks nothing at all.
_isp_scope_is_ssh_only() {
  local ssh_port port any=0
  ssh_port="$(detect_ssh_port)"
  while IFS= read -r port; do
    [[ -n $port ]] || continue
    any=1
    [[ $port == "$ssh_port" ]] || return 1
  done < <(ports_split "$1")
  ((any == 1))
}

# isp_set_scope VALUE — "all", or a port list such as 443,8443 / 10000-20000.
isp_set_scope() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_set_scope "$@"
    return
  fi
  local v="${1:-}"
  v="${v,,}"
  v="${v// /}"
  [[ -n $v ]] || die "Usage: st isp scope all | 443,8443 | 10000-20000"
  if [[ $v != all ]]; then
    _isp_csv_valid port "$v" || die "Invalid port list '${1}'."
    if _isp_scope_is_ssh_only "$v"; then
      die "Port $(detect_ssh_port) is your SSH port, which is always exempt — a scope of only that port blocks nothing. Use: st isp scope all"
    fi
    config_set isp_wports ''
  fi
  config_set isp_ports "$v"
  config_set isp_proto both
  isp_apply
}

# isp_set_blocked ID... — replace the blocked set and apply. Used by the menu
# and the CLI, so both always behave the same.
isp_set_blocked() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_set_blocked "$@"
    return
  fi
  _isp_store_ids "$@"
  isp_apply
}

# isp_block ID... / isp_unblock ID... — add to / remove from the blocked set.
isp_block() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_block "$@"
    return
  fi
  local -a cur=() id
  mapfile -t cur < <(_isp_blocked_ids)
  for id in "$@"; do
    _isp_is_blocked "$id" || cur+=("$id")
  done
  isp_set_blocked "${cur[@]}"
}

isp_unblock() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_unblock "$@"
    return
  fi
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
      printf '%s\n' "$id"
    fi
  done
}

# isp_remove — unblock everything and forget the settings.
isp_remove() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_remove
    return
  fi
  _isp_teardown
  local key
  for key in isp_ids isp_ports isp_proto isp_wl isp_wports; do
    config_set "$key" ''
  done
  log_info "ISP blocker removed."
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
  if _isp_scope_is_ssh_only "$(config_get isp_ports all)"; then
    printf '%s  This scope names only the SSH port, which is always exempt — NOTHING is blocked. Fix: st isp scope all%s\n' "$C_ERR" "$C_RESET"
  fi
  ui_kv "Always allowed" "SSH port $(detect_ssh_port), $(config_get isp_wl 'no extra IPs')"
  ui_kv "IPv4 ranges" "$(_isp_set_count "$ST_ISP_SET") blocked"
  if [[ -n "$(_isp_ranges 6 | sed -n '1p')" ]]; then
    if _isp_v6_active; then
      ui_kv "IPv6 ranges" "$(_isp_set_count "$ST_ISP_SET6") blocked"
    else
      ui_kv "IPv6 ranges" "not enforced (IPv6 is off on this host)"
    fi
  fi
  ui_kv "Packets dropped" "$(_isp_drops)"
  if isp_verify; then
    printf '%s  rules in effect%s\n' "$C_OK" "$C_RESET"
  else
    printf '%s  rules are NOT fully in effect — run: st isp update   (or pick any ISP number in the menu)%s\n' "$C_WARN" "$C_RESET"
  fi
  local saved
  if saved="$(_isp_saved_rules_file)"; then
    printf '%s  note: %s contains ServerTools rules (st-isp-*) and can break the boot-time firewall load; remove those lines%s\n' "$C_WARN" "$saved" "$C_RESET"
  fi
}

# _isp_list_has FAMILY IP ID — is IP inside one of ISP ID's cached/embedded ranges?
# IPv4 is a plain numeric comparison; IPv6 goes through a scratch ipset.
_isp_list_has() {
  local fam="$1" ip="$2" id="$3" tmp="st-isp-chk" src res=1 ext=ipv4
  if [[ $fam == 6 ]]; then
    ext=ipv6
  fi
  src="${ST_ISP_DIR}/${id}.${ext}"
  [[ -s $src ]] || return 1
  if [[ $fam == 4 ]]; then
    awk -v ip="$ip" '
      function n(s, a) { split(s, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
      BEGIN { t = n(ip) }
      {
        split($0, c, "/")
        m = (c[2] == "" ? 32 : c[2]); sz = 2 ^ (32 - m); b = n(c[1]); b -= b % sz
        if (t >= b && t < b + sz) { f = 1; exit }
      }
      END { exit !f }' "$src"
    return
  fi
  has_cmd ipset || return 1
  ipset create "$tmp" hash:net family inet6 -exist 2>/dev/null || return 1
  ipset flush "$tmp" 2>/dev/null
  if awk -v s="$tmp" '{print "add " s " " $0}' "$src" | ipset restore -exist 2>/dev/null; then
    ipset test "$tmp" "$ip" >/dev/null 2>&1 && res=0
  fi
  ipset destroy "$tmp" 2>/dev/null
  return "$res"
}

# isp_check IP — "why does this address still connect?" Shows which ISP lists
# contain it, whether the live rules drop it, and whether it is exempt.
isp_check() {
  local ip="${1:-}" fam=4 id found=0 live=''
  if is_valid_ipv6 "$ip"; then
    fam=6
  elif ! is_valid_ipv4 "$ip"; then
    die "Usage: st isp check IP   (an IPv4 or IPv6 address)"
  fi
  _isp_prepare_lists
  ui_section "Iran ISP blocker — ${ip}"
  for id in "${ST_ISP_IDS[@]}"; do
    if _isp_list_has "$fam" "$ip" "$id"; then
      found=1
      if _isp_is_blocked "$id"; then
        ui_kv "In list" "$(_isp_label "$id") — BLOCKED"
      else
        ui_kv "In list" "$(_isp_label "$id") — open (not blocked)"
      fi
    fi
  done
  if ((found == 0)); then
    printf 'Not in any ISP list — the blocker cannot stop this address.\n'
    printf 'Find its owner with: whois %s   (its AS / holder tells which range to add)\n' "$ip"
  fi
  if has_cmd ipset; then
    local lset="$ST_ISP_SET" wset="$ST_ISP_WL"
    if [[ $fam == 6 ]]; then
      lset="$ST_ISP_SET6"
      wset="$ST_ISP_WL6"
    fi
    if ipset test "$wset" "$ip" >/dev/null 2>&1; then
      live="exempt (never blocked: your IP, the exempt list or loopback)"
    elif ipset test "$lset" "$ip" >/dev/null 2>&1; then
      live="DROPPED by the live rules"
    else
      live="not matched by the live rules"
    fi
    ui_kv "Live rules" "$live"
  fi
  return 0
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
  if [[ $ports != all ]] && _isp_scope_is_ssh_only "$ports"; then
    log_error "Port $(detect_ssh_port) is your SSH port, which is always exempt — blocking only it blocks nothing. Choose other ports, or all."
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
  printf '  %sa%s block all   %sn%s open all   %sp%s ports   %sw%s exempt IPs   %su%s update lists   %sc%s check an IP   %sl%s live connections   %s0%s back\n' \
    "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET" "$C_KEY" "$C_RESET"
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
      l)
        ST_LIVE_WATCH=1
        isp_live || true
        ST_LIVE_WATCH=0
        continue
        ;;
      c)
        read -rp "IP address to look up: " tok || tok=''
        if [[ -n $tok ]]; then
          isp_check "${tok// /}" || true
          ui_pause
        fi
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
            printf '%sUnknown choice "%s" — ignored.%s\n' "$C_WARN" "$tok" "$C_RESET"
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
      printf '%sCould not apply — see the message above. The choice is saved; pick any ISP to retry.%s\n' "$C_ERR" "$C_RESET"
    elif ((rc == 3)); then
      printf '%sApplied, with a warning (see above).%s\n' "$C_WARN" "$C_RESET"
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
    check) isp_check "$list" ;;
    scope) isp_set_scope "$list" ;;
    live) isp_live ;;
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
    *) die "Usage: st isp status | live | check IP | scope PORTS | block LIST | unblock LIST | set LIST | all | none | reset | update" ;;
  esac
}
