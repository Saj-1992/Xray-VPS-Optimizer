# shellcheck shell=bash
# ============================================================================
# modules/isplive.sh — `st isp live`: how many connections each Iranian ISP
# has to this server right now.
#
# Method: the kernel's own socket table (`ss`), no packet capture, no extra
# service. Established TCP sockets whose LOCAL port is a listening port are
# inbound connections; each peer address is matched against the ISP address
# lists in data/isp (the same lists the blocker uses). A blocked ISP that still
# shows connections is either an old session that will time out, or traffic the
# rules do not cover — `st isp check IP` says which.
#
#   st isp live                one snapshot
#   st isp live --watch        refresh every few seconds (q quits)
#   st isp live --port 443,8443   only these local ports
# ============================================================================

ST_LIVE_WATCH=0
ST_LIVE_INTERVAL=3
ST_LIVE_PORTS=''

# _live_ranges FILE — "id cidr" lines for every ISP, in the canonical order.
_live_ranges() {
  local id
  for id in "${ST_ISP_IDS[@]}"; do
    if [[ -s ${ST_ISP_DIR}/${id}.ipv4 ]]; then
      sed "s/^/${id} /" "${ST_ISP_DIR}/${id}.ipv4"
    fi
  done >"$1"
}

# _live_peers — one inbound peer address per established TCP socket. Local
# ports must be listening ports (so our own outgoing connections are not
# counted), the SSH port is left out, and --port narrows it down.
_live_peers() {
  local listen ssh_port
  listen="$(ss -Htln 2>/dev/null | awk '{n = split($4, a, ":"); print a[n]}' | sort -u | tr '\n' ' ')"
  ssh_port="$(detect_ssh_port)"
  ss -Htn state established 2>/dev/null | awk -v listen=" ${listen}" -v ssh="$ssh_port" -v only=",${ST_LIVE_PORTS// /}," '
    {
      n = split($3, l, ":"); lp = l[n]
      if (index(listen, " " lp " ") == 0) next
      if (only != ",," ) { if (index(only, "," lp ",") == 0) next }
      else if (lp == ssh) next
      p = $4
      sub(/:[0-9]+$/, "", p); gsub(/[\[\]]/, "", p); sub(/^::ffff:/, "", p)
      print p
    }'
}

# _live_classify RANGES PEERS — "id connections unique-addresses" per ISP; the
# peers that match no list are reported as "other". IPv4 only (see below for v6).
_live_classify() {
  awk '
    function n(s,   a) { split(s, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
    FNR == NR {
      split($2, c, "/"); m = (c[2] == "" ? 32 : c[2]); sz = 2 ^ (32 - m)
      b = n(c[1]); b -= b % sz; o = int(b / 16777216)
      k = ++nb[o]; S[o, k] = b; E[o, k] = b + sz - 1; I[o, k] = $1
      next
    }
    {
      ip = $2; cnt = $1
      if (ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
      t = n(ip); o = int(t / 16777216); id = "other"
      for (k = 1; k <= nb[o]; k++) if (t >= S[o, k] && t <= E[o, k]) { id = I[o, k]; break }
      conns[id] += cnt; ips[id]++
    }
    END { for (id in conns) print id, conns[id], ips[id] }
  ' "$1" "$2"
}

# _live_classify6 PEERS6 — same for native IPv6 peers (rare): matched through a
# scratch ipset against the ISPs that have an IPv6 list.
_live_classify6() {
  local peers="$1" id ip cnt tmp="st-isp-live6" hit
  declare -A c6 u6
  has_cmd ipset || return 0
  while IFS=' ' read -r cnt ip; do
    hit=other
    for id in "${ST_ISP_IDS[@]}"; do
      [[ -s ${ST_ISP_DIR}/${id}.ipv6 ]] || continue
      ipset create "$tmp" hash:net family inet6 -exist 2>/dev/null || continue
      ipset flush "$tmp" 2>/dev/null
      awk -v s="$tmp" '{print "add " s " " $0}' "${ST_ISP_DIR}/${id}.ipv6" | ipset restore -exist 2>/dev/null || true
      if ipset test "$tmp" "$ip" >/dev/null 2>&1; then
        hit="$id"
        break
      fi
    done
    c6[$hit]=$((${c6[$hit]:-0} + cnt))
    u6[$hit]=$((${u6[$hit]:-0} + 1))
  done <"$peers"
  ipset destroy "$tmp" 2>/dev/null || true
  for id in "${!c6[@]}"; do
    printf '%s %s %s\n' "$id" "${c6[$id]}" "${u6[$id]}"
  done
}

# _live_bar PERCENT — a 12-cell bar.
_live_bar() {
  local pct="$1" cells=12 filled i bar=''
  filled=$(((pct * cells + 50) / 100))
  for ((i = 0; i < cells; i++)); do
    if ((i < filled)); then bar+='█'; else bar+='░'; fi
  done
  printf '%s' "$bar"
}

# isp_live_snapshot — gather and print one table.
isp_live_snapshot() {
  local work ranges peers peers4 peers6 id c u total=0 total_u=0
  work="$(mktemp -d)"
  ranges="${work}/ranges"
  peers="${work}/peers"
  peers4="${work}/peers4"
  peers6="${work}/peers6"
  _isp_prepare_lists
  _live_ranges "$ranges"
  _live_peers | sort | uniq -c | awk '{print $1, $2}' >"$peers"
  grep -v ':' "$peers" >"$peers4" || true
  grep ':' "$peers" >"$peers6" || true

  declare -A conns addrs
  while IFS=' ' read -r id c u; do
    [[ -n ${id:-} ]] || continue
    conns[$id]=$((${conns[$id]:-0} + c))
    addrs[$id]=$((${addrs[$id]:-0} + u))
  done < <(
    _live_classify "$ranges" "$peers4"
    if [[ -s $peers6 ]]; then
      _live_classify6 "$peers6"
    fi
  )
  rm -rf "$work"

  for id in "${!conns[@]}"; do
    total=$((total + conns[$id]))
    total_u=$((total_u + addrs[$id]))
  done

  printf '  %s%-22s %12s %10s  %-12s  %s%s\n' "$C_MUTED" "ISP" "Connections" "Addresses" "Share" "State" "$C_RESET"
  local label state pct shown=0 stale=0
  # Busiest ISP first.
  local -a order=()
  mapfile -t order < <(
    for id in "${ST_ISP_IDS[@]}" other; do
      printf '%s %s\n' "${conns[$id]:-0}" "$id"
    done | sort -k1,1nr -s | awk '{print $2}'
  )
  for id in "${order[@]}"; do
    c="${conns[$id]:-0}"
    u="${addrs[$id]:-0}"
    if ((c == 0)); then
      # Only a blocked ISP is worth a row of zeros: it shows the block works.
      if [[ $id == other ]] || ! _isp_is_blocked "$id"; then
        continue
      fi
    fi
    shown=1
    pct=0
    if ((total > 0)); then
      pct=$((c * 100 / total))
    fi
    if [[ $id == other ]]; then
      label='Not in any ISP list'
      state="${C_MUTED}foreign / hosting / unknown${C_RESET}"
    else
      label="$(_isp_label "$id")"
      if _isp_is_blocked "$id"; then
        if ((c > 0)); then
          state="${C_WARN}BLOCKED — still connected${C_RESET}"
          stale=1
        else
          state="${C_OK}BLOCKED — none connected${C_RESET}"
        fi
      else
        state="${C_MUTED}open${C_RESET}"
      fi
    fi
    printf '  %-22s %12s %10s  %s%s%s  %s\n' "$label" "$c" "$u" "$C_ACCENT" "$(_live_bar "$pct")" "$C_RESET" "$state"
  done
  if ((shown == 0)); then
    printf '  %sNo inbound connections right now.%s\n' "$C_MUTED" "$C_RESET"
  fi
  ui_hr
  printf '  %sTotal%s  %s connections from %s addresses' "$C_KEY" "$C_RESET" "$total" "$total_u"
  if [[ -n ${ST_LIVE_PORTS// /} ]]; then
    printf '  (ports %s)' "$ST_LIVE_PORTS"
  else
    printf '  (all listening ports except SSH %s)' "$(detect_ssh_port)"
  fi
  printf '\n'
  if ((stale)); then
    printf '  %sA blocked ISP still has connections: sessions opened before the block time out on their own. If the number does not fall, run: st isp check IP%s\n' "$C_MUTED" "$C_RESET"
  fi
}

# isp_live — one snapshot, or a refreshing view with --watch (q quits).
isp_live() {
  has_cmd ss || die "ss is not available (install iproute2)."
  local key prev_drops cur_drops rate
  if ((ST_LIVE_WATCH == 0)); then
    ui_section "Iran ISP — live connections"
    isp_live_snapshot
    return 0
  fi
  prev_drops="$(_isp_drops 2>/dev/null || printf 0)"
  while true; do
    printf '\033[H\033[2J'
    ui_title "Iran ISP — live connections"
    isp_live_snapshot
    cur_drops="$(_isp_drops 2>/dev/null || printf 0)"
    rate=$(((cur_drops - prev_drops) / ST_LIVE_INTERVAL))
    prev_drops="$cur_drops"
    printf '\n  %sBlocked packets: %s total, about %s/s   · refresh every %ss · q to quit%s\n' \
      "$C_MUTED" "$cur_drops" "$rate" "$ST_LIVE_INTERVAL" "$C_RESET"
    key=''
    read -rsn1 -t "$ST_LIVE_INTERVAL" key || true
    if [[ ${key,,} == q ]]; then
      return 0
    fi
  done
}
