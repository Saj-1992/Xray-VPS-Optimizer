# shellcheck shell=bash
# ============================================================================
# modules/tools.sh — on-demand network diagnostics. Read-only except where
# a tool explicitly says otherwise; nothing here runs in the background.
# ============================================================================

# Format: label|ip
readonly -a ST_PING_TARGETS=(
  'Iran - TCI (217.218.127.127)|217.218.127.127'
  'Iran - Shecan (178.22.122.100)|178.22.122.100'
  'Global - Cloudflare (1.1.1.1)|1.1.1.1'
  'Global - Google (8.8.8.8)|8.8.8.8'
)

# _tcp_probe_ms HOST PORT — real TCP handshake time in ms (bash /dev/tcp or curl).
_tcp_probe_ms() {
  local host="$1" port="${2:-443}"
  if has_cmd curl; then
    local t
    t="$(curl -o /dev/null -sS --max-time 2 -w '%{time_connect}' "https://${host}:${port}" 2>/dev/null)" || t=''
    if [[ -n $t && $t != 0.000000 ]]; then
      awk -v s="$t" 'BEGIN {printf "%.1f", s * 1000}'
      return 0
    fi
  fi
  return 1
}

tools_ping_matrix() {
  ui_section "Iran & global route quality (ICMP + Jitter + TCP/443)"
  if ! has_cmd ping; then
    printf 'ping is not available on this system.\n'
    return 0
  fi
  printf 'Measures ICMP latency/jitter/loss and real TCP/443 handshake time.\n\n'
  local entry label ip out loss avg mdev tcp_ms
  for entry in "${ST_PING_TARGETS[@]}"; do
    IFS='|' read -r label ip <<<"$entry"
    out="$(ping -c 4 -W 1 "$ip" 2>/dev/null)" || out=''
    loss="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' <<<"$out" | cut -d'%' -f1)" || loss=''
    avg="$(awk -F'/' '/rtt|round-trip/ {print $5; exit}' <<<"$out")" || avg=''
    mdev="$(awk -F'/' '/rtt|round-trip/ {gsub(/ ms.*/, "", $7); print $7; exit}' <<<"$out")" || mdev=''
    tcp_ms="$(_tcp_probe_ms "$ip" 443)" || tcp_ms='-'
    if [[ -n $avg ]]; then
      printf '  %-36s loss %3s%%   avg %6s ms (jitter %s)   tcp443 %s ms\n' \
        "$label" "${loss:-?}" "$avg" "${mdev:-?}" "$tcp_ms"
    else
      printf '  %-36s %sunreachable%s   (tcp443 %s ms)\n' "$label" "$C_ERR" "$C_RESET" "$tcp_ms"
    fi
  done
}

tools_tcp_status() {
  ui_section "TCP / UDP / conntrack live status"
  ui_kv "Congestion" "$(sysctl_get net.ipv4.tcp_congestion_control)"
  ui_kv "Qdisc" "$(sysctl_get net.core.default_qdisc)"
  ui_kv "Available cc" "$(sysctl_get net.ipv4.tcp_available_congestion_control)"
  ui_kv "IPv4 forward" "$(sysctl_get net.ipv4.ip_forward)"
  ui_kv "IPv6 forward" "$(sysctl_get net.ipv6.conf.all.forwarding)"

  local count max
  count="$(sysctl_get net.netfilter.nf_conntrack_count)"
  max="$(sysctl_get net.netfilter.nf_conntrack_max)"
  if [[ $count =~ ^[0-9]+$ && $max =~ ^[0-9]+$ && $max -gt 0 ]]; then
    ui_kv "Conntrack" "${count} / ${max} ($((count * 100 / max))% used)"
  else
    ui_kv "Conntrack" "module not loaded"
  fi

  local iface qstat
  iface="$(net_default_iface)" || iface=''
  if [[ -n $iface ]] && has_cmd tc; then
    qstat="$(tc -s qdisc show dev "$iface" 2>/dev/null | grep -oE 'dropped [0-9]+, overlimits [0-9]+, requeues [0-9]+' | head -n1)" || qstat=''
    [[ -n $qstat ]] && ui_kv "Qdisc (${iface})" "$qstat"
  fi

  if [[ -r /proc/net/snmp ]]; then
    local udp_err
    udp_err="$(awk '/^Udp:/ {if (!h) {for (i=1;i<=NF;i++) idx[$i]=i; h=1; next} printf "RcvbufErrors=%s SndbufErrors=%s", $idx["RcvbufErrors"], $idx["SndbufErrors"]; exit}' /proc/net/snmp 2>/dev/null)" || udp_err=''
    [[ -n $udp_err ]] && ui_kv "UDP buffer errs" "$udp_err"
  fi
}

tools_listening_ports() {
  ui_section "Listening ports"
  if ! has_cmd ss; then
    printf 'ss (iproute2) is not available.\n'
    return 0
  fi
  # Display-only snapshot, capped with awk: `head` would SIGPIPE ss under
  # pipefail and turn a fine listing into a spurious warning.
  ss -tulnp 2>/dev/null | awk 'NR <= 30' || log_warn "Could not list sockets."
}

# Ookla speedtest CLI — the accurate, reliable path: it uses Ookla's own
# protocol and a nearby server, so it sidesteps the Cloudflare 403s / inbound
# throttling some hosts (notably in Iran) hit on plain HTTP tests. Fetched on
# demand, run once and deleted — zero persistent footprint (rule 1).
readonly ST_OOKLA_VER='1.2.0'
# Cloudflare's speed endpoints answer 403 to a bare curl UA on some IPs; a
# browser UA dodges that for the HTTP fallback.
readonly ST_HTTP_UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36'

# _st_ookla_arch — Ookla CLI arch tag for this machine (non-zero if unsupported).
_st_ookla_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'x86_64' ;;
    aarch64 | arm64) printf 'aarch64' ;;
    armv7* | armhf) printf 'armhf' ;;
    i386 | i686) printf 'i386' ;;
    *) return 1 ;;
  esac
}

# _st_ookla_sha256 ARCH — the SHA-256 of ookla-speedtest-${ST_OOKLA_VER}-linux-ARCH.tgz,
# pinned here so the archive is checked before anything from it is run. Bump
# these together with ST_OOKLA_VER.
_st_ookla_sha256() {
  case "$1" in
    x86_64) printf '5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7' ;;
    aarch64) printf '3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3' ;;
    armhf) printf 'e45fcdebbd8a185553535533dd032d6b10bc8c64eee4139b1147b9c09835d08d' ;;
    i386) printf '9ff7e18dbae7ee0e03c66108445a2fb6ceea6c86f66482e1392f55881b772fe8' ;;
    *) return 1 ;;
  esac
}

# _st_fetch_ookla — download + extract the official Ookla CLI into a fresh temp
# dir; echo the dir on success (the caller runs and removes it). Empty output /
# non-zero on any failure, so the caller can fall back to the HTTP test.
_st_fetch_ookla() {
  local arch dir url
  arch="$(_st_ookla_arch)" || return 1
  has_cmd tar && has_cmd sha256sum || return 1
  mkdir -p "$ST_LIB_DIR"
  dir="$(mktemp -d "${ST_LIB_DIR}/ookla.XXXXXX" 2>/dev/null)" || return 1
  url="https://install.speedtest.net/app/cli/ookla-speedtest-${ST_OOKLA_VER}-linux-${arch}.tgz"
  if has_cmd curl; then
    curl -fsSL --max-time 60 -o "${dir}/cli.tgz" "$url" 2>>"$ST_LOG_FILE" || {
      rm -rf "$dir"
      return 1
    }
  elif has_cmd wget; then
    wget -q -T 60 -O "${dir}/cli.tgz" "$url" 2>>"$ST_LOG_FILE" || {
      rm -rf "$dir"
      return 1
    }
  else
    rm -rf "$dir"
    return 1
  fi
  # Never unpack or run an archive that is not the one we pinned.
  if [[ "$(sha256sum "${dir}/cli.tgz" | awk '{print $1}')" != "$(_st_ookla_sha256 "$arch")" ]]; then
    log_warn "The downloaded Ookla client does not match its pinned SHA-256 — not used."
    rm -rf "$dir"
    return 1
  fi
  if ! tar -xzf "${dir}/cli.tgz" -C "$dir" 2>>"$ST_LOG_FILE" || [[ ! -x "${dir}/speedtest" ]]; then
    rm -rf "$dir"
    return 1
  fi
  printf '%s' "$dir"
}

# _st_fmt_speed BYTES_PER_SEC — "938.5 Mbit/s  (117.3 MB/s)" or "n/a".
_st_fmt_speed() {
  awk -v s="${1:-0}" 'BEGIN {
    if (s + 0 <= 0) { printf "n/a"; exit }
    printf "%.1f Mbit/s  (%.1f MB/s)", s * 8 / 1000000, s / 1048576
  }'
}

# _st_cf_streams N URL OUTDIR PREFIX WRITEOUT [UPLOAD_FILE] — run N parallel
# curl transfers, each writing its %{WRITEOUT} to OUTDIR/PREFIX<i>, and echo
# the summed rate (bytes/s). Parallel streams are what a real speed test uses:
# a single flow rarely saturates a fast path.
_st_cf_streams() {
  local n="$1" url="$2" dir="$3" prefix="$4" field="$5" upload="${6:-}" i
  rm -f "${dir}/${prefix}"* 2>/dev/null # reusable across fallback attempts
  for ((i = 1; i <= n; i++)); do
    if [[ -n $upload ]]; then
      curl -o /dev/null -s -A "$ST_HTTP_UA" --max-time 20 -w "%{${field}}\n" \
        --data-binary @"$upload" "$url" >"${dir}/${prefix}${i}" 2>/dev/null &
    else
      curl -o /dev/null -s -A "$ST_HTTP_UA" --max-time 20 -w "%{${field}}\n" \
        "$url" >"${dir}/${prefix}${i}" 2>/dev/null &
    fi
  done
  wait
  cat "${dir}/${prefix}"* 2>/dev/null | awk '{s += $1} END {printf "%.0f", s + 0}'
}

# --- Result rendering -------------------------------------------------------
# Both back-ends (Ookla and the HTTP fallback) funnel their numbers through one
# renderer, so a test looks identical wherever it came from and matches the rest
# of the UI (ui_kv rows, palette colours, whitespace instead of rules).

# _st_mbit BYTES_PER_SEC — short "938.5 Mbit/s" for the live status line.
_st_mbit() {
  awk -v b="${1:-0}" 'BEGIN { printf "%.1f Mbit/s", b * 8 / 1000000 }'
}

# _st_status TEXT — one in-place status line during a test (carriage return,
# padded wide enough to overwrite a longer previous line).
_st_status() {
  printf '\r    %s%-48s%s' "$C_MUTED" "$1" "$C_RESET"
}

# _st_render_card SERVER ISP PING JITTER DL_BPS UL_BPS LOSS URL — the result
# card. Empty fields are skipped, so it fits Ookla (full) and the HTTP fallback
# (no jitter/loss/url) alike.
_st_render_card() {
  local server="$1" isp="$2" ping="$3" jit="$4" dl="$5" ul="$6" loss="$7" url="$8"
  printf '\n'
  [[ -n $server ]] && ui_kv "Server" "$server"
  [[ -n $isp ]] && ui_kv "ISP" "$isp"
  printf '\n'
  if [[ -n $ping ]]; then
    if [[ -n $jit ]]; then
      ui_kv "Ping" "${ping} ms   (jitter ${jit} ms)"
    else
      ui_kv "Ping" "${ping} ms"
    fi
  fi
  ui_kv "Download" "$(_st_fmt_speed "$dl")"
  ui_kv "Upload" "$(_st_fmt_speed "$ul")"
  [[ -n $loss ]] && ui_kv "Packet loss" "${loss} %"
  if [[ -n $url ]]; then
    printf '\n'
    ui_kv "Result" "$url"
  fi
  printf '\n'
  return 0
}

# --- Minimal JSON readers for the Ookla CLI's one-object-per-line output.
# Flat, first-match, and ALWAYS successful (empty on no match) so a missing
# field can never trip errexit inside the read loop below.
_st_json_str() {
  local m
  m="$(grep -oE "\"$2\":\"[^\"]*\"" <<<"$1" | head -1)" || m=''
  m="${m#*:\"}"
  printf '%s' "${m%\"}"
  return 0
}

_st_json_num() {
  local m
  m="$(grep -oE "\"$2\":[0-9]+(\.[0-9]+)?" <<<"$1" | head -1)" || m=''
  printf '%s' "${m##*:}"
  return 0
}

_st_json_pct() {
  local p pct
  p="$(_st_json_num "$1" progress)"
  [[ $p =~ ^[0-9.]+$ ]] || p=0
  pct="$(awk -v x="$p" 'BEGIN { printf "%d", x * 100 }')"
  printf '%s' "$pct"
  return 0
}

# _st_ookla_card RESULT_JSON — parse one Ookla "type:result" object (bandwidth
# is bytes/s, same unit the card expects) and render it.
_st_ookla_card() {
  local json="$1" ping jit loss isp url server name loc country ping_obj srv_obj
  local -a bws
  ping_obj="${json#*\"ping\":\{}"
  ping_obj="${ping_obj%%\}*}"
  ping="$(_st_json_num "$ping_obj" latency)"
  jit="$(_st_json_num "$ping_obj" jitter)"
  # Exactly two "bandwidth" fields: download first, upload second.
  mapfile -t bws < <(grep -oE '"bandwidth":[0-9]+' <<<"$json" | grep -oE '[0-9]+')
  loss="$(_st_json_num "$json" packetLoss)"
  isp="$(_st_json_str "$json" isp)"
  url="$(grep -oE '"url":"[^"]*"' <<<"$json" | head -1)" || url=''
  url="${url#*:\"}"
  url="${url%\"}"
  srv_obj="${json#*\"server\":\{}"
  srv_obj="${srv_obj%%\}*}"
  name="$(_st_json_str "$srv_obj" name)"
  loc="$(_st_json_str "$srv_obj" location)"
  country="$(_st_json_str "$srv_obj" country)"
  server="$name"
  [[ -n $loc ]] && server="${server:+${server} · }${loc}"
  [[ -n $country ]] && server="${server:+${server}, }${country}"
  _st_render_card "$server" "$isp" "$ping" "$jit" "${bws[0]:-0}" "${bws[1]:-0}" "$loss" "$url"
  return 0
}

# --- Server selection -------------------------------------------------------
# ST_SPEEDTEST_SERVER holds the chosen Ookla server id (empty = automatic).
ST_SPEEDTEST_SERVER=''

# _st_nearby BIN — "id|description" per nearby server, parsed from the stable
# text of `-L`. Empty if none / unsupported.
_st_nearby() {
  "$1" -L --accept-license --accept-gdpr 2>/dev/null | awk '
    /^=+$/ { seen = 1; next }
    seen && $1 ~ /^[0-9]+$/ {
      id = $1; $1 = ""; sub(/^ +/, ""); gsub(/ {2,}/, " ")
      print id "|" $0
    }' || true
}

# _st_pick_nearby BIN — list the closest servers and let the user choose one.
_st_pick_nearby() {
  local nearby line n=0 sel
  local -a list
  printf '  %sFinding nearby servers…%s\n' "$C_MUTED" "$C_RESET"
  nearby="$(_st_nearby "$1")" || nearby=''
  if [[ -z $nearby ]]; then
    printf '  %sCould not list servers — using Automatic.%s\n' "$C_WARN" "$C_RESET"
    ST_SPEEDTEST_SERVER=''
    return 0
  fi
  mapfile -t list <<<"$nearby"
  printf '\n'
  for line in "${list[@]}"; do
    ((n < 12)) || break
    n=$((n + 1))
    printf '    %s%2d%s  %s\n' "$C_KEY" "$n" "$C_RESET" "${line#*|}"
  done
  read -rp "  Server number [1-${n}, Enter = Automatic]: " sel ||
    {
      ST_SPEEDTEST_SERVER=''
      return 0
    }
  if [[ $sel =~ ^[0-9]+$ ]] && ((sel >= 1 && sel <= n)); then
    ST_SPEEDTEST_SERVER="${list[sel - 1]%%|*}"
  else
    ST_SPEEDTEST_SERVER=''
  fi
  return 0
}

# _st_pick_by_id — target any city/country by its speedtest.net server id.
_st_pick_by_id() {
  local id
  printf '  %sEvery server page on speedtest.net shows its numeric ID. Any\n' "$C_MUTED"
  printf '  city or country works — enter one to test that route.%s\n' "$C_RESET"
  read -rp "  Server ID [Enter = Automatic]: " id ||
    {
      ST_SPEEDTEST_SERVER=''
      return 0
    }
  if [[ $id =~ ^[0-9]+$ ]]; then
    ST_SPEEDTEST_SERVER="$id"
  else
    [[ -n $id ]] && printf '  %sNot a numeric ID — using Automatic.%s\n' "$C_WARN" "$C_RESET"
    ST_SPEEDTEST_SERVER=''
  fi
  return 0
}

# _st_choose_server BIN — sets ST_SPEEDTEST_SERVER. Returns 2 if cancelled.
_st_choose_server() {
  local bin="$1" choice
  ST_SPEEDTEST_SERVER=''
  printf '\n  %sTest server%s\n' "$C_ACCENT" "$C_RESET"
  ui_menu_item 1 "Automatic" "nearest server · recommended"
  ui_menu_item 2 "Choose nearby" "pick from the closest servers"
  ui_menu_item 3 "By server ID" "any city worldwide (from speedtest.net)"
  ui_menu_item 0 "Cancel"
  read -rp "$(_ui_prompt)" choice || return 2
  case "${choice:-1}" in
    1 | '') return 0 ;;
    2) _st_pick_nearby "$bin" ;;
    3) _st_pick_by_id ;;
    0) return 2 ;;
    *) return 0 ;;
  esac
}

# _st_run_ookla BIN — run Ookla in jsonl mode, animate a live status line from
# its progress events, and render the result card. Honours ST_SPEEDTEST_SERVER.
_st_run_ookla() {
  local bin="$1" line type result='' lat bw ping_obj
  local -a args=(--format=jsonl --accept-license --accept-gdpr)
  [[ -n $ST_SPEEDTEST_SERVER ]] && args+=(-s "$ST_SPEEDTEST_SERVER")

  printf '\n'
  # Process substitution: a non-zero exit from the client just ends the loop
  # (no pipefail/ERR-trap surprise) and leaves $result empty, handled below.
  while IFS= read -r line; do
    type="$(_st_json_str "$line" type)"
    case "$type" in
      ping)
        lat="$(_st_json_num "$line" latency)"
        _st_status "Latency · ${lat:-…} ms · $(_st_json_pct "$line")%"
        ;;
      download)
        bw="$(_st_json_num "$line" bandwidth)"
        _st_status "Download · $(_st_mbit "${bw:-0}") · $(_st_json_pct "$line")%"
        ;;
      upload)
        bw="$(_st_json_num "$line" bandwidth)"
        _st_status "Upload · $(_st_mbit "${bw:-0}") · $(_st_json_pct "$line")%"
        ;;
      result) result="$line" ;;
    esac
    # The client's own non-zero exit (e.g. a chosen server refused the test) is
    # surfaced by the empty-$result check below; `|| true` keeps that failure
    # from reaching the ERR trap from inside this process substitution.
  done < <("$bin" "${args[@]}" 2>>"$ST_LOG_FILE" || true)
  printf '\r%*s\r' 54 ''

  if [[ -z $result ]]; then
    log_warn "The Ookla speedtest returned no result (server unreachable?)."
    printf '  %sNo result — the chosen server may be unavailable. Try Automatic.%s\n' \
      "$C_WARN" "$C_RESET"
    return 1
  fi
  _st_ookla_card "$result"
  ping_obj="${result#*\"ping\":\{}"
  ping_obj="${ping_obj%%\}*}"
  log_info "Speedtest (Ookla): ping=$(_st_json_num "$ping_obj" latency)ms server=${ST_SPEEDTEST_SERVER:-auto}"
  return 0
}

# tools_speedtest — a real, reliable bandwidth test with a premium, consistent
# result card and a location picker. In order of preference:
#   1. an Ookla binary already on the host (gold standard);
#   2. the official Ookla CLI, fetched, run once and deleted (accurate, picks a
#      nearby server, sidesteps Cloudflare 403s some hosts get);
#   3. a self-contained HTTP test (parallel streams to Cloudflare + mirrors).
# The deprecated speedtest.net Python client is never used — it breaks against
# Ookla's API and is frequently filtered from Iran.
tools_speedtest() {
  ui_section "Bandwidth test"
  printf 'A real download / upload / latency test. It briefly uses bandwidth.\n'

  local bin='' fetched=''
  if has_cmd speedtest && speedtest --version 2>/dev/null | grep -qi 'ookla'; then
    bin='speedtest'
  elif _st_ookla_arch >/dev/null 2>&1 && has_cmd tar && { has_cmd curl || has_cmd wget; }; then
    printf '\nThe most accurate test uses the official %sOokla%s client —\n' "$C_KEY" "$C_RESET"
    printf '%sdownloaded, run once, then deleted (nothing stays installed).%s\n' "$C_MUTED" "$C_RESET"
    if ui_confirm "Download and run it now?"; then
      printf '  %sFetching the Ookla client…%s\n' "$C_MUTED" "$C_RESET"
      fetched="$(_st_fetch_ookla)" || fetched=''
      if [[ -n $fetched ]]; then
        bin="${fetched}/speedtest"
      else
        log_warn "Could not fetch the Ookla client — using the built-in HTTP test instead."
      fi
    fi
  fi

  if [[ -n $bin ]]; then
    local rc=0
    if _st_choose_server "$bin"; then
      _st_run_ookla "$bin" || rc=$?
    else
      rc=2 # cancelled at the server picker
    fi
    [[ -n $fetched ]] && rm -rf "$fetched"
    return "$rc"
  fi

  _st_http_test
}

# _st_http_test — dependency-light fallback when no Ookla client is available:
# parallel HTTP streams to Cloudflare with mirror fallback, into the same card.
_st_http_test() {
  if ! has_cmd curl; then
    log_error "curl is required for the built-in bandwidth test."
    return 1
  fi
  printf '\nBuilt-in %sdownload · upload · latency%s test (Cloudflare + mirrors).\n' "$C_KEY" "$C_RESET"
  ui_confirm "Run it now? (transfers up to ~500 MB)" || return 2

  local base='https://speed.cloudflare.com' streams=4 ul_bytes=26214400
  local dir lat dl=0 ul=0 src dl_host='n/a'

  printf '\n'
  _st_status "Latency…"
  lat="$(for _ in 1 2 3; do
    curl -o /dev/null -s -A "$ST_HTTP_UA" -w '%{time_connect}\n' --max-time 5 "${base}/__down?bytes=0" 2>/dev/null
  done | awk 'NF && $1 + 0 > 0 {if (m == 0 || $1 < m) m = $1} END {if (m > 0) printf "%.1f", m * 1000}')"

  mkdir -p "$ST_LIB_DIR"
  dir="$(mktemp -d "${ST_LIB_DIR}/sptest.XXXXXX" 2>/dev/null)" || dir=''
  if [[ -z $dir ]]; then
    printf '\r%*s\r' 54 ''
    log_error "Could not create a work directory for the test."
    return 1
  fi

  # Cloudflare caps __down at 1e8 bytes and some networks throttle large inbound
  # CDN transfers even when upload is fine, so we try Cloudflare then mirrors and
  # keep the first source that actually moves bytes.
  _st_status "Download…"
  for src in \
    "${base}/__down?bytes=100000000|Cloudflare" \
    'https://speed.hetzner.de/100MB.bin|Hetzner' \
    'http://ipv4.download.thinkbroadband.com/100MB.zip|thinkbroadband'; do
    dl="$(_st_cf_streams "$streams" "${src%%|*}" "$dir" dl speed_download)"
    if ((dl > 0)); then
      dl_host="${src##*|}"
      break
    fi
  done

  _st_status "Upload…"
  head -c "$ul_bytes" /dev/zero >"${dir}/payload" 2>/dev/null
  ul="$(_st_cf_streams "$streams" "${base}/__up" "$dir" ul speed_upload "${dir}/payload")"
  rm -rf "$dir"
  printf '\r%*s\r' 54 ''

  if ((dl == 0 && ul == 0)); then
    log_error "Could not reach the Cloudflare speed servers — network blocked? See the log."
    return 1
  fi
  _st_render_card "HTTP test · ${dl_host} · ${streams} streams" "" "${lat}" "" "$dl" "$ul" "" ""
  log_info "Bandwidth test (HTTP): down=${dl}B/s (${dl_host}) up=${ul}B/s ping=${lat:-?}ms."
  return 0
}

# tools_benchmark — quick, dependency-light CPU and disk figures. Comparable
# between servers, not absolute hardware ratings. The disk test averages three
# runs (like bench.sh) so one cached run cannot flatter the result, and AES-NI
# is reported because it decides TLS/Reality throughput on a proxy node.
tools_benchmark() {
  ui_section "Quick benchmark"

  ui_kv "CPU" "$(cpu_model)"
  local aes='no'
  grep -qm1 -w aes /proc/cpuinfo 2>/dev/null && aes='yes'
  ui_kv "Cores · AES-NI" "$(cpu_cores) · ${aes}"

  if has_cmd sha256sum; then
    local start end
    start="$(date +%s%N)"
    dd if=/dev/zero bs=1M count=256 status=none 2>/dev/null | sha256sum >/dev/null
    end="$(date +%s%N)"
    ui_kv "SHA256 (256 MB)" "$(awk -v n=$((end - start)) 'BEGIN {printf "%.2f s", n / 1000000000}')"
  fi

  local target='/var/tmp' avail_mb
  avail_mb="$(df -Pm "$target" 2>/dev/null | awk 'NR == 2 {print $4}')" || avail_mb=0
  [[ $avail_mb =~ ^[0-9]+$ ]] || avail_mb=0
  if ((avail_mb > 2048)); then
    printf '  %s%-19s%s measuring…' "$C_KEY" "Disk write (3×1 GB)" "$C_RESET"
    local run out mbps sum=0 cnt=0
    for run in 1 2 3; do
      out="$(LC_ALL=C dd if=/dev/zero of="${target}/.st-bench" bs=1M count=1024 conv=fdatasync 2>&1)" || out=''
      # dd's summary line ends in "… , N MB/s" (or GB/s / kB/s) — normalise to MB/s.
      mbps="$(awk '/copied|bytes/ {u = $NF; v = $(NF - 1) + 0
        if (u == "GB/s") v *= 1024; else if (u == "kB/s") v /= 1024
        printf "%.0f", v; exit}' <<<"$out")"
      [[ $mbps =~ ^[0-9]+$ ]] && {
        sum=$((sum + mbps))
        cnt=$((cnt + 1))
      }
    done
    rm -f "${target}/.st-bench"
    if ((cnt > 0)); then
      printf '\r  %s%-19s%s %d MB/s (avg of %d)        \n' "$C_KEY" "Disk write (3×1 GB)" "$C_RESET" $((sum / cnt)) "$cnt"
    else
      printf '\r  %s%-19s%s unavailable        \n' "$C_KEY" "Disk write (3×1 GB)" "$C_RESET"
    fi
  else
    ui_kv "Disk write" "skipped (needs 2 GB free in ${target})"
  fi

  ui_kv "Load · RAM" "$(load_avg) · $(mem_total_mb) MB"
  return 0
}

# tools_watch — live view of what matters under load. A foreground viewer,
# not a service: it exits when you leave and leaves nothing behind.
tools_watch() {
  if [[ ! -t 0 ]]; then
    printf 'The live view needs an interactive terminal.\n'
    return 2
  fi
  local iface rx_prev tx_prev rx tx ct max sockets key
  iface="$(net_default_iface)" || iface=''
  if [[ -z $iface || ! -r /sys/class/net/${iface}/statistics/rx_bytes ]]; then
    printf 'Cannot read interface counters for the live view.\n'
    return 2
  fi
  rx_prev="$(cat "/sys/class/net/${iface}/statistics/rx_bytes")"
  tx_prev="$(cat "/sys/class/net/${iface}/statistics/tx_bytes")"

  while true; do
    sleep 2
    rx="$(cat "/sys/class/net/${iface}/statistics/rx_bytes")"
    tx="$(cat "/sys/class/net/${iface}/statistics/tx_bytes")"
    ct="$(sysctl_get net.netfilter.nf_conntrack_count)"
    max="$(sysctl_get net.netfilter.nf_conntrack_max)"
    sockets="$(awk '/^TCP:/ {print $3; exit}' /proc/net/sockstat 2>/dev/null)" || sockets='?'

    clear 2>/dev/null || true # cosmetic only
    ui_title "Live view — ${iface} (press q to quit)"
    ui_kv "Traffic" "$(awk -v r=$((rx - rx_prev)) -v t=$((tx - tx_prev)) \
      'BEGIN {printf "down %.2f Mbit/s · up %.2f Mbit/s", r * 8 / 2000000, t * 8 / 2000000}')"
    ui_kv "TCP sockets" "$sockets"
    if [[ $ct =~ ^[0-9]+$ && $max =~ ^[0-9]+$ && $max -gt 0 ]]; then
      ui_kv "Conntrack" "${ct} / ${max} ($((ct * 100 / max))%)"
    else
      ui_kv "Conntrack" "module not loaded"
    fi
    ui_kv "Load" "$(load_avg)"
    ui_kv "RAM available" "$(awk '/^MemAvailable:/ {printf "%d MB", $2 / 1024; exit}' /proc/meminfo)"
    rx_prev="$rx"
    tx_prev="$tx"

    # Non-blocking key check: the sleep above paces the loop.
    if read -rsn1 -t 0.01 key && [[ ${key,,} == q ]]; then
      printf '\n'
      return 0
    fi
  done
}

# tools_report — plain-text support bundle (also behind --report). Printed
# to stdout AND saved, so users can paste it into an issue/ticket directly.
tools_report() {
  local out="${ST_LIB_DIR}/report-${ST_RUN_ID}.txt"
  {
    printf '=== %s support report v%s — %s ===\n\n' "$ST_NAME" "$ST_VERSION" "$(date '+%F %T')"
    printf -- '--- System\n'
    printf 'OS: %s\nKernel: %s\nVirt: %s\nUptime: %s\n' \
      "$(os_pretty_name)" "$(kernel_release)" "$(detect_virt)" "$(uptime_pretty)"
    printf 'CPU: %s (%s cores)\nRAM: %s MB\nLoad: %s\n\n' \
      "$(cpu_model)" "$(cpu_cores)" "$(mem_total_mb)" "$(load_avg)"
    printf -- '--- Workload\n'
    printf 'Detected: %s\n' "$(detect_summary)"
    printf 'Saved profile/tier: %s / %s\n\n' \
      "$(config_get last_profile none)" "$(config_get last_tier -)"
    printf -- '--- DNS\n'
    printf 'Resolver stack: %s\n' "$(dns_stack)"
    printf 'Servers in effect: %s\n' "$(dns_effective_servers)"
    printf 'DNS over TLS: %s\n\n' "$(dns_over_tls_state)"
    printf -- '--- Kernel tuning (live)\n'
    local key
    for key in net.ipv4.tcp_congestion_control net.core.default_qdisc \
      net.ipv4.tcp_mtu_probing net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
      net.core.somaxconn net.core.rmem_max net.netfilter.nf_conntrack_max \
      net.netfilter.nf_conntrack_count fs.file-max vm.swappiness; do
      printf '%s = %s\n' "$key" "$(sysctl_get "$key")"
    done
    printf 'nofile soft/hard: %s / %s\n\n' \
      "$(ulimit -Sn 2>/dev/null || printf '?')" "$(ulimit -Hn 2>/dev/null || printf '?')"
    printf -- '--- Swap\n'
    if [[ -r /proc/swaps ]]; then cat /proc/swaps; else printf 'unavailable\n'; fi
    printf '\n'
    printf -- '--- Manifest (last 15 changes)\n'
    if [[ -f $ST_MANIFEST_FILE ]]; then
      awk 'NR > 1' "$ST_MANIFEST_FILE" | tail -n 15
    else
      printf 'no manifest yet\n'
    fi
    printf '\n'
    printf -- '--- Log (last 30 lines)\n'
    if [[ -f $ST_LOG_FILE ]]; then tail -n 30 "$ST_LOG_FILE"; else printf 'no log yet\n'; fi
    printf '\n=== end of report ===\n'
  } | tee "$out"
  printf '\n%sSaved:%s %s\n' "$C_OK" "$C_RESET" "$out"
  log_info "Support report written to ${out}."
}

# --- Peer iperf3, Reality SNI, NIC ring, XanMod check, Safe Disk Cleaner ------

# tools_iperf3 — guided single-shot iperf3 test between two nodes (Iran <-> foreign).
tools_iperf3() {
  ui_section "Peer bandwidth test (iperf3, Iran <-> foreign)"
  if ! has_cmd iperf3; then
    ui_confirm "iperf3 is not installed. Install it now?" || return 0
    pkg_install iperf3 || {
      log_error "Could not install iperf3."
      return 1
    }
  fi
  local mode port peer rev_flag='' proto_flag=''
  printf '  1) Server mode  (listen once on this host, auto-exits after test)\n'
  printf '  2) Client mode  (connect to a peer running iperf3 server)\n'
  read -rp "Choose [1/2, Enter=cancel]: " mode || return 0
  case "$mode" in
    1)
      read -rp "Listen port [5201]: " port || return 0
      port="${port:-5201}"
      [[ $port =~ ^[0-9]+$ ]] || {
        log_error "Invalid port."
        return 1
      }
      printf 'Listening on %s (one-shot: exits as soon as client finishes)...\n' "$port"
      iperf3 -s -1 -p "$port" || true
      ;;
    2)
      read -rp "Peer IP / hostname: " peer || return 0
      [[ -n $peer ]] || return 0
      read -rp "Peer port [5201]: " port || return 0
      port="${port:-5201}"
      [[ $port =~ ^[0-9]+$ ]] || {
        log_error "Invalid port."
        return 1
      }
      ui_confirm "Test reverse download direction (-R, peer -> this host)?" && rev_flag='-R'
      ui_confirm "Use UDP instead of TCP?" && proto_flag='-u -b 0'
      # shellcheck disable=SC2086
      iperf3 -c "$peer" -p "$port" -P 4 -t 10 $rev_flag $proto_flag || true
      ;;
    *) return 0 ;;
  esac
}

# tools_sni_check — Reality SNI validator (TLS 1.3, ALPN h2, X25519, latency).
tools_sni_check() {
  ui_section "Reality SNI validator"
  has_cmd openssl || {
    log_error "openssl is required."
    return 1
  }
  local host port=443 out tls alpn kex verify_rc tcp_ms
  read -rp "Target SNI domain (e.g. www.google.com, yahoo.com): " host || return 0
  host="${host// /}"
  [[ -n $host ]] || return 0

  out="$(printf '' | timeout 5 openssl s_client -connect "${host}:${port}" -servername "$host" -tls1_3 -alpn h2 2>&1)" || true
  tls="$(awk -F': *' '/Protocol[[:space:]]*:/ {print $2; exit}' <<<"$out")"
  alpn="$(awk -F': *' '/ALPN protocol:/ {print $2; exit}' <<<"$out")"
  kex="$(awk -F': *' '/Server Temp Key:/ {print $2; exit}' <<<"$out")"
  verify_rc="$(awk -F': *' '/Verify return code:/ {print $2; exit}' <<<"$out")"
  tcp_ms="$(_tcp_probe_ms "$host" "$port")" || tcp_ms='-'

  ui_kv "Target" "${host}:${port}"
  ui_kv "TCP+TLS ping" "${tcp_ms} ms"
  ui_kv "Protocol" "${tls:-none}"
  ui_kv "ALPN" "${alpn:-none}"
  ui_kv "Key exchange" "${kex:-unknown}"
  ui_kv "Cert verify" "${verify_rc:-unknown}"

  if [[ $tls == *TLSv1.3* && $alpn == *h2* && $kex == *X25519* ]]; then
    printf '\n%sGOOD for Reality:%s supports TLS 1.3 + h2 + X25519.\n' "$C_OK" "$C_RESET"
  else
    printf '\n%sNOT ideal for Reality:%s missing TLSv1.3, ALPN h2, or X25519.\n' "$C_WARN" "$C_RESET"
  fi
}

# tools_nic_ring — inspect and optionally raise NIC RX/TX ring buffers.
tools_nic_ring() {
  ui_section "NIC ring buffer (ethtool -G)"
  local iface
  iface="$(net_default_iface)" || iface=''
  [[ -n $iface ]] || {
    log_error "No default interface found."
    return 1
  }
  if ! has_cmd ethtool; then
    ui_confirm "ethtool is not installed. Install it now?" || return 0
    pkg_install ethtool || return 1
  fi
  local info
  info="$(ethtool -g "$iface" 2>/dev/null)" || {
    printf 'Driver for %s does not expose ring parameters.\n' "$iface"
    return 0
  }
  printf '%s\n\n' "$info"
  printf '%sNote:%s changing ring sizes may briefly reset the NIC link on some drivers.\n' "$C_WARN" "$C_RESET"
  ui_confirm "Raise RX/TX ring buffers toward driver maximum (capped at 4096)?" || return 0

  local max_rx max_tx target_rx target_tx
  max_rx="$(awk '/Pre-set maximums:/{f=1;next} /Current hardware settings:/{f=0} f && /^RX:/ {print $2; exit}' <<<"$info")"
  max_tx="$(awk '/Pre-set maximums:/{f=1;next} /Current hardware settings:/{f=0} f && /^TX:/ {print $2; exit}' <<<"$info")"
  [[ $max_rx =~ ^[0-9]+$ ]] || max_rx=0
  [[ $max_tx =~ ^[0-9]+$ ]] || max_tx=0
  target_rx=$max_rx
  target_tx=$max_tx
  ((target_rx > 4096)) && target_rx=4096
  ((target_tx > 4096)) && target_tx=4096

  local -a args=()
  ((target_rx > 0)) && args+=(rx "$target_rx")
  ((target_tx > 0)) && args+=(tx "$target_tx")
  ((${#args[@]} > 0)) || {
    printf 'No adjustable ring parameters.\n'
    return 0
  }
  if ethtool -G "$iface" "${args[@]}" 2>>"$ST_LOG_FILE"; then
    printf '%sUpdated %s ring buffers (%s).%s\n' "$C_OK" "$iface" "${args[*]}" "$C_RESET"
    log_info "ethtool -G ${iface} ${args[*]}"
  else
    log_warn "ethtool -G failed on ${iface} — see log."
  fi
}

# tools_xanmod_check — pre-flight compatibility check for XanMod / BBRv3.
tools_xanmod_check() {
  ui_section "XanMod / BBRv3 compatibility check"
  local virt arch boot_mb flags lvl='x86-64-v1' cc mod_ver
  virt="$(detect_virt)"
  arch="$(uname -m)"
  boot_mb="$(df -Pm /boot 2>/dev/null | awk 'NR==2 {print $4}')" || boot_mb=0
  cc="$(sysctl_get net.ipv4.tcp_congestion_control)"
  mod_ver="$(modinfo -F version tcp_bbr 2>/dev/null || printf 'built-in/unknown')"
  flags="$(awk -F': ' '/^flags/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
  if [[ $flags == *avx2* && $flags == *bmi2* && $flags == *fma* ]]; then
    lvl='x86-64-v3'
  elif [[ $flags == *sse4_2* && $flags == *popcnt* ]]; then
    lvl='x86-64-v2'
  fi

  ui_kv "Architecture" "${arch} (${lvl})"
  ui_kv "Virtualization" "$virt"
  ui_kv "/boot free" "${boot_mb:-?} MB"
  ui_kv "Live CC / BBR" "${cc} (${mod_ver})"

  local ok=1
  if [[ $arch != x86_64 ]]; then
    printf '%sBLOCKER:%s XanMod requires x86_64 (found %s).\n' "$C_ERR" "$C_RESET" "$arch"
    ok=0
  fi
  case "$virt" in
    lxc | lxc-libvirt | openvz | docker | podman)
      printf '%sBLOCKER:%s container (%s) shares host kernel — cannot boot a custom kernel.\n' "$C_ERR" "$C_RESET" "$virt"
      ok=0
      ;;
  esac
  if [[ $boot_mb =~ ^[0-9]+$ ]] && ((boot_mb < 250)); then
    printf '%sWARN:%s /boot has only %s MB free (recommend >= 250 MB).\n' "$C_WARN" "$C_RESET" "$boot_mb"
    ok=0
  fi
  ((ok)) && printf '\n%sHost is compatible with XanMod (%s).%s\n' "$C_OK" "$lvl" "$C_RESET"
  return 0
}

# tools_disk_cleaner — safely inspect and reclaim disk space (logs, apt, docker).
tools_disk_cleaner() {
  ui_section "Safe disk cleaner"
  local docker_mb=0 apt_mb=0
  if [[ -d /var/lib/docker/containers ]]; then
    docker_mb="$(du -sm /var/lib/docker/containers/*/*-json.log 2>/dev/null | awk '{s+=$1} END {print s+0}')"
  fi
  if [[ -d /var/cache/apt/archives ]]; then
    apt_mb="$(du -sm /var/cache/apt/archives 2>/dev/null | awk '{print $1+0}')"
  fi
  ui_kv "Disk / usage" "$(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 ")"}')"
  ui_kv "Docker JSON logs" "${docker_mb} MB"
  ui_kv "APT cache" "${apt_mb} MB"
  has_cmd journalctl && ui_kv "Journald usage" "$(journalctl --disk-usage 2>/dev/null | awk '{print $NF}')"

  if ((apt_mb > 10)) && has_cmd apt-get && ui_confirm "Clean APT cache (${apt_mb} MB)?"; then
    apt-get clean >/dev/null 2>>"$ST_LOG_FILE" || true
    printf 'APT cache cleaned.\n'
  fi
  if has_cmd journalctl && ui_confirm "Vacuum systemd journal logs older than 7 days / >100M?"; then
    journalctl --vacuum-size=100M --vacuum-time=7d >/dev/null 2>>"$ST_LOG_FILE" || true
    printf 'Journald vacuumed.\n'
  fi
  if ((docker_mb > 50)) && ui_confirm "Truncate oversized Docker container logs (${docker_mb} MB total)?"; then
    find /var/lib/docker/containers -name '*-json.log' -size +50M -exec truncate -s 0 {} + 2>/dev/null || true
    printf 'Oversized Docker logs truncated.\n'
  fi
  if has_cmd docker && ui_confirm "Prune unused/dangling Docker images (docker image prune -f)?"; then
    docker image prune -f >/dev/null 2>>"$ST_LOG_FILE" || true
    printf 'Dangling Docker images pruned.\n'
  fi
  return 0
}

tools_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Network & VPN Tools"
    ui_menu_group "Diagnose"
    ui_menu_item 1 "Ping & route quality" "Iran + global ICMP, jitter, TCP/443"
    ui_menu_item 2 "DNS latency" "ping every DNS provider"
    ui_menu_item 3 "TCP / UDP / conntrack" "BBR · qdisc drops · UDP errs · table"
    ui_menu_item 4 "Listening ports" "ss snapshot"
    ui_menu_item v "Reality SNI check" "validate TLS 1.3 · ALPN h2 · X25519"
    ui_menu_group "Measure"
    ui_menu_item 9 "Bandwidth test" "speedtest or HTTP download"
    ui_menu_item x "Peer iperf3 test" "Iran <-> foreign server/client test"
    ui_menu_item b "Quick benchmark" "CPU and disk"
    ui_menu_item w "Live view" "traffic · sockets · conntrack"
    ui_menu_group "Network"
    ui_menu_item 5 "Smart MTU / MSS" "measure the path, fix 'connects but no sites'"
    ui_menu_item p "Proxy priority" "CPU + OOM priority for Xray · Docker nodes"
    ui_menu_item n "Conntrack NOTRACK" "exempt proxy ports (Xray/Reality)"
    ui_menu_item r "NIC ring buffers" "inspect / tune ethtool -G"
    ui_menu_item i "IPv6 control" "disable/enable the IPv6 stack"
    ui_menu_item 6 "Docker + UFW audit" "check the firewall bypass"
    ui_menu_group "System"
    ui_menu_item k "XanMod / BBRv3 check" "verify CPU, /boot, virtualization"
    ui_menu_item c "Safe disk cleaner" "docker logs · journald · apt cache"
    ui_menu_item 7 "Support report" "full plain-text dump"
    ui_menu_item d "Panels, nodes & Docker" "install Pasarguard node / x-ui · backup · limits"
    ui_menu_item s "Settings" "install 'st' · update · paths"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        tools_ping_matrix
        ui_pause
        ;;
      2)
        dns_latency_test
        ui_pause
        ;;
      3)
        tools_tcp_status
        ui_pause
        ;;
      4)
        tools_listening_ports
        ui_pause
        ;;
      v | V)
        tools_sni_check || true
        ui_pause
        ;;
      x | X)
        tools_iperf3 || true
        ui_pause
        ;;
      r | R)
        tools_nic_ring || true
        ui_pause
        ;;
      k | K)
        tools_xanmod_check || true
        ui_pause
        ;;
      c | C)
        tools_disk_cleaner || true
        ui_pause
        ;;
      5)
        vpn_mss_clamp
        ui_pause
        ;;
      n | N)
        vpn_conntrack_bypass
        ui_pause
        ;;
      p | P)
        priority_menu
        ui_pause
        ;;
      i | I)
        ipv6_control
        ui_pause
        ;;
      6)
        vpn_docker_ufw_audit
        ui_pause
        ;;
      7)
        tools_report
        ui_pause
        ;;
      9)
        tools_speedtest || true # outcome already reported
        ui_pause
        ;;
      b | B)
        tools_benchmark
        ui_pause
        ;;
      w | W) tools_watch || true ;;
      d | D) node_menu ;;
      s | S) menu_settings ;;
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
