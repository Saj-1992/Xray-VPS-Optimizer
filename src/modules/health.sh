# shellcheck shell=bash
# ============================================================================
# modules/health.sh — one-glance server health score and the one-key "go"
# flow. Reuses the Doctor verify functions (0 ok · 2 not configured · else
# drift) but runs them silently and condenses them into a 0-100 score.
# ============================================================================

# Registry: "label|verify function" — every row counts toward the score.
readonly -a ST_HEALTH_CORE=(
  'Kernel tuning|sysctl_verify'
  'Network data path|perf_verify'
  'File limits|limits_verify'
  'DNS|dns_verify'
)

ST_HEALTH_SCORE=0
ST_HEALTH_LIGHTS=() # "label|ok|warn|idle"

# _health_light LABEL STATE — record one row; STATE: ok | warn | idle.
_health_light() {
  ST_HEALTH_LIGHTS+=("$1|$2")
}

# health_collect — run every check quietly, fill the lights and the score,
# and cache the score so the dashboard can show it without re-running them.
health_collect() {
  ST_HEALTH_LIGHTS=()
  local entry label fn rc total=0 good=0
  for entry in "${ST_HEALTH_CORE[@]}"; do
    IFS='|' read -r label fn <<<"$entry"
    declare -F "$fn" >/dev/null 2>&1 || continue
    rc=0
    "$fn" >/dev/null 2>&1 || rc=$?
    total=$((total + 1))
    case "$rc" in
      0)
        good=$((good + 1))
        _health_light "$label" ok
        ;;
      2) _health_light "$label" idle ;;
      *) _health_light "$label" warn ;;
    esac
  done

  # Firewall: optional by design, so a missing one is "idle", never an error,
  # but it still weighs on the score because an open server is not healthy.
  total=$((total + 1))
  if has_cmd ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    good=$((good + 1))
    _health_light "Firewall (UFW)" ok
  else
    _health_light "Firewall (UFW)" idle
  fi

  ST_HEALTH_SCORE=$((total > 0 ? good * 100 / total : 0))
  config_set last_score "$ST_HEALTH_SCORE"
  return 0
}

# health_bar SCORE — a 10-cell bar colored by how healthy the score is.
health_bar() {
  local score="$1" filled color i bar=''
  filled=$((score / 10))
  if ((score >= 80)); then
    color="$C_OK"
  elif ((score >= 50)); then
    color="$C_WARN"
  else
    color="$C_ERR"
  fi
  for ((i = 0; i < 10; i++)); do
    if ((i < filled)); then bar+='█'; else bar+='░'; fi
  done
  printf '%s%s%s %s%d%%%s' "$color" "$bar" "$C_RESET" "$color" "$score" "$C_RESET"
}

# usage_bar PCT — like health_bar, but a FULL bar is the bad direction.
usage_bar() {
  local pct="$1" filled color i bar=''
  filled=$((pct / 10))
  color="$(_usage_color "$pct")"
  for ((i = 0; i < 10; i++)); do
    if ((i < filled)); then bar+='█'; else bar+='░'; fi
  done
  printf '%s%s%s %s%d%%%s' "$color" "$bar" "$C_RESET" "$color" "$pct" "$C_RESET"
}

# health_show — score bar plus one traffic light per check.
health_show() {
  local entry label state
  printf '  %sHealth%s  %s\n\n' "$C_KEY" "$C_RESET" "$(health_bar "$ST_HEALTH_SCORE")"
  for entry in "${ST_HEALTH_LIGHTS[@]}"; do
    IFS='|' read -r label state <<<"$entry"
    case "$state" in
      ok) printf '  %s  %s\n' "$(ui_badge ok)" "$label" ;;
      warn) printf '  %s  %s %s— drifted, needs a fix%s\n' "$(ui_badge warn)" "$label" "$C_WARN" "$C_RESET" ;;
      *) printf '  %s  %s %s— not set up yet%s\n' "$(ui_badge idle)" "$label" "$C_MUTED" "$C_RESET" ;;
    esac
  done
}

# go_optimize — the one-command flow behind `st go`: detect, optimize with
# safe defaults, ask nothing, then show the resulting health.
go_optimize() {
  auto_optimize
  health_collect
  ui_hr
  health_show
  printf '\n%sDone.%s Re-check anytime with: st --verify\n' "$C_OK" "$C_RESET"
}

# menu_health — Status & Health screen: score first, details on request.
menu_health() {
  local choice
  while true; do
    ui_logo
    ui_title "Status & Health"
    detect_stack
    health_collect
    health_show
    headroom_show
    ui_hr
    if ((ST_HEALTH_SCORE < 100)); then
      ui_menu_item 1 "Fix everything" "one-key optimize, no questions"
    fi
    ui_menu_item 2 "Full report" "all system details"
    ui_menu_item 3 "Detailed check" "Doctor — what exactly drifted"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        if ((ST_HEALTH_SCORE < 100)); then
          ST_OPT_BATCH=1
          go_optimize || true # per-step outcomes are already printed
          ST_OPT_BATCH=0
          ui_pause
        fi
        ;;
      2) show_status ;;
      3)
        doctor_run || true # drift is reported on screen, not an error here
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

# --- Remaining capacity ------------------------------------------------------
# Everything below reads /proc only, so it is instant and safe on the dashboard.

# _usage_color PCT — green below 70, amber below 90, red above.
_usage_color() {
  if (($1 >= 90)); then
    printf '%s' "$C_ERR"
  elif (($1 >= 70)); then
    printf '%s' "$C_WARN"
  else
    printf '%s' "$C_OK"
  fi
}

# Filled by headroom_collect; -1 means "not available on this host".
ST_HR_CT_PCT=-1
ST_HR_CT_FREE=0
ST_HR_RAM_PCT=-1
ST_HR_RAM_AVAIL_MB=0
ST_HR_LOAD='0.00'
ST_HR_LOAD_PCT=-1
ST_HR_FD_PCT=-1
ST_HR_ROOM_USERS=-1

headroom_collect() {
  ST_HR_CT_PCT=-1
  ST_HR_RAM_PCT=-1
  ST_HR_LOAD_PCT=-1
  ST_HR_FD_PCT=-1
  ST_HR_ROOM_USERS=-1

  local count max total avail cores fd_used fd_max load1
  count="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)" || count=''
  max="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)" || max=''
  if [[ $count =~ ^[0-9]+$ && $max =~ ^[0-9]+$ ]] && ((max > 0)); then
    ST_HR_CT_PCT=$((count * 100 / max))
    ST_HR_CT_FREE=$((max - count))
  fi

  total="$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null)" || total=''
  avail="$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null)" || avail=''
  if [[ $total =~ ^[0-9]+$ && $avail =~ ^[0-9]+$ ]] && ((total > 0)); then
    ST_HR_RAM_PCT=$(((total - avail) * 100 / total))
    ST_HR_RAM_AVAIL_MB="$avail"
  fi

  load1="$(awk '{print $1}' /proc/loadavg 2>/dev/null)" || load1=''
  cores="$(cpu_cores)"
  if [[ $load1 =~ ^[0-9]+(\.[0-9]+)?$ && $cores =~ ^[0-9]+$ ]] && ((cores > 0)); then
    ST_HR_LOAD="$load1"
    ST_HR_LOAD_PCT="$(awk -v l="$load1" -v c="$cores" 'BEGIN {printf "%d", l * 100 / c}')"
  fi

  read -r fd_used _ fd_max </proc/sys/fs/file-nr 2>/dev/null || fd_used=''
  if [[ ${fd_used:-} =~ ^[0-9]+$ && ${fd_max:-} =~ ^[0-9]+$ ]] && ((fd_max > 0)); then
    ST_HR_FD_PCT=$((fd_used * 100 / fd_max))
  fi

  # Rough room for more users: each online user costs ~36 conntrack entries
  # (24 flows x 1.5 headroom, the same model as the capacity planner) and about
  # 0.8 MB of RAM in the proxy. The smaller of the two limits is the answer.
  local by_ct=-1 by_ram=-1
  if ((ST_HR_CT_PCT >= 0)); then
    by_ct=$((ST_HR_CT_FREE / 36))
  fi
  if ((ST_HR_RAM_PCT >= 0)); then
    by_ram=$((ST_HR_RAM_AVAIL_MB * 10 / 8))
  fi
  if ((by_ct >= 0 && by_ram >= 0)); then
    ST_HR_ROOM_USERS=$((by_ct < by_ram ? by_ct : by_ram))
  elif ((by_ram >= 0)); then
    ST_HR_ROOM_USERS="$by_ram"
  fi
  return 0
}

# _hr_part LABEL PCT — "label 42%" colored by how full it is, or nothing.
_hr_part() {
  (($2 >= 0)) || return 0
  printf '%s %s%d%%%s' "$1" "$(_usage_color "$2")" "$2" "$C_RESET"
}

# headroom_line — the one-line dashboard summary.
headroom_line() {
  headroom_collect
  local parts=() p
  for p in "$(_hr_part conntrack "$ST_HR_CT_PCT")" "$(_hr_part RAM "$ST_HR_RAM_PCT")" \
    "$(_hr_part CPU "$ST_HR_LOAD_PCT")"; do
    [[ -n $p ]] && parts+=("$p")
  done
  local out='' sep=''
  for p in "${parts[@]}"; do
    out+="${sep}${p}"
    sep=" ${C_MUTED}·${C_RESET} "
  done
  if ((ST_HR_ROOM_USERS >= 0)); then
    out+=" ${C_MUTED}· room for ~${ST_HR_ROOM_USERS} more users${C_RESET}"
  fi
  printf '%s' "$out"
}

# headroom_show — the detailed block for the Status & Health screen.
headroom_show() {
  headroom_collect
  ui_section "Remaining capacity"
  local label pct
  for label in "Connections (conntrack)|${ST_HR_CT_PCT}" "Memory|${ST_HR_RAM_PCT}" \
    "CPU load (${ST_HR_LOAD})|${ST_HR_LOAD_PCT}" "Open files|${ST_HR_FD_PCT}"; do
    IFS='|' read -r label pct <<<"$label"
    ((pct >= 0)) || continue
    ((pct > 100)) && pct=100
    printf '  %-26s %s\n' "$label" "$(usage_bar "$pct")"
  done
  if ((ST_HR_ROOM_USERS >= 0)); then
    printf '\n  %sRoom for roughly %d more users%s %s(rough: the smaller of the connection-table and RAM limits)%s\n' \
      "$C_KEY" "$ST_HR_ROOM_USERS" "$C_RESET" "$C_MUTED" "$C_RESET"
  fi
  if ((ST_HR_CT_PCT >= 70)); then
    printf '  %sConnection table is %d%% full — raise the tier/users or exempt proxy ports (Tools → NOTRACK).%s\n' \
      "$C_WARN" "$ST_HR_CT_PCT" "$C_RESET"
  fi
  if ((ST_HR_RAM_PCT >= 85)); then
    printf '  %sMemory is %d%% used — add RAM or move users to another node before the OOM killer acts.%s\n' \
      "$C_WARN" "$ST_HR_RAM_PCT" "$C_RESET"
  fi
}
