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
