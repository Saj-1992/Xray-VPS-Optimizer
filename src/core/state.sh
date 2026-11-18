# shellcheck shell=bash
# ============================================================================
# core/state.sh — persistent user config (key=value) and the change manifest.
#
# The manifest is the source of truth for rollback: every file the tool
# creates or modifies gets one TSV row (see docs/ROLLBACK.md).
# ============================================================================

declare -A ST_CONFIG=()

state_init() {
  mkdir -p "$ST_ETC_DIR" "$ST_LIB_DIR" "$ST_BACKUP_DIR"
  if [[ ! -f $ST_MANIFEST_FILE ]]; then
    printf '# timestamp\trun_id\taction\ttarget\n' >"$ST_MANIFEST_FILE"
  fi
}

config_load() {
  ST_CONFIG=()
  [[ -f $ST_CONFIG_FILE ]] || return 0
  local key value
  while IFS='=' read -r key value; do
    [[ -z $key || $key == \#* ]] && continue
    ST_CONFIG[$key]="$value"
  done <"$ST_CONFIG_FILE"
}

config_get() { # config_get KEY [DEFAULT]
  printf '%s' "${ST_CONFIG[$1]:-${2:-}}"
}

config_set() { # config_set KEY VALUE — updates memory and persists.
  ST_CONFIG[$1]="$2"
  config_save
}

config_save() {
  mkdir -p "$ST_ETC_DIR"
  local tmp="${ST_CONFIG_FILE}.tmp.$$" key
  {
    printf '# %s configuration — generated; editing by hand is fine.\n' "$ST_NAME"
    for key in "${!ST_CONFIG[@]}"; do
      printf '%s=%s\n' "$key" "${ST_CONFIG[$key]}"
    done | sort
  } >"$tmp"
  mv -f "$tmp" "$ST_CONFIG_FILE"
}

# manifest_add ACTION TARGET — ACTION is "created", "modified", "unit" or, once
# a run has been rolled back, "reverted" (TARGET = the run id that was undone).
manifest_add() {
  printf '%s\t%s\t%s\t%s\n' "$(date '+%F %T')" "$ST_RUN_ID" "$1" "$2" >>"$ST_MANIFEST_FILE"
}

manifest_entry_count() {
  [[ -f $ST_MANIFEST_FILE ]] || {
    printf '0'
    return 0
  }
  awk -F'\t' 'NR > 1 && $3 != "reverted"' "$ST_MANIFEST_FILE" | wc -l | tr -d '[:space:]'
}

# manifest_latest_run — most recent run id that recorded changes and has not
# been rolled back yet (empty if none). A rollback leaves a "reverted" row, so a
# second --rollback goes on to the run before instead of repeating the same one.
manifest_latest_run() {
  local file="${1:-$ST_MANIFEST_FILE}"
  [[ -f $file ]] || return 0
  awk -F'\t' '
    NR > 1 {
      if ($3 == "reverted") rev[$4] = 1
      else seen[$2] = 1
    }
    END {
      best = ""
      for (r in seen) if (!(r in rev) && (r "") > (best "")) best = r
      if (best != "") print best
    }' "$file"
}

# --- Exclusive lock ---------------------------------------------------------
# Two `st` runs writing config, manifest or the ISP sets at the same moment
# would corrupt each other. Functions that change the system take this lock for
# the duration of the change (not for a whole menu session, so a boot unit never
# waits behind someone who left the menu open). It is re-entrant, and child
# processes started by us inherit ST_LOCKED and do not lock again.

readonly ST_LOCK_FILE='/run/lock/server-tools.lock'

# st_locked FUNCTION [ARGS...] — run FUNCTION holding the lock; waits up to 120 s.
# Without flock (or when the lock file cannot be opened) FUNCTION still runs,
# unlocked, with ST_LOCKED set so the guard in FUNCTION does not call us again.
st_locked() {
  local fd='' rc
  if [[ ${ST_LOCKED:-0} == 1 ]]; then
    "$@"
    return
  fi
  if has_cmd flock; then
    # Best effort: /run/lock exists on any systemd host; the open below reports.
    mkdir -p "${ST_LOCK_FILE%/*}" 2>/dev/null || true
    if exec {fd}>>"$ST_LOCK_FILE"; then
      if ! flock -w 120 "$fd"; then
        exec {fd}>&-
        log_error "Another ServerTools run is busy (waited 120 s) — try again in a moment."
        return 1
      fi
      # Another run may have saved settings while we waited for the lock;
      # working from the copy loaded at start-up would silently overwrite them.
      config_load
    else
      log_warn "Cannot open ${ST_LOCK_FILE} — continuing without the lock."
      fd=''
    fi
  fi
  export ST_LOCKED=1
  # Deliberately not `"$@" || rc=$?`: that would switch error handling off for
  # the whole function. If an unhandled failure ends the process here, the
  # lock is released with it.
  "$@"
  rc=$?
  export ST_LOCKED=0
  if [[ -n $fd ]]; then
    flock -u "$fd"
    exec {fd}>&-
  fi
  return "$rc"
}
