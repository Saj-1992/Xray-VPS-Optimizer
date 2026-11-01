# shellcheck shell=bash
# ============================================================================
# modules/persist.sh — what ServerTools sets must (1) still be there after a
# reboot, and (2) be undoable at any moment, including the live state.
#
# Persistence: every setting is a file (sysctl.d, limits.d, drop-ins, ...) or a
# oneshot systemd unit that re-applies it at boot and exits. persist_verify
# checks that each of those is really in place and enabled; persist_repair
# puts back what is missing (`st repair`).
#
# Undo: file rollback (backup.sh) restores or removes the files. Live state is
# not a file — firewall rules, ipsets, process priorities, loaded sysctl values
# — so the rollbacks also call runtime_revert_prepass / runtime_restore_original
# here, and nothing is left running that the files no longer describe.
# ============================================================================

readonly ST_RUNTIME_ORIGINAL="${ST_LIB_DIR}/original-runtime.tsv"
readonly -a ST_PERSIST_UNITS=(
  server-tools-perf server-tools-zram server-tools-dns
  server-tools-mss server-tools-notrack server-tools-boost server-tools-isp
)

# persist_ensure_st — units call back into `st`, so it must be installed. It is
# the tool itself, not a system change (and is deliberately not tracked, so a
# rollback never removes the command that performs it).
persist_ensure_st() {
  [[ -x $ST_INSTALL_PATH ]] && return 0
  printf 'Installing the "st" command so the boot unit can find it...\n'
  st_self_install
}

# _persist_problems — one line per problem; empty when everything survives a reboot.
_persist_problems() {
  has_cmd systemctl || return 0
  local unit file
  for unit in "${ST_PERSIST_UNITS[@]}"; do
    file="/etc/systemd/system/${unit}.service"
    if [[ $unit == server-tools-isp ]]; then
      # Its unit exists exactly while something is blocked.
      if [[ -n "$(config_get isp_ids '')" ]]; then
        if [[ ! -f $file ]]; then
          printf '%s|missing\n' "$unit"
          continue
        fi
      else
        continue
      fi
    fi
    [[ -f $file ]] || continue
    if ! systemctl is-enabled --quiet "${unit}.service" 2>/dev/null; then
      printf '%s|disabled\n' "$unit"
    fi
  done
  if [[ -f $ST_PRIO_UNIT || -f $ST_ISP_UNIT ]] && [[ ! -x $ST_INSTALL_PATH ]]; then
    printf 'st|not installed (boot units call it)\n'
  fi
}

# persist_verify — Doctor contract: 0 every setting survives a reboot,
# 2 nothing of ours is persisted here, 3 something would not come back.
persist_verify() {
  has_cmd systemctl || return 2
  local problems any=0 unit
  problems="$(_persist_problems)"
  [[ -z $problems ]] || return 3
  for unit in "${ST_PERSIST_UNITS[@]}"; do
    [[ -f /etc/systemd/system/${unit}.service ]] && any=1
  done
  [[ -f $ST_SYSCTL_FILE ]] && any=1
  ((any)) || return 2
  return 0
}

# persist_repair — re-enable what is disabled, recreate what is missing.
persist_repair() {
  ui_section "Boot persistence"
  has_cmd systemctl || {
    printf 'No systemd here — nothing to repair.\n'
    return 0
  }
  local problems line unit what fixed=0 rc=0
  problems="$(_persist_problems)"
  if [[ -z $problems ]]; then
    printf '%sEverything ServerTools set will come back after a reboot.%s\n' "$C_OK" "$C_RESET"
    return 0
  fi
  while IFS='|' read -r unit what; do
    [[ -n $unit ]] || continue
    case "$unit" in
      st)
        persist_ensure_st && fixed=$((fixed + 1)) || rc=3
        ;;
      server-tools-isp)
        persist_ensure_st || rc=3
        if _isp_write_unit; then fixed=$((fixed + 1)); else rc=3; fi
        ;;
      *)
        if systemctl enable "${unit}.service" >/dev/null 2>>"$ST_LOG_FILE"; then
          printf '  %s  %s %s(was %s — enabled)%s\n' "$(ui_badge ok)" "$unit" "$C_MUTED" "$what" "$C_RESET"
          fixed=$((fixed + 1))
        else
          printf '  %s  %s could not be enabled — see the log\n' "$(ui_badge err)" "$unit"
          rc=3
        fi
        ;;
    esac
  done <<<"$problems"
  systemctl daemon-reload 2>>"$ST_LOG_FILE" || log_warn "daemon-reload failed."
  printf '%d item(s) repaired.\n' "$fixed"
  log_info "Persistence repaired: ${fixed} item(s), rc=${rc}."
  return "$rc"
}

# --- Original runtime state ---------------------------------------------------

# runtime_snapshot_save RENDERED — before the very first sysctl apply, remember
# the live value of every key we are about to set, and the root qdisc of the
# default interface. Only a host never tuned by ServerTools has an original to
# remember; once our file exists the live values are no longer the original.
runtime_snapshot_save() {
  local rendered="$1" line key iface kind
  [[ -f $ST_RUNTIME_ORIGINAL || -f $ST_SYSCTL_FILE ]] && return 0
  mkdir -p "$ST_LIB_DIR"
  {
    while IFS= read -r line; do
      [[ -z $line || $line == \#* ]] && continue
      key="${line%%=*}"
      key="${key//[[:space:]]/}"
      key="${key#-}"
      printf 'sysctl|%s|%s\n' "$key" "$(sysctl_get "$key" | tr -s '[:space:]' ' ' | sed 's/ $//')"
    done <<<"$rendered"
    iface="$(net_default_iface)" || iface=''
    if [[ -n $iface ]] && has_cmd tc; then
      kind="$(tc qdisc show dev "$iface" root 2>/dev/null | awk 'NR == 1 {print $2}')" || kind=''
      printf 'qdisc|%s|%s\n' "$iface" "$kind"
    fi
  } >"$ST_RUNTIME_ORIGINAL"
  log_info "Original runtime values saved to ${ST_RUNTIME_ORIGINAL}."
}

# runtime_restore_original — put the live kernel values back as they were
# before ServerTools first ran (for hosts that have a snapshot).
runtime_restore_original() {
  if [[ ! -f $ST_RUNTIME_ORIGINAL ]]; then
    printf '%sNo runtime snapshot (this host was tuned before snapshots existed): files are restored; loaded kernel values return fully after a reboot.%s\n' \
      "$C_MUTED" "$C_RESET"
    return 0
  fi
  local kind key value restored=0 failed=0
  while IFS='|' read -r kind key value; do
    case "$kind" in
      sysctl)
        [[ -n $value ]] || continue
        if sysctl -w "${key}=${value}" >/dev/null 2>>"$ST_LOG_FILE"; then
          restored=$((restored + 1))
        else
          failed=$((failed + 1))
        fi
        ;;
      qdisc)
        # Deleting the root qdisc makes the kernel attach its default again.
        if has_cmd tc && [[ -n $key ]]; then
          tc qdisc del dev "$key" root 2>>"$ST_LOG_FILE" ||
            log_warn "Could not reset the qdisc of ${key}."
        fi
        ;;
    esac
  done <"$ST_RUNTIME_ORIGINAL"
  printf '  %s  kernel values: %d put back as before%s\n' "$(ui_badge ok)" "$restored" \
    "$([[ $failed -gt 0 ]] && printf ' (%d read-only or unavailable)' "$failed")"
  rm -f "$ST_RUNTIME_ORIGINAL"
  log_info "Original runtime values restored (${restored} ok, ${failed} failed)."
}

# --- Live-state revert --------------------------------------------------------

# _notrack_remove_live — delete the raw-table NOTRACK rules the unit describes.
_notrack_remove_live() {
  local bin port spec target
  local -a rule=()
  has_cmd iptables || return 0
  for bin in iptables ip6tables; do
    has_cmd "$bin" || continue
    while IFS= read -r port; do
      [[ -n $port ]] || continue
      while IFS= read -r spec; do
        IFS=' ' read -ra rule <<<"$spec"
        for target in 'CT --notrack' 'NOTRACK'; do
          local -a tgt=()
          IFS=' ' read -ra tgt <<<"-j ${target}"
          if "$bin" -t raw -C "${rule[@]}" "${tgt[@]}" 2>/dev/null; then
            "$bin" -t raw -D "${rule[@]}" "${tgt[@]}" 2>>"$ST_LOG_FILE" ||
              log_warn "Could not remove a NOTRACK rule (${bin}): ${spec}"
          fi
        done
      done < <(_notrack_specs "$port")
    done < <(_notrack_unit_ports)
  done
}

# _prio_reset_pid PID — undo _prio_boost_pid (nice 0, default OOM score).
_prio_reset_pid() {
  local pid="$1" tid
  [[ -d /proc/$pid ]] || return 0
  for tid in "/proc/${pid}/task/"*; do
    # A thread may exit between listing and renice; that is not a failure.
    renice -n 0 -p "${tid##*/}" >/dev/null 2>&1 || continue
  done
  printf '0' >"/proc/${pid}/oom_score_adj" 2>>"$ST_LOG_FILE" ||
    log_warn "Could not reset oom_score_adj of PID ${pid}."
}

# priority_revert — running proxies back to default priority.
priority_revert() {
  priority_detect
  local svc entry engine name pid
  for svc in "${ST_PRIO_SVC_TARGETS[@]}"; do
    while IFS= read -r pid; do
      [[ -n $pid ]] && _prio_reset_pid "$pid"
    done < <(_prio_service_pids "$svc")
  done
  for entry in "${ST_PRIO_CTR_TARGETS[@]}"; do
    IFS=$'\t' read -r engine name <<<"$entry"
    while IFS= read -r pid; do
      [[ -n $pid ]] && _prio_reset_pid "$pid"
    done < <(_prio_container_pids "$engine" "$name")
    "$engine" update --cpu-shares 1024 "$name" >/dev/null 2>>"$ST_LOG_FILE" ||
      log_warn "Could not reset cpu-shares of ${name}."
  done
  return 0
}

# runtime_revert_prepass RUN|all — before the files are touched, undo the live
# effect of every feature the rollback is about to remove. Order matters: the
# NOTRACK ports are read from the unit file that the rollback then deletes.
runtime_revert_prepass() {
  local run="$1" entries
  entries="$(awk -F'\t' -v run="$run" 'NR > 1 && (run == "all" || $2 == run) {print $4}' "$ST_MANIFEST_FILE" 2>/dev/null)" || entries=''
  [[ -n $entries ]] || return 0

  if grep -q 'server-tools-isp.service' <<<"$entries" && has_cmd iptables; then
    _isp_teardown
    local key
    for key in isp_ids isp_ports isp_proto isp_wl isp_wports isp_mode; do
      config_set "$key" ''
    done
    printf '  %s  Iran ISP blocker: rules and sets removed%s\n' "$(ui_badge ok)" "$C_RESET"
  fi
  if grep -qE 'server-tools-mss.service|/etc/ufw/before.rules' <<<"$entries" && has_cmd iptables; then
    local tool
    for tool in iptables ip6tables; do
      has_cmd "$tool" && _mss_remove_live "$tool"
    done
    config_set mss_value ''
    printf '  %s  MSS clamp: live rules removed%s\n' "$(ui_badge ok)" "$C_RESET"
  fi
  if grep -q 'server-tools-notrack.service' <<<"$entries"; then
    _notrack_remove_live
    printf '  %s  NOTRACK: live rules removed%s\n' "$(ui_badge ok)" "$C_RESET"
  fi
  if grep -qE 'server-tools-boost.service|\.service\.d/99-server-tools\.conf' <<<"$entries"; then
    priority_revert
    printf '  %s  Proxy priority: processes back to default%s\n' "$(ui_badge ok)" "$C_RESET"
  fi
  return 0
}
