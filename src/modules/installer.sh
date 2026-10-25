# shellcheck shell=bash
# ============================================================================
# modules/installer.sh — node helpers: back up node configuration and
# certificates (the part everyone forgets before an upgrade).
# ============================================================================

readonly ST_NODE_BACKUP_DIR="${ST_LIB_DIR}/backups/nodes"

# Format: label|paths (space separated)
readonly -a ST_NODE_TARGETS=(
  'Marzban node|/opt/marzban-node /var/lib/marzban-node'
  'Pasarguard node (pg-node)|/opt/pg-node /var/lib/pg-node /opt/pasarguard'
  '3x-ui panel|/etc/x-ui /usr/local/x-ui'
  'WireGuard + WGDashboard|/etc/wireguard'
)

# node_backup — archive whatever node configuration exists on this host.
node_backup() {
  ui_section "Back up node configuration"
  local entry _label paths found=() path
  for entry in "${ST_NODE_TARGETS[@]}"; do
    IFS="|" read -r _label paths <<<"$entry"
    for path in $paths; do
      [[ -e $path ]] && found+=("$path")
    done
  done

  if ((${#found[@]} == 0)); then
    printf 'No known node configuration found on this server.\n'
    return 2
  fi

  printf 'Found:\n'
  printf '  %s\n' "${found[@]}"
  if ! has_cmd tar; then
    log_error "tar is not available — cannot create the archive."
    return 1
  fi

  mkdir -p "$ST_NODE_BACKUP_DIR"
  local archive="${ST_NODE_BACKUP_DIR}/node-config-${ST_RUN_ID}.tar.gz"
  if ! tar -czf "$archive" "${found[@]}" 2>>"$ST_LOG_FILE"; then
    log_error "Creating ${archive} failed — see the log."
    return 1
  fi
  chmod 600 "$archive"
  printf '%sSaved:%s %s (%s)\n' "$C_OK" "$C_RESET" "$archive" \
    "$(du -h "$archive" 2>/dev/null | awk '{print $1}')"
  printf '%sIt contains certificates and keys — keep it private.%s\n' "$C_WARN" "$C_RESET"
  log_info "Node configuration archived to ${archive}."
  return 0
}

node_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Node & Docker helpers"
    ui_kv "Detected" "$(detect_summary)"
    ui_menu_item 1 "Back up node config" "archive certificates and settings"
    ui_menu_item 2 "Docker file limits" "raise nofile for all containers"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        node_backup || true # outcome already reported
        ui_pause
        ;;
      2)
        limits_docker_ulimits || true
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
