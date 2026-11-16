# shellcheck shell=bash
# ============================================================================
# modules/installer.sh — node helpers: back up node configuration and
# certificates (the part everyone forgets before an upgrade), and install a
# Pasarguard node or the x-ui panel with the projects' own installers.
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

# --- Official installers: Pasarguard node, x-ui panel -------------------------
#
# ServerTools does not re-implement these installers. It fetches the project's
# own script over HTTPS, checks that it is a complete shell script, shows where
# it came from, and runs it. The result is a normal installation of that
# project (and not something `st --rollback` can undo).

readonly ST_URL_PGNODE='https://raw.githubusercontent.com/PasarGuard/scripts/main/pg-node.sh'
readonly ST_URL_XUI='https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh'

# _app_normalize WORD — canonical app key (pg-node | xui), failing for others.
_app_normalize() {
  case "${1,,}" in
    pg-node | pgnode | pasarguard | pasarguard-node) printf 'pg-node' ;;
    xui | x-ui | alireza0) printf 'xui' ;;
    *) return 1 ;;
  esac
}

_app_label() {
  case "$1" in
    pg-node) printf 'Pasarguard node (pg-node)' ;;
    xui) printf 'x-ui panel (alireza0)' ;;
  esac
}

_app_installed() {
  case "$1" in
    pg-node) [[ -d /opt/pg-node || -x /usr/local/bin/pg-node ]] ;;
    xui) [[ -x /usr/local/x-ui/x-ui || -f /etc/systemd/system/x-ui.service ]] ;;
    *) return 1 ;;
  esac
}

# _app_state APP — one word for menus and status.
_app_state() {
  if ! _app_installed "$1"; then
    printf 'not installed'
    return 0
  fi
  case "$1" in
    xui)
      if has_cmd systemctl && systemctl is-active --quiet x-ui 2>/dev/null; then
        printf 'installed, running'
      else
        printf 'installed'
      fi
      ;;
    pg-node)
      if has_cmd docker && docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'pg-node\|pasarguard'; then
        printf 'installed, running'
      else
        printf 'installed'
      fi
      ;;
  esac
}

# _app_manager_hint APP — the command the project itself gives for upkeep.
_app_manager_hint() {
  case "$1" in
    pg-node) printf 'pg-node update | pg-node restart | pg-node logs | pg-node uninstall' ;;
    xui) printf 'x-ui   (menu: update, restart, settings, uninstall)' ;;
  esac
}

app_status() {
  local app
  ui_section "Panels and nodes"
  for app in pg-node xui; do
    ui_kv "$(_app_label "$app")" "$(_app_state "$app")"
  done
}

# app_install APP — fetch, verify, show, run the official installer.
app_install() {
  local app url args=() tmp script rc=0 size sum
  app="$(_app_normalize "${1:-}")" || die "Unknown app '${1:-}'. Use: pg-node | xui"
  case "$app" in
    pg-node)
      url="$ST_URL_PGNODE"
      args=(install)
      ;;
    xui) url="$ST_URL_XUI" ;;
  esac

  ui_section "Install $(_app_label "$app")"
  if _app_installed "$app"; then
    printf '%sAlready installed (%s).%s\n' "$C_OK" "$(_app_state "$app")" "$C_RESET"
    printf 'Upkeep uses the project'"'"'s own command: %s\n' "$(_app_manager_hint "$app")"
    return 0
  fi
  if ! has_cmd curl; then
    pkg_install curl || {
      log_error "curl is required to download the installer."
      return 1
    }
  fi

  tmp="$(mktemp -d)"
  script="${tmp}/installer.sh"
  if ! curl -fsSL --max-time 90 "$url" -o "$script" 2>>"$ST_LOG_FILE" || [[ ! -s $script ]]; then
    rm -rf "$tmp"
    log_error "Could not download the installer from ${url}."
    return 1
  fi
  if [[ "$(head -c 2 "$script")" != '#!' ]] || ! bash -n "$script" 2>>"$ST_LOG_FILE"; then
    rm -rf "$tmp"
    log_error "The downloaded file is not a complete shell script — nothing was run."
    return 1
  fi
  size="$(wc -c <"$script" | tr -d '[:space:]')"
  sum="$(sha256sum "$script" 2>/dev/null | cut -c1-16)"
  ui_kv "Source" "$url"
  ui_kv "Size" "${size} bytes   sha256 ${sum}…"
  printf '%sThe project'"'"'s own installer runs as root and may install Docker and packages.%s\n' "$C_MUTED" "$C_RESET"
  if ((ST_OPT_BATCH == 0)); then
    ui_confirm "Run it now?" || {
      rm -rf "$tmp"
      return 0
    }
  fi

  log_info "Running the official installer for ${app} (${url}, sha256 ${sum})."
  bash "$script" "${args[@]}" || rc=$?
  rm -rf "$tmp"
  if ((rc != 0)); then
    log_error "The installer exited with code ${rc}."
    return 1
  fi
  printf '\n%s%s is installed.%s\n' "$C_OK" "$(_app_label "$app")" "$C_RESET"
  printf 'Upkeep: %s\n' "$(_app_manager_hint "$app")"
  printf 'Next: run %sst go%s to tune the server for it.\n' "$C_KEY" "$C_RESET"
  return 0
}

# app_cli SUB — `st setup pg-node | xui | status`.
app_cli() {
  case "${1:-status}" in
    status) app_status ;;
    *) app_install "$1" ;;
  esac
}

node_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Panels, nodes & Docker"
    ui_kv "Detected" "$(detect_summary)"
    ui_kv "Pasarguard node" "$(_app_state pg-node)"
    ui_kv "x-ui panel" "$(_app_state xui)"
    ui_menu_item 1 "Back up node config" "archive certificates and settings"
    ui_menu_item 2 "Docker file limits" "raise nofile for all containers"
    ui_menu_item 3 "Install Pasarguard node" "official installer (pg-node)"
    ui_menu_item 4 "Install x-ui panel" "alireza0/x-ui, official installer"
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
      3)
        app_install pg-node || true
        ui_pause
        ;;
      4)
        app_install xui || true
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
