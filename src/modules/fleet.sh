# shellcheck shell=bash
# ============================================================================
# modules/fleet.sh — carry the settings of one server to the next:
#
#   st --config-export [FILE]   write the portable settings (stdout without FILE)
#   st --config-import FILE     validate, then merge them into this server's config
#
# Import only changes the saved settings; nothing is applied until you run
# `st go` / `st --auto` (kernel tuning) or `st isp set ...` (ISP blocker). Every
# line is validated first — one bad line and nothing at all is imported.
# ============================================================================

# Settings that describe THIS host or a moment in time, never carried over.
readonly -a ST_CONFIG_TRANSIENT=(update_check_ts update_latest last_score isp_mode)

# Settings an import is allowed to set.
readonly -a ST_CONFIG_PORTABLE=(
  dns_primary dns_secondary expected_users last_profile last_tier mss_value qdisc
  isp_ids isp_ports isp_proto isp_wl isp_wports
)

# _config_is_transient KEY
_config_is_transient() {
  local t
  for t in "${ST_CONFIG_TRANSIENT[@]}"; do
    if [[ $1 == "$t" ]]; then
      return 0
    fi
  done
  return 1
}

# config_export [FILE]
config_export() {
  local file="${1:-}" key out
  out="$(
    for key in "${!ST_CONFIG[@]}"; do
      if _config_is_transient "$key"; then
        continue
      fi
      printf '%s=%s\n' "$key" "${ST_CONFIG[$key]}"
    done | sort
  )"
  if [[ -z $file ]]; then
    printf '%s\n' "$out"
    return 0
  fi
  {
    printf '# %s settings exported %s — import with: st --config-import FILE\n' "$ST_NAME" "$(date '+%F %T')"
    [[ -z $out ]] || printf '%s\n' "$out"
  } >"$file"
  printf 'Exported %d setting(s) to %s\n' "$(awk '/=/ {n++} END {print n + 0}' "$file")" "$file"
}

# _config_value_ok KEY VALUE — is VALUE acceptable for KEY?
_config_value_ok() {
  local key="$1" value="$2" id item
  [[ $value != *[[:cntrl:]]* ]] || return 1
  case "$key" in
    expected_users | mss_value) [[ -z $value || $value =~ ^[0-9]+$ ]] ;;
    qdisc) [[ -z $value || $value == fq || $value == fq_codel || $value == cake ]] ;;
    dns_primary | dns_secondary) [[ -z $value ]] || is_valid_ipv4 "$value" || is_valid_ipv6 "$value" ;;
    last_profile) [[ $value =~ ^[a-z-]*$ ]] ;;
    last_tier) [[ $value =~ ^[A-Za-z-]*$ ]] ;;
    isp_proto) [[ -z $value || $value == both || $value == tcp || $value == udp ]] ;;
    isp_ids)
      while IFS= read -r item; do
        [[ -n $item ]] || continue
        for id in "${ST_ISP_IDS[@]}"; do
          [[ $item == "$id" ]] && continue 2
        done
        return 1
      done < <(ports_split "$value")
      ;;
    isp_ports) [[ -z $value || $value == all ]] || _isp_csv_valid port "$value" ;;
    isp_wports) [[ -z $value ]] || _isp_csv_valid port "$value" ;;
    isp_wl) [[ -z $value ]] || _isp_csv_valid cidr "$value" ;;
    *) return 1 ;;
  esac
}

# config_import FILE
config_import() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked config_import "$@"
    return
  fi
  local file="${1:-}" line key value k known n=0 lineno=0
  [[ -n $file && -r $file ]] || die "Usage: st --config-import FILE   (a file written by --config-export)"
  local -a keys=() values=()
  while IFS= read -r line || [[ -n $line ]]; do
    lineno=$((lineno + 1))
    line="${line%$'\r'}"
    if [[ -z $line || $line == \#* ]]; then
      continue
    fi
    [[ $line == *=* ]] || die "${file}:${lineno}: not a key=value line — nothing was imported."
    key="${line%%=*}"
    value="${line#*=}"
    [[ $key =~ ^[a-z][a-z0-9_]*$ ]] || die "${file}:${lineno}: invalid setting name '${key}' — nothing was imported."
    if _config_is_transient "$key"; then
      continue
    fi
    known=0
    for k in "${ST_CONFIG_PORTABLE[@]}"; do
      if [[ $key == "$k" ]]; then
        known=1
      fi
    done
    if ((known == 0)); then
      log_warn "${file}:${lineno}: '${key}' is not a portable setting — skipped."
      continue
    fi
    _config_value_ok "$key" "$value" || die "${file}:${lineno}: '${value}' is not a valid value for ${key} — nothing was imported."
    keys+=("$key")
    values+=("$value")
  done <"$file"

  for ((n = 0; n < ${#keys[@]}; n++)); do
    ST_CONFIG[${keys[$n]}]="${values[$n]}"
  done
  if ((${#keys[@]} > 0)); then
    config_save
  fi
  printf '%sImported %d setting(s).%s Nothing is applied yet:\n' "$C_OK" "${#keys[@]}" "$C_RESET"
  printf '  kernel tuning:  st go            (or st --auto)\n'
  printf '  ISP blocker:    st isp set <ids> (see: st isp status)\n'
  log_info "Imported ${#keys[@]} setting(s) from ${file}."
}
