# shellcheck shell=bash
# ============================================================================
# modules/isp_lists.sh — the Iran ISP address lists: seeding the on-disk cache
# from the lists embedded in the script, refreshing them from this repository
# (checksum-verified) and reading them back. Part of the ISP blocker; see
# isp.sh for the overview and isp_fw.sh for what is done with the lists.
# ============================================================================

# _isp_ranges FAMILY — every range of the blocked ISPs, one per line, unique.
_isp_ranges() {
  local fam="$1" id ext=ipv4
  if [[ $fam == 6 ]]; then
    ext=ipv6
  fi
  {
    while IFS= read -r id; do
      if [[ -s ${ST_ISP_DIR}/${id}.${ext} ]]; then
        cat "${ST_ISP_DIR}/${id}.${ext}"
      fi
    done < <(_isp_blocked_ids)
  } | sort -u
}

# --- Address lists: embedded in the script, refreshable from this repo -------

# _isp_prepare_lists — make sure every list is on disk. A new ServerTools
# version re-seeds the cache from its embedded data (newer than any older
# download); `isp update` can then refresh it again.
_isp_prepare_lists() {
  local id stamp="${ST_ISP_DIR}/.seeded-by"
  mkdir -p "$ST_ISP_DIR"
  local reseed=0
  if [[ ! -f $stamp || "$(<"$stamp")" != "$ST_VERSION" ]]; then
    reseed=1
  fi
  for id in "${ST_ISP_IDS[@]}"; do
    if ((reseed)) || [[ ! -s ${ST_ISP_DIR}/${id}.ipv4 ]]; then
      _isp_embedded "$id" >"${ST_ISP_DIR}/${id}.ipv4"
    fi
    # IPv6 exists only for some ISPs; a new version replaces what was cached.
    if ((reseed)) || [[ ! -f ${ST_ISP_DIR}/${id}.ipv6 ]]; then
      _isp_embedded6 "$id" >"${ST_ISP_DIR}/${id}.ipv6"
      if [[ ! -s ${ST_ISP_DIR}/${id}.ipv6 ]]; then
        rm -f "${ST_ISP_DIR}/${id}.ipv6"
      fi
    fi
  done
  printf '%s\n' "$ST_VERSION" >"$stamp"
}

# isp_update_lists — refresh the cached lists from this project's repository.
# Every line is validated; a failed or empty download keeps what is there.
isp_update_lists() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked isp_update_lists
    return
  fi
  has_cmd curl || {
    log_error "curl is required to update the lists."
    return 1
  }
  _isp_prepare_lists
  # The lists come with a SHA256SUMS file (written by the sync workflow). A list
  # that does not match it — a truncated download, a stale cache — is not used.
  ST_ISP_SUMS="$(curl -fsSL --max-time 30 "${ST_ISP_URL}/SHA256SUMS" 2>>"$ST_LOG_FILE")" || ST_ISP_SUMS=''
  if [[ -z $ST_ISP_SUMS ]] || ! has_cmd sha256sum; then
    if ((ST_ALLOW_UNVERIFIED != 1)); then
      log_error "The list checksums (SHA256SUMS) are unavailable — the current lists were kept. Retry later, or pass --allow-unverified."
      return 3
    fi
    log_warn "Updating the lists WITHOUT checksum verification (--allow-unverified)."
  fi
  local id tmp line n ok=0 failed=0 total=0 total6=0
  for id in "${ST_ISP_IDS[@]}"; do
    if _isp_fetch_list6 "$id"; then
      total6=$((total6 + $(wc -l <"${ST_ISP_DIR}/${id}.ipv6" | tr -d '[:space:]')))
    fi
    tmp="${ST_ISP_DIR}/${id}.ipv4.new"
    if curl -fsSL --max-time 30 "${ST_ISP_URL}/${id}.ipv4" -o "$tmp" 2>>"$ST_LOG_FILE" && _isp_sum_ok "$tmp" "${id}.ipv4"; then
      : >"${tmp}.clean"
      while IFS= read -r line; do
        line="${line//[$'\r ']/}"
        if [[ -n $line && $line != *:* ]] && _isp_valid_cidr "$line"; then
          printf '%s\n' "$line" >>"${tmp}.clean"
        fi
      done <"$tmp"
      rm -f "$tmp"
      if [[ -s ${tmp}.clean ]]; then
        mv -f "${tmp}.clean" "${ST_ISP_DIR}/${id}.ipv4"
        ok=$((ok + 1))
        n="$(wc -l <"${ST_ISP_DIR}/${id}.ipv4" | tr -d '[:space:]')"
        total=$((total + n))
        continue
      fi
      rm -f "${tmp}.clean"
    fi
    rm -f "$tmp"
    failed=$((failed + 1))
    log_warn "Could not refresh the $(_isp_label "$id") list — keeping the current one."
  done
  printf 'Lists refreshed: %d of %d (%d IPv4 + %d IPv6 ranges).\n' "$ok" "${#ST_ISP_IDS[@]}" "$total" "$total6"
  ((failed == 0)) || return 3
}

# _isp_sum_ok FILE NAME — FILE matches the published checksum of NAME. A name
# missing from SHA256SUMS passes only with --allow-unverified.
_isp_sum_ok() {
  local want got
  want="$(awk -v n="$2" '{f = $2; sub(/^[*]/, "", f)} f == n {print $1; exit}' <<<"$ST_ISP_SUMS")"
  if [[ -z $want ]]; then
    ((ST_ALLOW_UNVERIFIED == 1))
    return
  fi
  got="$(sha256sum "$1" | awk '{print $1}')"
  if [[ $want != "$got" ]]; then
    log_warn "Checksum mismatch for $2 — not used."
    return 1
  fi
}

# _isp_fetch_list6 ID — refresh one ISP's IPv6 list. Succeeds when the ISP has
# IPv6 data afterwards (downloaded or already cached). A failed download keeps
# the cached copy and is not an error: most ISPs have no IPv6 list at all.
_isp_fetch_list6() {
  local id="$1" tmp line
  tmp="${ST_ISP_DIR}/${id}.ipv6.new"
  if curl -fsSL --max-time 30 "${ST_ISP_URL}/${id}.ipv6" -o "$tmp" 2>>"$ST_LOG_FILE" && _isp_sum_ok "$tmp" "${id}.ipv6"; then
    : >"${tmp}.clean"
    while IFS= read -r line; do
      line="${line//[$'\r ']/}"
      if [[ $line == *:* ]] && _isp_valid_cidr "$line"; then
        printf '%s\n' "${line,,}" >>"${tmp}.clean"
      fi
    done <"$tmp"
    if [[ -s ${tmp}.clean ]]; then
      mv -f "${tmp}.clean" "${ST_ISP_DIR}/${id}.ipv6"
    fi
    rm -f "${tmp}.clean"
  fi
  rm -f "$tmp"
  [[ -s ${ST_ISP_DIR}/${id}.ipv6 ]]
}

# _isp_count ID — number of ranges (IPv4 + IPv6) of one ISP.
_isp_count() {
  local f4="${ST_ISP_DIR}/${1}.ipv4" f6="${ST_ISP_DIR}/${1}.ipv6" n4 n6
  if [[ -s $f4 ]]; then
    n4="$(wc -l <"$f4" | tr -d '[:space:]')"
  else
    n4="$(_isp_embedded "$1" | wc -l | tr -d '[:space:]')"
  fi
  if [[ -s $f6 ]]; then
    n6="$(wc -l <"$f6" | tr -d '[:space:]')"
  else
    n6="$(_isp_embedded6 "$1" | wc -l | tr -d '[:space:]')"
  fi
  printf '%s' "$((n4 + n6))"
}
