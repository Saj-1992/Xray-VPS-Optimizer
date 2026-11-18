#!/usr/bin/env bash
# ============================================================================
# tools/merge-isp.sh — builds data/isp/<id>.ipv4 and <id>.ipv6 (what the script
# embeds) from
#   data/isp/upstream/<id>.ipv4   the Kiya6955/IR-ISP-Blocker list (IPv4 only)
#   data/isp/asn/<id>.ipv4|6      prefixes announced by the ISP's AS (asn.map)
#   data/isp/extra/<id>.ipv4|6    ranges added by hand / from the RIR database;
#                                 never touched by the sync
# Union, validated, sorted, de-duplicated. An IPv6 file is written only for an
# ISP that has IPv6 data.
# ============================================================================
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${ROOT_DIR}/data/isp"

for up in "${DATA}"/upstream/*.ipv4; do
  id="$(basename "$up" .ipv4)"
  {
    cat "$up"
    if [[ -f ${DATA}/asn/${id}.ipv4 ]]; then
      cat "${DATA}/asn/${id}.ipv4"
    fi
    if [[ -f ${DATA}/extra/${id}.ipv4 ]]; then
      cat "${DATA}/extra/${id}.ipv4"
    fi
  } | tr -d '\r' |
    awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[12][0-9]|3[0-2]))?$/' |
    sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | uniq >"${DATA}/${id}.ipv4"

  # IPv6 — lower-case, must contain a colon and a /0-128 prefix length.
  v6="$(
    {
      for dir in asn extra; do
        if [[ -f ${DATA}/${dir}/${id}.ipv6 ]]; then
          cat "${DATA}/${dir}/${id}.ipv6"
        fi
      done
    } | tr -d '\r' | tr 'A-F' 'a-f' |
      awk '/^[0-9a-f:]+:[0-9a-f:]*\/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$/' | sort -u
  )"
  if [[ -n $v6 ]]; then
    printf '%s\n' "$v6" >"${DATA}/${id}.ipv6"
  else
    rm -f "${DATA}/${id}.ipv6"
  fi
done
# Integrity file for `st isp update` (sha256, name) — covers every merged list.
(
  cd "$DATA"
  for f in *.ipv4 *.ipv6; do
    if [[ -f $f ]]; then
      sha256sum "$f"
    fi
  done
) | sed 's/ [*]/  /' >"${DATA}/SHA256SUMS"
printf 'merged %d lists (%d with IPv6)\n' \
  "$(find "$DATA" -maxdepth 1 -name '*.ipv4' | wc -l)" \
  "$(find "$DATA" -maxdepth 1 -name '*.ipv6' | wc -l)"
