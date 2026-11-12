#!/usr/bin/env bash
# ============================================================================
# tools/merge-isp.sh — builds data/isp/<id>.ipv4 (what the script embeds) from
#   data/isp/upstream/<id>.ipv4   the Kiya6955/IR-ISP-Blocker list
#   data/isp/asn/<id>.ipv4        prefixes announced by the ISP's AS (asn.map)
#   data/isp/extra/<id>.ipv4      ranges added by hand; never touched by the sync
# Union, validated, sorted, de-duplicated.
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
done
printf 'merged %d lists\n' "$(find "$DATA" -maxdepth 1 -name '*.ipv4' | wc -l)"
