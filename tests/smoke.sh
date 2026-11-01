#!/usr/bin/env bash
# ============================================================================
# tests/smoke.sh — fast sanity checks that need no root and no network:
# the build succeeds, the output parses, and --version/--help behave.
# ============================================================================
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT_DIR}/dist/server-tools.sh"
VERSION="$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")"

fail() {
  printf 'smoke: FAIL — %s\n' "$1" >&2
  exit 1
}

# Invoke via bash so the test never depends on the exec bit surviving checkout.
bash "${ROOT_DIR}/build.sh" >/dev/null

bash -n "$DIST" || fail "dist does not parse"

if grep -q $'\r' "$DIST"; then
  fail "dist contains CRLF line endings"
fi

out="$(bash "$DIST" --version)"
[[ $out == *"$VERSION"* ]] || fail "--version output '${out}' does not contain '${VERSION}'"

bash "$DIST" --help >/dev/null || fail "--help exited non-zero"

if bash "$DIST" --definitely-not-an-option >/dev/null 2>&1; then
  fail "unknown option should exit non-zero"
fi

if bash "$DIST" --auto --profile >/dev/null 2>&1; then
  fail "--profile without a value should exit non-zero"
fi

bash "$DIST" --help | grep -q -- '--auto' || fail "--help should document --auto"
bash "$DIST" --help | grep -q -- '--dry-run' || fail "--help should document --dry-run"
bash "$DIST" --help | grep -q -- '--report' || fail "--help should document --report"

if bash "$DIST" --auto --qdisc bogus >/dev/null 2>&1; then
  fail "--qdisc with an invalid value should exit non-zero"
fi
bash "$DIST" --help | grep -q -- '--qdisc' || fail "--help should document --qdisc"

bash "$DIST" --help | grep -q -- ' go ' || fail "--help should document go"

# The ISP address lists must be embedded and well-formed.
bash "$DIST" --help | grep -q -- 'isp SUB' || fail "--help should document isp"
for list in "${ROOT_DIR}"/data/isp/*.ipv4; do
  [[ -s $list ]] || fail "empty ISP list: $list"
  if grep -qvE '^([0-9]{1,3}.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$' "$list"; then
    fail "malformed line in $list"
  fi
  grep -qxF "$(sed -n 1p "$list")" "$DIST" || fail "$list is not embedded in dist"
done

printf 'smoke: OK (v%s)\n' "$VERSION"
