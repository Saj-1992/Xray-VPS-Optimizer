#!/usr/bin/env bash
# ============================================================================
# tests/unit.sh — unit tests for the pure functions of the built script.
# Loads dist/server-tools.sh with ST_SOURCE_ONLY=1 (nothing runs, no root
# needed) and calls functions directly; anything that would touch the host is
# stubbed. Run: ./tests/unit.sh   (also run by CI and `make test`)
# ============================================================================
# The stubs below are called indirectly by the code under test.
# shellcheck disable=SC2317,SC2329
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT_DIR}/dist/server-tools.sh"

if [[ ! -f $DIST ]]; then
  bash "${ROOT_DIR}/build.sh" >/dev/null
fi

export ST_SOURCE_ONLY=1
# shellcheck disable=SC1090
source "$DIST"
# The build enables strict mode and an ERR trap; the tests do their own checks.
set +eE
trap - ERR

PASS=0
FAIL=0

ok() {
  PASS=$((PASS + 1))
}

bad() {
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n' "$1" >&2
}

# t NAME CMD... — passes when the command succeeds.
t() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then ok; else bad "$name"; fi
}

# f NAME CMD... — passes when the command fails.
f() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then bad "$name (should have failed)"; else ok; fi
}

# eq NAME EXPECTED ACTUAL
eq() {
  if [[ $2 == "$3" ]]; then ok; else bad "$1: expected [$2], got [$3]"; fi
}

# --- validators -------------------------------------------------------------
t "ipv4 ok" is_valid_ipv4 "192.168.1.1"
t "ipv4 edge" is_valid_ipv4 "255.255.255.255"
f "ipv4 octet 256" is_valid_ipv4 "1.2.3.256"
f "ipv4 short" is_valid_ipv4 "1.2.3"
f "ipv4 text" is_valid_ipv4 "abc"
f "ipv4 with mask" is_valid_ipv4 "1.2.3.4/24"
t "ipv6 full" is_valid_ipv6 "2a02:4540:0:0:0:0:0:1"
t "ipv6 compressed" is_valid_ipv6 "2a02:4540::1"
t "ipv6 loopback" is_valid_ipv6 "::1"
f "ipv6 two ::" is_valid_ipv6 "2a02::4540::1"
f "ipv6 not hex" is_valid_ipv6 "zzzz::1"
f "ipv6 empty" is_valid_ipv6 ""

# --- versions ---------------------------------------------------------------
t "ver_ge equal" ver_ge 2.14.4 2.14.4
t "ver_ge newer" ver_ge 2.14.10 2.14.9
f "ver_ge older" ver_ge 2.9.0 2.14.0
t "ver_ge major" ver_ge 3.0.0 2.99.99

# --- json_escape ------------------------------------------------------------
eq "json plain" 'abc' "$(json_escape 'abc')"
eq "json quote" 'a\"b' "$(json_escape 'a"b')"
eq "json backslash" 'a\\b' "$(json_escape 'a\b')"
eq "json newline" 'a\nb' "$(json_escape $'a\nb')"
eq "json tab" 'a\tb' "$(json_escape $'a\tb')"
eq "json control dropped" 'ab' "$(json_escape $'a\001b')"
eq "json empty" '' "$(json_escape '')"

# --- port helpers -----------------------------------------------------------
t "port in list" _port_in_reserved_list 443 "80,443"
t "port in range" _port_in_reserved_list 10500 "10000-20000"
f "port outside range" _port_in_reserved_list 9999 "10000-20000"
f "port not listed" _port_in_reserved_list 8080 "80,443"
eq "ports_split" $'80\n443\n1000-1002' "$(ports_split '80,443 1000-1002')"

# --- sysctl: never lower a kernel default ------------------------------------
sysctl_get() { printf '4096\t131072\t6291456'; }
eq "triple keeps larger live values" "net.ipv4.tcp_rmem = 4096 131072 6291456" \
  "$(_sysctl_triple_ceiling net.ipv4.tcp_rmem 4096 87380 6291456)"
eq "triple raises smaller live values" "net.ipv4.tcp_rmem = 8192 262144 67108864" \
  "$(_sysctl_triple_ceiling net.ipv4.tcp_rmem 8192 262144 67108864)"
sysctl_get() { printf 'garbage'; }
eq "triple with unreadable key uses ours" "k = 1 2 3" "$(_sysctl_triple_ceiling k 1 2 3)"

# --- manifest: a rolled-back run is skipped -----------------------------------
mf="$(mktemp)"
printf '# timestamp\trun_id\taction\ttarget\n' >"$mf"
eq "latest of empty manifest" "" "$(manifest_latest_run "$mf")"
printf '2026-01-01 10:00:00\t20260101-1000\tcreated\t/etc/a\n' >>"$mf"
printf '2026-01-02 10:00:00\t20260102-1000\tmodified\t/etc/b\n' >>"$mf"
eq "latest = newest run" "20260102-1000" "$(manifest_latest_run "$mf")"
printf '2026-01-03 10:00:00\t20260103-1000\treverted\t20260102-1000\n' >>"$mf"
eq "reverted run is skipped" "20260101-1000" "$(manifest_latest_run "$mf")"
printf '2026-01-04 10:00:00\t20260104-1000\treverted\t20260101-1000\n' >>"$mf"
eq "everything reverted" "" "$(manifest_latest_run "$mf")"
printf '2026-01-05 10:00:00\t20260105-1000\tcreated\t/etc/c\n' >>"$mf"
eq "a new run after rollbacks counts again" "20260105-1000" "$(manifest_latest_run "$mf")"
rm -f "$mf"

# --- ISP blocker: parsing and helpers ----------------------------------------
t "cidr v4" _isp_valid_cidr "5.106.0.0/17"
t "cidr v4 host" _isp_valid_cidr "5.106.1.1"
f "cidr v4 mask 33" _isp_valid_cidr "5.106.0.0/33"
t "cidr v6" _isp_valid_cidr "2a02:4540::/29"
f "cidr v6 mask 129" _isp_valid_cidr "2a02:4540::/129"
f "cidr junk" _isp_valid_cidr "hello"
t "port 443" _isp_valid_port 443
t "port range" _isp_valid_port 10000-20000
f "port 0" _isp_valid_port 0
f "port 70000" _isp_valid_port 70000
f "port reversed range" _isp_valid_port 20000-10000
eq "resolve id" mci "$(_isp_resolve mci)"
eq "resolve number" mtn "$(_isp_resolve 2)"
eq "resolve alias" mtn "$(_isp_resolve Irancell)"
eq "resolve alias 2" mci "$(_isp_resolve hamrah)"
f "resolve unknown" _isp_resolve nonsense
t "family v4" _isp_in_family 4 "1.2.3.4"
f "family v4 rejects v6" _isp_in_family 4 "2a02::1"
t "family v6" _isp_in_family 6 "2a02::1"
f "family v6 rejects v4" _isp_in_family 6 "1.2.3.4"

detect_ssh_port() { printf '22'; }
t "scope: only the ssh port" _isp_scope_is_ssh_only "22"
f "scope: ssh and others" _isp_scope_is_ssh_only "22,443"
f "scope: other port" _isp_scope_is_ssh_only "443"
f "scope: all" _isp_scope_is_ssh_only "all"

# --- live view classifier ------------------------------------------------------
work="$(mktemp -d)"
printf 'mci 5.106.0.0/16\nmci 46.51.48.0/20\nmtn 5.112.0.0/12\nmtn 2.144.0.0/14\n' >"$work/ranges"
printf '3 5.106.1.1\n2 46.51.60.139\n5 5.119.216.84\n1 8.8.8.8\n4 5.106.200.9\n' >"$work/peers"
out="$(_live_classify "$work/ranges" "$work/peers" | sort)"
eq "classify counts" $'mci 9 3\nmtn 5 1\nother 1 1' "$out"
rm -rf "$work"

# --- the run lock: a guarded function runs once, whatever the environment -------
guard_calls=0
guarded_demo() {
  if [[ ${ST_LOCKED:-0} != 1 ]]; then
    st_locked guarded_demo
    return
  fi
  guard_calls=$((guard_calls + 1))
  return 7
}
guarded_demo 2>/dev/null
guard_rc=$?
eq "guarded function ran exactly once" "1" "$guard_calls"
eq "guarded function's status is returned" "7" "$guard_rc"
eq "the lock is released afterwards" "0" "${ST_LOCKED:-0}"

# --- fleet: settings import validation -------------------------------------------
t "cfg qdisc ok" _config_value_ok qdisc fq_codel
f "cfg qdisc bad" _config_value_ok qdisc pfifo
t "cfg users ok" _config_value_ok expected_users 5000
f "cfg users bad" _config_value_ok expected_users many
t "cfg dns ok" _config_value_ok dns_primary 1.1.1.1
f "cfg dns bad" _config_value_ok dns_primary not-an-ip
t "cfg isp ids ok" _config_value_ok isp_ids "mci,mtn"
f "cfg isp ids unknown" _config_value_ok isp_ids "mci,nope"
t "cfg isp ports all" _config_value_ok isp_ports all
t "cfg isp ports list" _config_value_ok isp_ports "443,10000-20000"
f "cfg isp ports bad" _config_value_ok isp_ports "99999"
f "cfg unknown key" _config_value_ok something_else 1
f "cfg control char" _config_value_ok qdisc $'fq\001'
bad_cfg="$(mktemp)"
printf 'qdisc=fq\nthis is not a setting\n' >"$bad_cfg"
f "import rejects a malformed file" bash -c "ST_SOURCE_ONLY=1 source '$DIST' >/dev/null 2>&1; config_import '$bad_cfg'"
printf 'qdisc=banana\n' >"$bad_cfg"
f "import rejects an invalid value" bash -c "ST_SOURCE_ONLY=1 source '$DIST' >/dev/null 2>&1; config_import '$bad_cfg'"
rm -f "$bad_cfg"

# --- the embedded lists --------------------------------------------------------
t "embedded mci list is not empty" bash -c "source '$DIST' >/dev/null 2>&1; [[ -n \"\$(_isp_embedded mci)\" ]]"
t "embedded mci has IPv6" bash -c "source '$DIST' >/dev/null 2>&1; _isp_embedded6 mci | grep -q ':'"

printf 'unit: %d passed, %d failed\n' "$PASS" "$FAIL"
((FAIL == 0))
