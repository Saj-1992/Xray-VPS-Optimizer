# 🧰 ServerTools (Xray VPS Optimizer)

A **Linux server optimization toolkit** with a **zero runtime footprint** — built
for high-traffic VPN infrastructure: Xray/Reality nodes (`marzban-node`,
`pg-node`/Pasarguard, `marznode`), Marzban/Pasarguard panels, WireGuard, `x-ui`,
and Hiddify — as well as general-purpose tuning of any Linux server.

> Current version: **v2.14.4** · single file, no runtime dependencies, run as `root` · [Latest release](https://github.com/Saj-1992/Xray-VPS-Optimizer/releases/latest)  
> Version 1 is frozen under [`legacy/`](legacy/) and no longer updated.

📖 **[Full 0-to-100 guide & project overview (Persian) ← docs/GUIDE.md](docs/GUIDE.md)**

---

## 📥 Install & run

Run directly:

```bash
bash <(curl -fsSL4 https://github.com/Saj-1992/Xray-VPS-Optimizer/releases/latest/download/server-tools.sh)
```

Install as the `st` command (recommended):

```bash
bash <(curl -fsSL4 https://github.com/Saj-1992/Xray-VPS-Optimizer/releases/latest/download/server-tools.sh) --install
```

From then on just run `st`, and update anytime with:

```bash
st --update
```

> If `curl` is not installed, use `wget -qO-`, and remove `-4` on IPv6-only hosts.

---

## 🚀 Fastest way

```bash
st go                  # detect, optimize, and show health score — no questions
st go --users 10000    # size conntrack & RAM warnings from your real user count
st boost               # re-apply proxy CPU priority & OOM protection to running services/containers
```

---

## 🧠 How ServerTools works

Instead of blindly writing hardcoded sysctl values, **ServerTools** uses a layered, capacity-aware, and fully reversible architecture:

1. **Base layer (always):** Enables **BBR** with **`fq_codel`** (or `fq`/`cake` via `--qdisc`), RAM-scaled accept queues and socket buffers, TCP timers and keepalive, safe kernel hardening, `tcp_min_snd_mss` (CVE-2019-11479 floor), and file/map ceilings.
2. **Workload layer (VPN nodes):** Auto-detects active services/containers (`marzban-node`, `pg-node`, `xray`, `x-ui`, `hiddify`, `sing-box`, `hysteria`, `wireguard`, etc.), enables IPv4+IPv6 forwarding, sizes the `conntrack` table from RAM or `--users`, and reserves listening service ports (`ip_local_reserved_ports`) so outbound connections never steal inbound ports.
3. **Data-path & priority layer (`perf` & `boost`):** Spreads NIC softirq processing across all CPU cores (`RPS/RFS/XPS`), sets the CPU governor to `performance`, sets THP to `madvise`, and prioritizes proxy processes/containers (nice / OOM shield / CPU weight) — all non-disruptive and zero-footprint.
4. **Extras:** Swap (`zram` or swapfile, Btrfs-safe), 1M `nofile` limits (PAM + systemd), `journald` log cap + NTP, and DNS selection that persists across reboots.

Everything is **idempotent** — re-running is safe and converges cleanly to the same state.

---

## 🛡️ Iran ISP blocker (`st isp`)

From **Security → 5** or via the CLI, you can block the IP ranges of chosen Iranian ISPs (MCI, MTN/Irancell, TCI, Rightel, Shatel, AsiaTech, Pishgaman, MobinNet, ParsOnline) on all ports or selected ports:

- **Built on `ipset`**: constant-time lookups even with thousands of CIDR ranges.
- **Covers Docker**: rules are hooked into `DOCKER-USER` as well as `INPUT`.
- **Lockout-safe**: your SSH port and current session IP are automatically exempted.
- **IPv6 support**: enforces MCI and Irancell IPv6 ranges via `ip6tables` when IPv6 is active.
- **Offline-ready**: address lists (`data/isp`) are embedded inside the single-file script (idea and base lists from [Kiya6955/IR-ISP-Blocker](https://github.com/Kiya6955/IR-ISP-Blocker)).

```bash
st isp status                 # show blocked ISPs, scope, and rule state
st isp block mci,mtn          # block MCI and Irancell
st isp unblock mtn            # unblock Irancell
st isp scope 443,8443         # limit blocking to specific ports (or "all")
st isp check 1.2.3.4          # check which ISP owns an IP and whether live rules drop it
st isp live --watch           # watch live connection counts per ISP
st isp update                 # refresh lists from the repository and reload
```

---

## 🧭 Interactive menu (`st`)

| Section | What it includes |
| --- | --- |
| **1. Optimize** | **Quick** (auto-detect + asks user count), **One key** (`st go`), **Custom** (choose profile, tier, and modules) |
| **2. Status & Health** | 0–100 Health Score, remaining headroom (conntrack / RAM / CPU), full System Status, and **Doctor** drift detection |
| **3. Security** | **UFW** (with SSH lockout protection), **fail2ban** (only optional resident service, ~20 MB), **SSH hardening** (validated with `sshd -t`), node-API restriction, and **Iran ISP Blocker** |
| **4. Tools** | Ping matrix (Iran + global), **speedtest (Ookla or HTTP with server picker)**, benchmark, **Smart MTU/MSS**, **Conntrack NOTRACK**, **full IPv6 control**, live view, APT mirror, support report (`--report`), and **Node & Docker** |
| **5. Rollback** | Undo the latest recorded run (`--rollback`) or restore the original pre-tool state (`--rollback-original`) |

---

## 📦 Official panel & node setup (`st setup`)

`st setup pg-node` installs a **Pasarguard node** and `st setup xui` installs the **x-ui panel (alireza0)** using each project's official installer (downloaded over HTTPS, syntax-checked with `bash -n`, and shown with its source URL and SHA-256 before running):

```bash
st setup pg-node
st setup xui
st setup status
```

---

## ✨ Design principles

| Principle | Detail |
| --- | --- |
| **Zero footprint ⚡** | One-shot: tunes the kernel and exits. No background daemons, cron jobs, or telemetry. |
| **Capacity-aware 📊** | `conntrack` and buffers scale by tier or **real user count** (`--users`), with RAM estimates and honest OOM warnings. |
| **No regressions 🛡️** | Memory ceilings never drop below a modern kernel's own defaults. |
| **Real rollback ♻️** | Every file is tracked in `manifest.tsv` before modification, and a pristine `original/` copy is kept forever. |
| **Honest reporting ✅** | No fake "OK": every step reports `OK`/`WARN`/`SKIPPED`/`FAILED` and verifies live kernel/DNS state after apply. |
| **Tested quality 🧪** | ShellCheck + shfmt in CI; boot-tested on Ubuntu 20.04/22.04/24.04 and Debian 11/12. |

---

## ⌨️ CLI reference

```text
st                              Open the interactive menu and live dashboard
st go                           Detect, optimize, and show health — no questions
st --status                     Print full system status and exit
st --auto                       Non-interactive optimize (base + detected profile)
  --profile NAME                general | vpn-node | wireguard | panel | accounting | full
  --tier S|M|L|XL               Manual capacity tier
  --users N                     Size conntrack from expected concurrent users
  --qdisc fq|fq_codel|cake      Queue discipline paired with BBR (default: fq_codel)
  --dns VALUE                   cloudflare | google | quad9 | opendns | shecan | electro | begzar | "ip1,ip2"
  --no-swap / --no-limits       Skip optional steps in --auto mode
  --no-extras / --no-perf / --no-priority
st --dry-run                    Show the plan and exact sysctl diff, apply NOTHING
st --verify [--json]            Doctor: check if everything is still in effect (text or JSON)
st --report                     Print and save a plain-text support report
st --rollback                   Revert the latest recorded run
st --rollback-original          Restore the state from before ServerTools ever ran
st repair                       Ensure all oneshot persistence units are enabled for reboot
st boost                        Re-apply proxy CPU priority & OOM protection
st isp SUB [ARGS]               Manage Iran ISP blocker (status | live | check | scope | block | unblock | update)
st setup APP                    Official panel/node installer (pg-node | xui | status)
st --install / st --update      Install as 'st' / self-update from latest release
--no-color · --debug · -v · -h
```

**Exit codes (for Ansible/CI):** `0` success · `1` step failed · `2` usage error · `3` applied with warnings or drift detected.

---

## 📚 Documentation

- [📖 Full guide & project overview (Persian)](docs/GUIDE.md)
- [🏗️ Architecture](docs/ARCHITECTURE.md)
- [🎚️ Profiles & tiers](docs/PROFILES.md)
- [⚙️ sysctl specification](docs/SYSCTL.md)
- [♻️ Rollback & manifest design](docs/ROLLBACK.md)
- [❓ FAQ](docs/FAQ.md)
- [📝 Changelog](CHANGELOG.md)

---

## 🛠️ Repository layout & development

```text
src/       modular source (core/ + modules/ + menu.sh + 99-main.sh)
data/isp/  Iran ISP IP ranges (embedded into dist/server-tools.sh at build time)
build.sh   compiles src/ and data/isp/ into dist/server-tools.sh
dist/      generated single-file build (do not edit directly)
docs/      documentation and technical specs
tests/     smoke tests
legacy/    version 1 (frozen)
```

```bash
./build.sh        # build dist/server-tools.sh
make lint         # shellcheck + shfmt
./tests/smoke.sh  # fast non-root smoke test
```

Engineering rules live in [CLAUDE.md](CLAUDE.md).

---

## 👤 Creator & License

- Creator: **Saj-1992** (fork of Sir-Adnan/server-tools, originally by UnknownZero)
- License: [MIT](LICENSE)

*مستندات فارسی: [README.md](README.md)*
