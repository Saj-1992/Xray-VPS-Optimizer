#!/usr/bin/env bash
# ============================================================
#  Xray VPS Optimizer — full auto-tune  v2.0
#  Supports: Xray-core, 3x-ui, Marzban, Hiddify, Remnawave,
#            Pasargad panel, v2ray, sing-box
#
#  Usage:
#    sudo bash vps.sh            — full interactive setup
#    sudo bash vps.sh --status   — show current state
#    sudo bash vps.sh --dns      — re-apply DNS only
#    sudo bash vps.sh --restore  — restore latest backups
# ============================================================

# ===== Logging — all output goes to terminal + log file =====
LOG_FILE="/var/log/vps-optimizer-$(date +%F_%H%M%S).log"
# We set this up after need_root() confirms we're root, inside main()

# ===== Defaults (can be overridden via env) =====
SERVER_LOCATION="${SERVER_LOCATION:-}"
SWAP_SIZE="${SWAP_SIZE:-}"
SWAPPINESS="${SWAPPINESS:-10}"
QDISC="${QDISC:-}"
CC="${CC:-}"
TCP_FASTOPEN="${TCP_FASTOPEN:-3}"
APPLY_MSS_CLAMP="${APPLY_MSS_CLAMP:-1}"
MSS_VALUE="${MSS_VALUE:-1360}"
OPEN_BBR_CHECK="${OPEN_BBR_CHECK:-1}"
GRUB_PROFILE="${GRUB_PROFILE:-}"

# ===== Colours =====
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; BLUE="\033[1;34m"; MAGENTA="\033[1;35m"
NC="\033[0m"

# ===== Helpers =====
log()  { echo -e "\n${GREEN}[+] $*${NC}"; }
warn() { echo -e "${YELLOW}[!] $*${NC}"; }
die()  { echo -e "${RED}[x] $*${NC}"; exit 1; }
info() { echo -e "${CYAN}[i] $*${NC}"; }

need_root()      { [[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"; }
is_debian_like() { [[ -f /etc/debian_version ]] && command -v apt >/dev/null 2>&1; }

backup_file(){
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts; ts="$(date +%F_%H%M%S)"
  cp -a "$f" "${f}.bak.${ts}"
  info "Backed up: ${f}.bak.${ts}"
}

detect_iface(){
  ip route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

sysctl_set(){
  local k="$1" v="$2" conf="/etc/sysctl.d/99-xray-tune.conf"
  grep -qE "^${k}\s*=" "$conf" 2>/dev/null \
    && sed -i "s|^${k}\s*=.*|${k} = ${v}|" "$conf" \
    || echo "${k} = ${v}" >> "$conf"
}

sysctl_apply(){
  sysctl --system 2>&1 | grep -v "^sysctl: setting key" || true
}

check_qdisc_support(){
  local q="$1"
  tc qdisc add dev lo root "$q" >/dev/null 2>&1 \
    && { tc qdisc del dev lo root >/dev/null 2>&1; return 0; } \
    || return 1
}

apply_qdisc_runtime(){
  local iface; iface="$(detect_iface || true)"
  [[ -n "${iface}" ]] || { warn "Could not detect main interface; skipping tc."; return 0; }
  if check_qdisc_support "$QDISC"; then
    log "Applying qdisc=$QDISC on $iface"
    tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
    tc qdisc add dev "$iface" root "$QDISC"
  else
    warn "QDISC=$QDISC not supported. Falling back to fq."
    QDISC="fq"
    sysctl_set "net.core.default_qdisc" "fq"
    sysctl_apply
    tc qdisc del dev "$iface" root >/dev/null 2>&1 || true
    tc qdisc add dev "$iface" root fq || true
  fi
}

# ================================================================
#  Xray / Panel service detection
# ================================================================
detect_xray_services(){
  local found=()
  local candidates=(
    xray xray.service
    v2ray v2ray.service
    sing-box sing-box.service
    x-ui x-ui.service
    3x-ui 3x-ui.service
    sanaei sanaei.service
    marzban marzban.service
    hiddify hiddify.service hiddify-panel hiddify-panel.service
    remnawave remnawave.service remnawave-panel remnawave-panel.service
    pasargad pasargad.service pasargad-panel pasargad-panel.service
  )

  while IFS= read -r unit; do
    candidates+=("$unit")
  done < <(systemctl list-unit-files --type=service 2>/dev/null \
    | awk '{print $1}' \
    | grep -iE 'xray|v2ray|marzban|hiddify|remnawave|pasargad|sing.box|x-ui|3x-ui|sanaei' \
    || true)

  for s in "${candidates[@]}"; do
    [[ " ${found[*]:-} " == *" $s "* ]] && continue
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$s" 2>/dev/null; then
      found+=("$s")
    fi
  done

  echo "${found[@]:-}"
}

iptables_persistent_installed(){
  dpkg -s iptables-persistent >/dev/null 2>&1
}

install_iptables_persistent(){
  log "Installing iptables-persistent"
  export DEBIAN_FRONTEND=noninteractive
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
  apt-get install -y iptables-persistent netfilter-persistent
}

save_iptables_rules(){
  iptables_persistent_installed || { warn "iptables-persistent missing; skipping save."; return 0; }
  netfilter-persistent save
  systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  systemctl restart netfilter-persistent >/dev/null 2>&1 || true
  info "iptables rules saved."
}

# ================================================================
#  INTERACTIVE QUESTIONS
# ================================================================

ask_server_location(){
  [[ -n "${SERVER_LOCATION:-}" ]] && return 0
  echo
  echo -e "${BLUE}+-------------------------------------+${NC}"
  echo -e "${BLUE}     Where is this server located?${NC}"
  echo -e "${BLUE}+-------------------------------------+${NC}"
  echo -e "  ${RED}1)${NC} Iran"
  echo -e "  ${RED}2)${NC} Abroad / Foreign"
  while true; do
    read -r -p "$(echo -e "${YELLOW}Your choice [1/2]: ${NC}")" loc
    case "$loc" in
      1) SERVER_LOCATION="ir";      break ;;
      2) SERVER_LOCATION="foreign"; break ;;
      *) warn "Invalid. Enter 1 or 2." ;;
    esac
  done
}

ask_swap_size(){
  [[ -n "${SWAP_SIZE:-}" ]] && return 0

  # FIX: نمایش RAM فعلی قبل از انتخاب
  local total_ram_mb
  total_ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "?")
  local free_disk_gb
  free_disk_gb=$(df -BG / 2>/dev/null | awk 'NR==2{gsub("G",""); print $4}' || echo "?")

  echo
  echo -e "${BLUE}+---------------------------------------------+${NC}"
  echo -e "${BLUE}          Swap File Configuration${NC}"
  echo -e "${BLUE}+---------------------------------------------+${NC}"
  echo -e "  ${CYAN}RAM detected : ${total_ram_mb}MB${NC}"
  echo -e "  ${CYAN}Free disk    : ${free_disk_gb}GB${NC}"
  echo -e "  ${CYAN}TIP: Swap = 2x RAM if RAM < 2GB and disk allows.${NC}"
  echo
  echo -e "  ${RED}1)${NC} 512MB"
  echo -e "  ${RED}2)${NC} 1GB"
  echo -e "  ${RED}3)${NC} 2GB  ${GREEN}(recommended)${NC}"
  echo -e "  ${RED}4)${NC} 4GB"
  echo -e "  ${RED}5)${NC} Custom  (e.g. 3G, 768M)"
  echo -e "  ${RED}6)${NC} No swap – skip"
  while true; do
    read -r -p "$(echo -e "${YELLOW}Your choice [1-6]: ${NC}")" sw
    case "$sw" in
      1) SWAP_SIZE="512M"; break ;;
      2) SWAP_SIZE="1G";   break ;;
      3) SWAP_SIZE="2G";   break ;;
      4) SWAP_SIZE="4G";   break ;;
      5)
        read -r -p "$(echo -e "${YELLOW}Enter size (e.g. 1500M, 3G): ${NC}")" custom
        if [[ "$custom" =~ ^[0-9]+(M|G)$ ]]; then
          SWAP_SIZE="$custom"; break
        else
          warn "Invalid format. Use e.g. 512M or 2G."
        fi ;;
      6) SWAP_SIZE="0"; break ;;
      *) warn "Enter 1–6." ;;
    esac
  done
}

ask_bbr_qdisc(){
  # FIX: چک کرنل برای BBR2
  local kernel_major
  kernel_major=$(uname -r | cut -d. -f1)

  echo
  echo -e "${BLUE}+-----------------------------------------------------------+${NC}"
  echo -e "${BLUE}         TCP Congestion Control Selection${NC}"
  echo -e "${BLUE}+-----------------------------------------------------------+${NC}"
  echo -e "  ${CYAN}Kernel: $(uname -r)${NC}"
  echo
  echo -e "  ${RED}1)${NC} ${GREEN}BBR v1${NC}   – Stable, widely supported ${GREEN}(recommended)${NC}"
  if (( kernel_major >= 6 )); then
    echo -e "  ${RED}2)${NC} ${GREEN}BBR v2${NC}   – Better throughput, kernel 6.x+ ${GREEN}(supported)${NC}"
  else
    echo -e "  ${RED}2)${NC} ${GREEN}BBR v2${NC}   – Better throughput ${RED}(kernel < 6 — likely unsupported)${NC}"
  fi
  echo -e "  ${RED}3)${NC} ${GREEN}HYBLA${NC}    – High-latency / satellite links"
  echo -e "  ${RED}0)${NC} ${GREEN}None${NC}     – Keep current setting"
  while true; do
    read -r -p "$(echo -e "${YELLOW}Your choice [0-3]: ${NC}")" bv
    case "$bv" in
      1) CC="bbr";   break ;;
      2) CC="bbr2";  break ;;
      3) CC="hybla"; break ;;
      0) CC="none";  break ;;
      *) warn "Enter 0–3." ;;
    esac
  done

  [[ "$CC" == "none" ]] && { info "Skipping qdisc selection."; return 0; }

  echo
  echo -e "${BLUE}+-----------------------------------------------------------+${NC}"
  echo -e "${BLUE}           Queue Discipline (Qdisc) Selection${NC}"
  echo -e "${BLUE}+-----------------------------------------------------------+${NC}"
  echo -e "  ${CYAN}FQ${NC}         – Fair Queue; best balance (latency + throughput)"
  echo -e "  ${CYAN}FQ_CoDel${NC}  – Reduces buffer bloat; great for VPN/proxy"
  echo -e "  ${CYAN}CAKE${NC}       – Advanced shaping; ideal for high-latency WAN"
  echo -e "  ${CYAN}SFQ${NC}        – Simple fairness; low CPU overhead"
  echo -e "  ${CYAN}HTB${NC}        – Hierarchical bandwidth control"
  echo -e "  ${CYAN}PFIFO_FAST${NC} – Basic priority queue"
  echo -e "  ${MAGENTA}Suggested for Xray/VPN: fq_codel / fq / cake${NC}"
  echo
  echo -e "  ${RED}1)${NC} fq"
  echo -e "  ${RED}2)${NC} fq_codel  ${GREEN}(recommended)${NC}"
  echo -e "  ${RED}3)${NC} cake"
  echo -e "  ${RED}4)${NC} sfq"
  echo -e "  ${RED}5)${NC} htb"
  echo -e "  ${RED}6)${NC} pfifo_fast"
  while true; do
    read -r -p "$(echo -e "${YELLOW}Your choice [1-6]: ${NC}")" qd
    local chosen_qdisc
    case "$qd" in
      1) chosen_qdisc="fq";;        2) chosen_qdisc="fq_codel";;
      3) chosen_qdisc="cake";;      4) chosen_qdisc="sfq";;
      5) chosen_qdisc="htb";;       6) chosen_qdisc="pfifo_fast";;
      *) warn "Enter 1–6."; continue;;
    esac
    if check_qdisc_support "$chosen_qdisc"; then
      QDISC="$chosen_qdisc"; break
    else
      warn "$chosen_qdisc is NOT supported by this kernel. Choose another."
    fi
  done

  info "Selected: CC=$CC | QDISC=$QDISC"
}

ask_grub_profile(){
  [[ -n "${GRUB_PROFILE:-}" ]] && return 0

  local virt=""
  command -v systemd-detect-virt >/dev/null 2>&1 \
    && virt="$(systemd-detect-virt 2>/dev/null || true)"
  if [[ "$virt" == "openvz" || "$virt" == "lxc" ]]; then
    warn "Virtualization=$virt: GRUB tuning not supported. Skipping."
    GRUB_PROFILE="skip"; return 0
  fi
  [[ -f /etc/default/grub ]] || { warn "/etc/default/grub not found."; GRUB_PROFILE="skip"; return 0; }

  echo
  echo -e "${BLUE}+-----------------------------------------------------------+${NC}"
  echo -e "${BLUE}              GRUB / CPU Tuning Profile${NC}"
  echo -e "${BLUE}+-----------------------------------------------------------+${NC}"
  echo -e "  ${RED}1)${NC} ${GREEN}Server/VPS${NC}     – ${CYAN}mitigations=off + nohz=on + intel_pstate=active${NC}"
  echo -e "                    Max throughput. Only use if you control all tenants."
  echo -e "  ${RED}2)${NC} ${GREEN}Virtualization${NC} – ${CYAN}transparent_hugepage=madvise + nohz=on${NC}"
  echo -e "                    KVM/QEMU hypervisor host."
  echo -e "  ${RED}3)${NC} ${GREEN}Balanced${NC}        – ${CYAN}intel_pstate=active + nohz=on${NC} (mitigations ON)"
  echo -e "                    Safer default with performance gains."
  echo -e "  ${RED}0)${NC} ${GREEN}Skip${NC}            – Do not touch GRUB"
  while true; do
    read -r -p "$(echo -e "${YELLOW}Your choice [0-3]: ${NC}")" gp
    case "$gp" in
      1) GRUB_PROFILE="server";   break ;;
      2) GRUB_PROFILE="virt";     break ;;
      3) GRUB_PROFILE="balanced"; break ;;
      0) GRUB_PROFILE="skip";     break ;;
      *) warn "Enter 0–3." ;;
    esac
  done
}

# ================================================================
#  ACTION FUNCTIONS
# ================================================================

# ----- DNS -----
action_dns(){
  local dns_primary dns_fallback label

  case "$SERVER_LOCATION" in
    ir)
      label="Iran"
      dns_primary="217.218.127.127"
      dns_fallback="217.218.155.155"
      ;;
    foreign)
      label="Abroad"
      dns_primary="1.1.1.1"
      dns_fallback="8.8.8.8"
      ;;
    *) warn "Unknown SERVER_LOCATION; skipping DNS."; return 0 ;;
  esac

  log "Configuring DNS for: $label"

  # FIX: unlock قبل از ویرایش (در صورت re-run)
  chattr -i /etc/systemd/resolved.conf 2>/dev/null || true
  backup_file /etc/systemd/resolved.conf

  cat >/etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=${dns_primary} ${dns_fallback}
FallbackDNS=9.9.9.9
DNSStubListener=yes
EOF

  systemctl restart systemd-resolved 2>/dev/null || true
  rm -f /etc/resolv.conf
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  info "DNS: ${dns_primary}  fallback: ${dns_fallback}"

  if [[ "$SERVER_LOCATION" == "ir" ]]; then
    grep -q "185.199.108.133 raw.githubusercontent.com" /etc/hosts \
      || echo "185.199.108.133 raw.githubusercontent.com" >> /etc/hosts
    grep -q "140.82.114.4 github.com" /etc/hosts \
      || echo "140.82.114.4 github.com" >> /etc/hosts
    info "Added GitHub entries to /etc/hosts."
  fi
}

# ----- DNS Persist — جلوگیری از پاک شدن DNS بعد از reboot -----
action_dns_persist(){
  log "Making DNS persistent across reboots"

  # 1) cloud-init
  if [[ -d /etc/cloud/cloud.cfg.d ]]; then
    cat >/etc/cloud/cloud.cfg.d/99-disable-dns.cfg <<'EOF'
manage_resolv_conf: false
EOF
    info "cloud-init: DNS management disabled."
  fi

  # 2) NetworkManager
  if [[ -d /etc/NetworkManager/conf.d ]]; then
    cat >/etc/NetworkManager/conf.d/99-dns-none.conf <<'EOF'
[main]
dns=none
EOF
    systemctl reload NetworkManager 2>/dev/null || true
    info "NetworkManager: DNS management disabled."
  fi

  # 3) قفل کردن resolved.conf با chattr
  if chattr +i /etc/systemd/resolved.conf 2>/dev/null; then
    info "resolved.conf locked (immutable). To edit later: chattr -i /etc/systemd/resolved.conf"
  else
    warn "chattr not available; resolved.conf not locked (filesystem may not support it)."
  fi

  # 4) systemd service برای enforce DNS بعد از هر reboot
  cat >/etc/systemd/system/dns-enforce.service <<'EOF'
[Unit]
Description=Enforce custom DNS settings (vps-optimizer)
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'systemctl restart systemd-resolved; resolvectl status'

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable dns-enforce.service >/dev/null 2>&1
  info "dns-enforce.service enabled — DNS will be re-enforced after each reboot."
}

# ----- Mirror selection -----
action_iran_mirror(){
  [[ "$SERVER_LOCATION" == "ir" ]] || return 0
  log "Selecting best Iran mirror (DNS already configured)"

  local mirrors=("mirror.arvancloud.ir" "ir.ubuntu.sindad.cloud" "ubuntu.shatel.ir")
  local best="" best_ms=99999

  for m in "${mirrors[@]}"; do
    printf "  Testing %-35s ... " "$m"
    local ms
    # FIX: safe با || echo ""
    ms=$(ping -c 3 -W 2 "$m" 2>/dev/null | awk -F'/' '/rtt/{print int($5)}' || echo "")
    if [[ -n "$ms" ]]; then
      echo "${ms} ms"
      (( ms < best_ms )) && { best_ms="$ms"; best="$m"; }
    else
      echo "unreachable"
    fi
  done

  if [[ -z "$best" ]]; then
    warn "No responsive mirror. Keeping current apt sources."
    return 0
  fi
  info "Best mirror: $best (${best_ms} ms)"

  local os_id release
  os_id=$(grep -oP '(?<=^ID=)[^\n]+' /etc/os-release | tr -d '"' || echo "ubuntu")
  release=$(lsb_release -cs 2>/dev/null \
    || grep -oP '(?<=VERSION_CODENAME=)[^\n]+' /etc/os-release | tr -d '"' \
    || echo "")

  if [[ -z "$release" ]]; then
    warn "Could not detect OS release codename. Skipping mirror change."
    return 0
  fi

  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    backup_file /etc/apt/sources.list.d/ubuntu.sources
    sed -i "s|^URIs:.*|URIs: http://${best}/ubuntu/|" \
      /etc/apt/sources.list.d/ubuntu.sources
  elif [[ -f /etc/apt/sources.list ]]; then
    backup_file /etc/apt/sources.list
    if [[ "$os_id" == "ubuntu" ]]; then
      cat >/etc/apt/sources.list <<EOF
deb http://${best}/ubuntu ${release} main restricted universe multiverse
deb http://${best}/ubuntu ${release}-updates main restricted universe multiverse
deb http://${best}/ubuntu ${release}-backports main restricted universe multiverse
deb http://${best}/ubuntu ${release}-security main restricted universe multiverse
EOF
    else
      cat >/etc/apt/sources.list <<EOF
deb http://${best}/debian ${release} main
deb http://${best}/debian ${release}-updates main
deb http://${best}/debian ${release}-backports main
deb http://${best}/debian-security ${release}-security main
EOF
    fi
  else
    warn "No apt sources file found. Skipping mirror change."
    return 0
  fi

  rm -rf /var/lib/apt/lists/*
  apt-get update -y
}

# ----- Tools -----
action_install_tools(){
  log "Installing required packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y \
    curl wget git jq ca-certificates gnupg lsb-release \
    htop nload nethogs \
    iperf3 mtr-tiny dnsutils \
    unzip tar \
    chrony haveged \
    net-tools iproute2 iptables nftables \
    conntrack \
    tmux \
    e2fsprogs  # برای chattr
}

# ----- Swap -----
action_swap(){
  if [[ "$SWAP_SIZE" == "0" ]]; then
    warn "Swap skipped."; return 0
  fi
  log "Setting up swap: ${SWAP_SIZE}"

  local existing
  existing=$(swapon --show=NAME --noheadings 2>/dev/null || true)
  for sw in $existing; do
    swapoff "$sw" 2>/dev/null || true
    [[ "$sw" == /swapfile* || "$sw" == /swap ]] && rm -f "$sw" || true
  done
  sed -i '/\bswap\b/d' /etc/fstab 2>/dev/null || true

  local count unit
  if [[ "$SWAP_SIZE" =~ ^([0-9]+)(M|G)$ ]]; then
    count="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    [[ "$unit" == "G" ]] && count=$(( count * 1024 ))
  else
    warn "Cannot parse SWAP_SIZE=$SWAP_SIZE. Using 2GB."
    count=2048
  fi

  local swapfile="/swapfile"
  info "Creating ${SWAP_SIZE} swapfile at $swapfile..."

  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "${count}M" "$swapfile"
  else
    dd if=/dev/zero of="$swapfile" bs=1M count="$count" status=progress
  fi

  chmod 600 "$swapfile"
  mkswap "$swapfile"
  swapon "$swapfile"
  echo "${swapfile} none swap sw 0 0" >> /etc/fstab

  sysctl_set "vm.swappiness" "$SWAPPINESS"
  sysctl_apply

  info "Swap active: ${SWAP_SIZE} | swappiness=${SWAPPINESS}"
  swapon --show
}

# ----- GRUB -----
action_grub(){
  [[ "$GRUB_PROFILE" == "skip" ]] && { warn "GRUB tuning skipped."; return 0; }
  [[ -f /etc/default/grub ]] || { warn "/etc/default/grub not found."; return 0; }

  log "Applying GRUB profile: $GRUB_PROFILE"
  backup_file /etc/default/grub

  local current_params
  current_params=$(grep -oP '(?<=GRUB_CMDLINE_LINUX_DEFAULT=")[^"]*' /etc/default/grub \
    || echo "quiet splash")

  current_params=$(echo "$current_params" \
    | sed -E 's/\b(mitigations|nohz|nosmt|intel_pstate|amd_iommu|transparent_hugepage|skew_tick)=[^ ]*//g' \
    | tr -s ' ')

  local extra=""
  case "$GRUB_PROFILE" in
    server)
      extra="quiet mitigations=off nohz=on intel_pstate=active skew_tick=1"
      ;;
    virt)
      extra="quiet nohz=on intel_pstate=active transparent_hugepage=madvise"
      ;;
    balanced)
      extra="quiet intel_pstate=active nohz=on"
      ;;
  esac

  local new_params
  new_params="$(echo "${current_params} ${extra}" | tr -s ' ' | sed 's/^ //;s/ $//')"

  sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${new_params}\"|" \
    /etc/default/grub
  sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' /etc/default/grub

  if command -v update-grub >/dev/null 2>&1; then
    update-grub 2>/dev/null && info "GRUB updated." \
      || warn "update-grub had a warning (non-fatal)."
  elif command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null && info "GRUB updated." \
      || warn "grub2-mkconfig warning (non-fatal)."
  else
    warn "No grub update tool found. Run update-grub manually."
  fi

  warn "GRUB changes apply after next reboot."
}

# ----- Load CC kernel module -----
load_cc_module(){
  [[ "$CC" == "none" ]] && return 0
  local mod="tcp_${CC}"

  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "$CC"; then
    info "Module $mod already available."; return 0
  fi

  log "Loading kernel module: $mod"
  if modprobe "$mod" 2>/dev/null; then
    info "Module $mod loaded successfully."
    echo "$mod" > "/etc/modules-load.d/${mod}.conf"
  else
    warn "modprobe $mod failed. Falling back to bbr v1."
    CC="bbr"
    if modprobe tcp_bbr 2>/dev/null; then
      echo "tcp_bbr" > /etc/modules-load.d/tcp_bbr.conf
    else
      warn "Cannot load tcp_bbr either. Setting CC=none."
      CC="none"
    fi
  fi
}

# ----- FIX: بارگذاری nf_conntrack قبل از sysctl -----
action_load_conntrack(){
  if ! lsmod | grep -q nf_conntrack 2>/dev/null; then
    if modprobe nf_conntrack 2>/dev/null; then
      echo "nf_conntrack" > /etc/modules-load.d/nf_conntrack.conf
      info "nf_conntrack module loaded and persisted."
    else
      warn "nf_conntrack module not available — conntrack sysctl keys will be skipped."
    fi
  else
    info "nf_conntrack already loaded."
    # اطمینان از persistence
    grep -q nf_conntrack /etc/modules-load.d/nf_conntrack.conf 2>/dev/null \
      || echo "nf_conntrack" > /etc/modules-load.d/nf_conntrack.conf
  fi
}

# ----- Sysctl -----
action_sysctl_xray(){
  action_load_conntrack
  load_cc_module

  log "Writing /etc/sysctl.d/99-xray-tune.conf"

  cat >/etc/sysctl.d/99-xray-tune.conf <<EOF
# ===== Xray VPS Optimizer – auto-generated =====

# ---- File handles ----
fs.file-max = 10000000

# ---- Backlog / queues ----
net.core.somaxconn          = 131072
net.core.netdev_max_backlog = 250000
net.core.optmem_max         = 262144

# ---- Socket buffers ----
net.core.rmem_max         = 268435456
net.core.wmem_max         = 268435456
net.core.rmem_default     = 2097152
net.core.wmem_default     = 2097152
net.ipv4.udp_rmem_min     = 16384
net.ipv4.udp_wmem_min     = 16384
net.ipv4.tcp_rmem         = 8192 1048576 268435456
net.ipv4.tcp_wmem         = 8192 1048576 268435456

# ---- TCP performance ----
net.core.default_qdisc              = ${QDISC:-fq}
net.ipv4.tcp_congestion_control     = ${CC:-bbr}
net.ipv4.tcp_fastopen               = ${TCP_FASTOPEN}
net.ipv4.tcp_mtu_probing            = 1
net.ipv4.tcp_slow_start_after_idle  = 0
net.ipv4.tcp_no_metrics_save        = 1
net.ipv4.tcp_moderate_rcvbuf        = 1
net.ipv4.tcp_window_scaling         = 1
net.ipv4.tcp_sack                   = 1
net.ipv4.tcp_dsack                  = 1
net.ipv4.tcp_ecn                    = 1
net.ipv4.tcp_ecn_fallback           = 1
net.ipv4.tcp_notsent_lowat          = 16384
net.ipv4.tcp_adv_win_scale          = 0

# ---- Keepalives / timeouts ----
net.ipv4.tcp_keepalive_time   = 60
net.ipv4.tcp_keepalive_intvl  = 10
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_fin_timeout      = 15
net.ipv4.tcp_tw_reuse         = 1
net.ipv4.tcp_max_tw_buckets   = 1440000
net.ipv4.tcp_max_orphans      = 819200

# ---- Port range ----
net.ipv4.ip_local_port_range  = 1024 65535

# ---- SYN hardening ----
net.ipv4.tcp_syncookies      = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries  = 2
net.ipv4.tcp_syn_retries     = 3

# ---- Memory ----
net.ipv4.tcp_mem  = 786432 1048576 26777216
net.ipv4.udp_mem  = 65536  1048576 33554432

# ---- UDP / QUIC (Xray QUIC support) ----
net.core.netdev_budget       = 600
net.core.netdev_budget_usecs = 8000

# ---- IP fragmentation ----
net.ipv4.ipfrag_high_thresh = 524288
net.ipv4.ipfrag_low_thresh  = 446464
net.ipv4.ipfrag_time        = 60

# ---- Conntrack ----
net.netfilter.nf_conntrack_max                     = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait   = 30
net.netfilter.nf_conntrack_udp_timeout             = 30
net.netfilter.nf_conntrack_udp_timeout_stream      = 120

# ---- IP forwarding ----
net.ipv4.ip_forward          = 1
net.ipv6.conf.all.forwarding = 1

# ---- ARP ----
net.ipv4.neigh.default.gc_thresh1    = 512
net.ipv4.neigh.default.gc_thresh2    = 2048
net.ipv4.neigh.default.gc_thresh3    = 16384
net.ipv4.neigh.default.gc_stale_time = 60
net.ipv4.conf.default.arp_announce   = 2
net.ipv4.conf.all.arp_announce       = 2

# ---- Hardening ----
net.ipv4.conf.all.rp_filter               = 2
net.ipv4.conf.default.rp_filter           = 2
net.ipv4.conf.all.accept_redirects        = 0
net.ipv4.conf.default.accept_redirects    = 0
net.ipv4.conf.all.send_redirects          = 0
net.ipv4.conf.all.accept_source_route     = 0
net.ipv4.conf.default.accept_source_route = 0

# ---- IPv6 ----
net.ipv6.conf.all.disable_ipv6     = 0
net.ipv6.conf.default.disable_ipv6 = 0

# ---- Unix sockets ----
net.unix.max_dgram_qlen = 256

# ---- Virtual memory ----
vm.swappiness              = ${SWAPPINESS}
vm.dirty_ratio             = 15
vm.dirty_background_ratio  = 5
vm.dirty_expire_centisecs  = 3000
vm.dirty_writeback_centisecs = 500
vm.min_free_kbytes         = 65536
vm.vfs_cache_pressure      = 100

# ---- Kernel ----
kernel.printk = 4 4 1 7
kernel.panic  = 1
EOF

  sysctl_apply

  if [[ "$OPEN_BBR_CHECK" == "1" && "${CC:-none}" != "none" ]]; then
    if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw "$CC"; then
      info "Congestion control '$CC' confirmed."
    else
      warn "'$CC' not in available list. Kernel: $(uname -r)"
      warn "Available: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo '?')"
    fi
  fi
}

# ----- CC + Qdisc runtime -----
action_qdisc_cc(){
  [[ "${CC:-none}" == "none" ]] && { warn "CC=none; skipping."; return 0; }
  log "Applying CC=$CC | QDISC=$QDISC"
  sysctl_set "net.ipv4.tcp_congestion_control" "$CC"
  sysctl_set "net.core.default_qdisc" "$QDISC"
  sysctl_apply
  apply_qdisc_runtime
}

# ----- FIX: Persist qdisc across reboots via systemd service -----
action_qdisc_persist(){
  [[ "${CC:-none}" == "none" ]] && return 0
  local iface; iface="$(detect_iface || true)"
  [[ -z "$iface" ]] && { warn "Cannot detect iface; qdisc service not created."; return 0; }

  cat >/etc/systemd/system/tc-qdisc.service <<EOF
[Unit]
Description=Apply tc qdisc on boot (vps-optimizer: ${QDISC} on ${iface})
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/sbin/tc qdisc del dev ${iface} root
ExecStart=/sbin/tc qdisc add dev ${iface} root ${QDISC}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable tc-qdisc.service >/dev/null 2>&1
  info "tc-qdisc.service enabled — $QDISC will be applied on $iface after each reboot."
}

# ----- File limits -----
action_limits(){
  log "Setting system-wide open-file limits"
  cat >/etc/security/limits.d/99-xray-tune.conf <<'EOF'
* soft nproc  655350
* hard nproc  655350
* soft nofile 10485760
* hard nofile 10485760
root soft nproc  655350
root hard nproc  655350
root soft nofile 10485760
root hard nofile 10485760
EOF
  ulimit -n 10485760 2>/dev/null || true
}

# ----- Systemd overrides for Xray-related services -----
action_xray_systemd_limits(){
  local all_svcs
  all_svcs="$(detect_xray_services)"

  if [[ -z "${all_svcs// }" ]]; then
    warn "No Xray/panel services found. Skipping systemd overrides."
    return 0
  fi

  log "Detected services: $all_svcs"

  for svc in $all_svcs; do
    local drop_dir="/etc/systemd/system/${svc}.d"
    mkdir -p "$drop_dir"
    cat >"${drop_dir}/99-xray-limits.conf" <<'EOF'
[Service]
LimitNOFILE=10485760
LimitNPROC=1048576
TasksMax=infinity
OOMScoreAdjust=-500
Restart=on-failure
RestartSec=5s
EOF
    info "Override → ${drop_dir}/99-xray-limits.conf"
  done

  systemctl daemon-reload

  for svc in $all_svcs; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      systemctl reload "$svc" 2>/dev/null \
        || systemctl restart "$svc" 2>/dev/null \
        || warn "Could not reload/restart $svc"
      info "$svc reloaded."
    fi
  done
}

# ----- MSS clamping -----
action_mss_clamp(){
  [[ "$APPLY_MSS_CLAMP" == "1" ]] || return 0
  command -v iptables >/dev/null 2>&1 || { warn "iptables not found."; return 0; }
  log "Applying MSS clamping (PMTU + ${MSS_VALUE})"
  for chain in FORWARD OUTPUT; do
    iptables -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
      || iptables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN \
           -j TCPMSS --clamp-mss-to-pmtu
    iptables -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --set-mss "$MSS_VALUE" >/dev/null 2>&1 \
      || iptables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN \
           -j TCPMSS --set-mss "$MSS_VALUE"

    if command -v ip6tables >/dev/null 2>&1; then
      ip6tables -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
        || ip6tables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN \
             -j TCPMSS --clamp-mss-to-pmtu
      ip6tables -t mangle -C "$chain" -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "$MSS_VALUE" >/dev/null 2>&1 \
        || ip6tables -t mangle -A "$chain" -p tcp --tcp-flags SYN,RST SYN \
             -j TCPMSS --set-mss "$MSS_VALUE"
    fi
  done
  iptables_persistent_installed && save_iptables_rules \
    || warn "iptables-persistent not installed; rules lost on reboot."
}

# ----- NTP -----
action_chrony_ntp(){
  log "Configuring Chrony NTP"
  command -v chronyd >/dev/null 2>&1 || { warn "chrony not installed; skipping."; return 0; }
  backup_file /etc/chrony/chrony.conf
  grep -q "time.cloudflare.com" /etc/chrony/chrony.conf 2>/dev/null \
    || cat >>/etc/chrony/chrony.conf <<'EOF'

# Added by vps-optimizer
pool pool.ntp.org iburst maxsources 4
server time.cloudflare.com iburst
server time.google.com iburst
EOF
  systemctl enable chrony >/dev/null 2>&1 || true
  systemctl restart chrony
  chronyc makestep >/dev/null 2>&1 || true
  info "Chrony NTP configured."
}

# ----- Entropy -----
action_haveged(){
  log "Enabling haveged (entropy daemon for fast TLS)"
  command -v haveged >/dev/null 2>&1 || { warn "haveged not installed; skipping."; return 0; }
  systemctl enable haveged >/dev/null 2>&1 || true
  systemctl restart haveged
  info "haveged running."
}

# ================================================================
#  BENCHMARK — قبل و بعد از اعمال تنظیمات
# ================================================================
action_benchmark(){
  local label="$1"
  local bench_log="/var/log/vps-bench.log"

  echo "======================================" >> "$bench_log"
  echo "  Benchmark: $label — $(date)"          >> "$bench_log"
  echo "======================================" >> "$bench_log"

  # latency به 1.1.1.1
  echo "--- Latency (1.1.1.1) ---"              >> "$bench_log"
  ping -c 5 -W 2 1.1.1.1 2>/dev/null | tail -2 >> "$bench_log" || true

  # TCP CC
  echo "--- CC / QDISC ---"                     >> "$bench_log"
  sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null >> "$bench_log" || true
  sysctl -n net.core.default_qdisc 2>/dev/null          >> "$bench_log" || true

  # open files
  echo "--- Open file limit ---"                >> "$bench_log"
  ulimit -n 2>/dev/null                         >> "$bench_log" || true

  # memory
  echo "--- Memory ---"                         >> "$bench_log"
  free -m 2>/dev/null | head -2                 >> "$bench_log" || true

  echo "" >> "$bench_log"
  info "Benchmark [$label] saved to $bench_log"
}

# ================================================================
#  STATUS
# ================================================================
action_status(){
  log "===== Status Summary ====="
  printf "  %-22s %s\n" "Kernel:"        "$(uname -r)"
  printf "  %-22s %s\n" "Interface:"     "$(detect_iface 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "CC available:"  "$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "CC active:"     "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "QDISC:"         "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "Swappiness:"    "$(sysctl -n vm.swappiness 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "Conntrack max:" "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "Open files:"    "$(ulimit -n 2>/dev/null || echo '?')"
  printf "  %-22s %s\n" "GRUB profile:"  "${GRUB_PROFILE:-not set}"
  printf "  %-22s %s\n" "Log file:"      "${LOG_FILE}"
  echo
  echo "--- DNS ---"
  resolvectl status 2>/dev/null | grep -E "DNS Servers|Current DNS" | head -5 || \
    cat /etc/resolv.conf 2>/dev/null | grep nameserver | head -3 || echo "(unknown)"
  echo
  echo "--- Swap ---"
  swapon --show 2>/dev/null || echo "(none)"
  echo
  echo "--- tc qdisc ---"
  tc qdisc show 2>/dev/null | head -10 || true
  echo
  echo "--- Detected Xray/panel services ---"
  local svcs; svcs="$(detect_xray_services)"
  if [[ -n "${svcs// }" ]]; then
    for s in $svcs; do
      local st; st=$(systemctl is-active "$s" 2>/dev/null || echo "not-found")
      printf "  %-35s %s\n" "$s" "$st"
    done
  else
    echo "  (none detected)"
  fi
  echo
  if [[ -f /var/log/vps-bench.log ]]; then
    echo "--- Last benchmark ---"
    tail -20 /var/log/vps-bench.log
  fi
}

# ================================================================
#  RESTORE — بازگشت به آخرین بکاپ‌ها
# ================================================================
action_restore(){
  log "Restoring from latest backups..."

  local restored=0
  local targets=(
    /etc/systemd/resolved.conf
    /etc/default/grub
    /etc/chrony/chrony.conf
    /etc/apt/sources.list
    /etc/apt/sources.list.d/ubuntu.sources
  )

  for f in "${targets[@]}"; do
    # پیدا کردن آخرین بکاپ
    local latest
    latest=$(ls -t "${f}.bak."* 2>/dev/null | head -1 || echo "")
    if [[ -n "$latest" ]]; then
      # unlock در صورت immutable بودن
      chattr -i "$f" 2>/dev/null || true
      cp -a "$latest" "$f"
      info "Restored: $f ← $latest"
      (( restored++ ))
    fi
  done

  # حذف فایل‌های اضافه‌شده توسط اسکریپت
  local extra_files=(
    /etc/sysctl.d/99-xray-tune.conf
    /etc/security/limits.d/99-xray-tune.conf
    /etc/cloud/cloud.cfg.d/99-disable-dns.cfg
    /etc/NetworkManager/conf.d/99-dns-none.conf
    /etc/systemd/system/dns-enforce.service
    /etc/systemd/system/tc-qdisc.service
    /etc/modules-load.d/nf_conntrack.conf
  )
  for ef in "${extra_files[@]}"; do
    if [[ -f "$ef" ]]; then
      rm -f "$ef"
      info "Removed: $ef"
      (( restored++ ))
    fi
  done

  # حذف CC module configs
  rm -f /etc/modules-load.d/tcp_bbr.conf \
        /etc/modules-load.d/tcp_bbr2.conf \
        /etc/modules-load.d/tcp_hybla.conf 2>/dev/null || true

  systemctl daemon-reload
  systemctl disable dns-enforce.service 2>/dev/null || true
  systemctl disable tc-qdisc.service    2>/dev/null || true

  # re-apply grub اگه restore شد
  if [[ -f /etc/default/grub ]]; then
    command -v update-grub >/dev/null 2>&1 && update-grub 2>/dev/null || true
  fi

  sysctl_apply

  if (( restored > 0 )); then
    info "Restore complete. $restored items restored/removed."
    warn "Reboot recommended to fully revert kernel/GRUB changes."
  else
    warn "No backups found to restore."
  fi
}

# ================================================================
#  MAIN
# ================================================================
run_all(){
  log "======= Xray VPS Full Auto-Tune Started ======="
  info "Full log: $LOG_FILE"

  # --- Benchmark قبل از تغییرات ---
  action_benchmark "before"

  # Phase 1: همه سوال‌ها
  ask_server_location
  ask_swap_size
  ask_bbr_qdisc
  ask_grub_profile

  echo
  log "All answers collected. Applying settings now..."
  echo

  # Phase 2: اجرا
  action_dns
  action_dns_persist        # FIX: DNS persistence
  action_iran_mirror
  action_install_tools
  action_swap
  action_grub
  action_sysctl_xray        # nf_conntrack + CC module + sysctl
  action_qdisc_cc
  action_qdisc_persist      # FIX: qdisc persist across reboots
  action_limits
  action_xray_systemd_limits
  action_chrony_ntp
  action_haveged
  install_iptables_persistent
  action_mss_clamp
  save_iptables_rules

  log "======= All done ======="

  # --- Benchmark بعد از تغییرات ---
  action_benchmark "after"

  action_status

  echo
  echo -e "${MAGENTA}+-----------------------------------------------------+${NC}"
  echo -e "${MAGENTA}|  Reboot recommended to fully apply GRUB + kernel   |${NC}"
  echo -e "${MAGENTA}|  changes.  Run:  reboot                            |${NC}"
  echo -e "${MAGENTA}|                                                     |${NC}"
  echo -e "${MAGENTA}|  Recommendation: For best Xray/Accounting speed,   |${NC}"
  echo -e "${MAGENTA}|  install XanMod Kernel (which supports BBRv3).     |${NC}"
  echo -e "${MAGENTA}|                                                     |${NC}"
  echo -e "${MAGENTA}|  Log saved to: ${LOG_FILE}  |${NC}"
  echo -e "${MAGENTA}+-----------------------------------------------------+${NC}"
}

main(){
  need_root
  is_debian_like || die "Requires Debian/Ubuntu (apt-based)."

  # راه‌اندازی لاگ‌فایل بعد از تأیید root
  exec > >(tee -a "$LOG_FILE") 2>&1

  case "${1:-}" in
    --restore) action_restore ;;
    --status)  action_status  ;;
    --dns)
      ask_server_location
      action_dns
      action_dns_persist
      ;;
    *) run_all ;;
  esac
}

main "$@"
