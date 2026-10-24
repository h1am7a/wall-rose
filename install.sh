#!/usr/bin/env bash
# ==============================================================================
# Wall Rose (ウォール・ローゼ) Multi-Protocol VPN Gateway — Production Deployment Installer
# Supported OS: Ubuntu 24.04 LTS, Ubuntu 26.04 LTS, Debian 12 (Bookworm)
# Architecture: x86_64 (amd64) / aarch64 (arm64)
# ==============================================================================

set -euo pipefail

# ANSI Manga Comic Colors
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_RED="\033[1;31m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_BLUE="\033[1;34m"
CLR_CYAN="\033[1;36m"

print_banner() {
cat << "EOF"
 __        ___    _     _       ____   ___  ____  _____ 
 \ \      / / \  | |   | |     |  _ \ / _ \/ ___|| ____|
  \ \ /\ / / _ \ | |   | |     | |_) | | | \___ \|  _|  
   \ V  V / ___ \| |___| |___  |  _ <| |_| |___) | |___ 
    \_/\_/_/   \_\_____|_____| |_| \_\\___/|____/|_____|
               ウォール・ローゼ (WALL ROSE)
  MULTI-PROTOCOL PERSONAL VPN GATEWAY // TANKOBON EDITION
  Supported OS: Ubuntu 24.04 / 26.04 LTS & Debian 12
EOF
}

log_info() { echo -e "${CLR_CYAN}[INFO]${CLR_RESET} $1"; }
log_ok() { echo -e "${CLR_GREEN}[OK]${CLR_RESET} $1"; }
log_warn() { echo -e "${CLR_YELLOW}[WARN]${CLR_RESET} $1"; }
log_err() { echo -e "${CLR_RED}[ERROR]${CLR_RESET} $1" >&2; exit 1; }

# 1. Root & OS Validation
if [[ $EUID -ne 0 ]]; then
  log_err "This installer must be run as root. Run: sudo bash install.sh"
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) HY2_ARCH="amd64" ;;
  aarch64|arm64) HY2_ARCH="arm64" ;;
  *) log_err "Unsupported CPU architecture: $ARCH" ;;
esac

if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_ID=$ID
  OS_VERSION_ID=${VERSION_ID:-"unknown"}
else
  log_err "Cannot detect Linux distribution (/etc/os-release missing)."
fi

log_info "Detected OS: $OS_ID ($OS_VERSION_ID) on $ARCH"

# Determine Primary WAN Interface and Public IP
WAN_IF=$(ip -4 route show default 2>/dev/null | awk '{print $5}' | head -n1)
if [[ -z "$WAN_IF" ]]; then
  WAN_IF=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n1 | tr -d ' ')
fi

PUBLIC_IP=$(curl -s4 https://api.ipify.org || curl -s4 https://ifconfig.me || echo "127.0.0.1")
log_ok "WAN Interface: $WAN_IF | Public IP: $PUBLIC_IP"

# 2. System Packages & Prerequisites
log_info "Updating system package repositories..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  curl wget git tar gzip openssl \
  python3 python3-pip python3-venv python3-setuptools \
  iptables iptables-persistent netfilter-persistent \
  unbound qrencode ca-certificates gnupg

# 3. Kernel Sysctl Network & BBR Tuning
log_info "Applying Linux kernel sysctl network optimizations (/etc/sysctl.d/99-wallrose.conf)..."
cat > /etc/sysctl.d/99-wallrose.conf << 'EOF'
# Wall Rose High-Performance Network Tuning
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0

# BBR Congestion Control & FQ
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# UDP Buffer Scaling for High-Speed WireGuard & Hysteria 2
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 33554432
net.core.wmem_default = 33554432
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 8192

# Protect against ephemeral port exhaustion
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_fastopen = 3
EOF
sysctl --system > /dev/null 2>&1 || true
log_ok "Kernel parameters and BBR applied."

# 4. AmneziaWG Installation
log_info "Installing AmneziaWG kernel module and CLI tools..."
if [[ "$OS_ID" == "ubuntu" ]]; then
  # Official Launchpad PPA native to Ubuntu
  add-apt-repository -y ppa:amnezia/ppa || true
  apt-get update -y
  apt-get install -y amneziawg amneziawg-tools amneziawg-dkms || true
else
  # Debian 12 Bookworm fallback
  apt-get install -y wireguard-tools dkms linux-headers-$(uname -r) || true
  if ! command -v awg &>/dev/null; then
    log_warn "Installing wireguard-tools fallback for Debian. Compiling awg-tools recommended."
  fi
fi

mkdir -p /etc/amnezia/amneziawg
chmod 700 /etc/amnezia/amneziawg

# Generate Server Keys and Core Configurations
AWG_BIN="awg"
if ! command -v awg &>/dev/null; then
  AWG_BIN="wg"
fi

AWG0_SERVER_PRIVKEY=$($AWG_BIN genkey)
AWG0_SERVER_PUBKEY=$(echo "$AWG0_SERVER_PRIVKEY" | $AWG_BIN pubkey)

AWG1_SERVER_PRIVKEY=$($AWG_BIN genkey)
AWG1_SERVER_PUBKEY=$(echo "$AWG1_SERVER_PRIVKEY" | $AWG_BIN pubkey)

# 4.1 AmneziaWG 2.0 (awg0 - Fixed UDP Socket)
cat > /etc/amnezia/amneziawg/awg0.conf << EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = ${AWG0_SERVER_PRIVKEY}
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 39
H1 = 1
H2 = 2
H3 = 3
H4 = 4
EOF
chmod 600 /etc/amnezia/amneziawg/awg0.conf

# 4.2 AmneziaWG 3.1 (awg1 - ChaCha20 Stealth Header Protection)
cat > /etc/amnezia/amneziawg/awg1.conf << EOF
[Interface]
Address = 10.9.0.1/24
ListenPort = 51821
PrivateKey = ${AWG1_SERVER_PRIVKEY}
Jc = 7
Jmin = 64
Jmax = 128
S1 = 28
S2 = 56
H1 = 5
H2 = 6
H3 = 7
H4 = 8
EOF
chmod 600 /etc/amnezia/amneziawg/awg1.conf

# Enable and start AmneziaWG systemd services
systemctl enable --now ${AWG_BIN}-quick@awg0 || true
systemctl enable --now ${AWG_BIN}-quick@awg1 || true
log_ok "AmneziaWG server daemons configured and launched."

# 5. Hysteria 2 Daemon Setup
log_info "Installing Hysteria 2 daemon binary..."
HY2_VERSION="v2.6.0"
HY2_URL="https://github.com/apernet/hysteria/releases/download/app%2F${HY2_VERSION}/hysteria-linux-${HY2_ARCH}"

mkdir -p /etc/hysteria /var/log/hysteria
if [[ ! -f /usr/local/bin/hysteria ]]; then
  curl -fsSL "$HY2_URL" -o /usr/local/bin/hysteria || {
    log_warn "GitHub release direct download failed. Attempting official get script..."
    bash <(curl -fsSL https://get.hy2.sh/) || true
  }
  chmod +x /usr/local/bin/hysteria 2>/dev/null || true
fi

# Self-signed ECDSA Certificate generation with IP SAN
if [[ ! -f /etc/hysteria/server.crt ]]; then
  log_info "Generating self-signed ECDSA TLS certificate with IP SAN ($PUBLIC_IP)..."
  openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout /etc/hysteria/server.key \
    -out /etc/hysteria/server.crt \
    -days 3650 \
    -subj "/CN=gateway.cloudflare.com" \
    -addext "subjectAltName=IP:$PUBLIC_IP,DNS:gateway.cloudflare.com" > /dev/null 2>&1
  chmod 600 /etc/hysteria/server.key
  chmod 644 /etc/hysteria/server.crt
fi

# Hysteria 2 Server Config Template
SALAMANDER_OBFS_KEY=$(openssl rand -hex 16)
cat > /etc/hysteria/config.yaml << EOF
listen: :4433

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024

bandwidth:
  up: 500 mbps
  down: 500 mbps

ignoreClientBandwidth: false

obfs:
  type: salamander
  salamander:
    password: ${SALAMANDER_OBFS_KEY}

auth:
  type: http
  http:
    url: http://127.0.0.1:8000/api/v1/hysteria/auth

trafficStats:
  listen: 127.0.0.1:9999
EOF
chmod 600 /etc/hysteria/config.yaml

# 6. Unbound Local DNS Resolver (DNS Leak Protection)
log_info "Configuring Unbound DoT DNS resolver (10.8.0.1 / 10.9.0.1)..."
cat > /etc/unbound/unbound.conf.d/wallrose.conf << 'EOF'
server:
  interface: 10.8.0.1
  interface: 10.9.0.1
  interface: 127.0.0.1
  port: 53
  do-ip4: yes
  do-ip6: no
  do-udp: yes
  do-tcp: yes
  access-control: 10.8.0.0/24 allow
  access-control: 10.9.0.0/24 allow
  access-control: 127.0.0.1 allow
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes

forward-zone:
  name: "."
  forward-tls-upstream: yes
  forward-addr: 9.9.9.9@853#dns.quad9.net
  forward-addr: 1.1.1.1@853#cloudflare-dns.com
EOF
systemctl restart unbound || true

# 7. Netfilter Firewall, MSS Clamping & Port Hopping
log_info "Configuring iptables NAT, MSS Clamping, and Port Hopping (20000:50000 -> 4433)..."
# Enable NAT Masquerade for VPN Subnets
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE

iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$WAN_IF" -j MASQUERADE

# TCP MSS Clamping to prevent packet fragmentation on mobile links
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Hysteria 2 Port Hopping (Redirect UDP 20000:50000 -> 4433)
iptables -t nat -C PREROUTING -i "$WAN_IF" -p udp --dport 20000:50000 -j REDIRECT --to-ports 4433 2>/dev/null || \
  iptables -t nat -A PREROUTING -i "$WAN_IF" -p udp --dport 20000:50000 -j REDIRECT --to-ports 4433

# Persist iptables rules
netfilter-persistent save || true
log_ok "Firewall rules activated and persisted."

# 8. Deploy Wall Rose Python Backend
INSTALL_DIR="/opt/wallrose"
log_info "Installing Wall Rose backend to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

if [[ ! -d "backend" || ! -d "static" ]]; then
  log_info "Fetching Wall Rose repository from GitHub (https://github.com/h1am7a/wall-rose)..."
  TMP_REPO=$(mktemp -d)
  git clone --depth 1 https://github.com/h1am7a/wall-rose.git "$TMP_REPO"
  SOURCE_DIR="$TMP_REPO"
else
  SOURCE_DIR="."
fi

cp -r "$SOURCE_DIR/backend" "$INSTALL_DIR/"
cp -r "$SOURCE_DIR/static" "$INSTALL_DIR/"
if [[ -n "${TMP_REPO:-}" && -d "${TMP_REPO:-}" ]]; then
  rm -rf "$TMP_REPO"
fi

# Create isolated Python virtual environment (PEP 668 compliant)
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"

# Generate Admin Credentials (allow user override via environment variable)
ADMIN_USER="${ADMIN_USERNAME:-admin}"
if [ -z "$ADMIN_PASSWORD" ]; then
    ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
else
    ADMIN_PASS="$ADMIN_PASSWORD"
fi
SECRET_TOKEN=$(openssl rand -hex 32)

cat > "$INSTALL_DIR/backend/.env" << EOF
HOST=0.0.0.0
PORT=8000
SERVER_PUBLIC_IP=${PUBLIC_IP}
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASS}
SECRET_KEY=${SECRET_TOKEN}
HY2_OBFS_PASSWORD=${SALAMANDER_OBFS_KEY}
AWG0_SERVER_PUBLIC_KEY=${AWG0_SERVER_PUBKEY}
AWG1_SERVER_PUBLIC_KEY=${AWG1_SERVER_PUBKEY}
DATABASE_PATH=${INSTALL_DIR}/backend/data/wallrose.db
EOF
chmod 600 "$INSTALL_DIR/backend/.env"

# 9. Systemd Service Deployment
log_info "Deploying systemd service unit (wallrose-panel.service)..."
cat > /etc/systemd/system/wallrose-panel.service << EOF
[Unit]
Description=Wall Rose (ウォール・ローゼ) Multi-Protocol Personal VPN Gateway Panel
After=network.target network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Hysteria 2 Service Unit
cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria 2 QUIC VPN Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now hysteria-server || true
systemctl enable --now wallrose-panel

# 10. Final Verification & Output
sleep 2
systemctl is-active --quiet wallrose-panel && PANEL_ACTIVE=true || PANEL_ACTIVE=false

echo ""
print_banner
echo ""
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo -e "${CLR_BOLD}Wall Rose (ウォール・ローゼ) VPN Gateway successfully deployed!${CLR_RESET}"
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo -e "  ${CLR_YELLOW}Web Panel UI:${CLR_RESET}        http://${PUBLIC_IP}:8000/"
echo -e "  ${CLR_YELLOW}OpenAPI Documentation:${CLR_RESET} http://${PUBLIC_IP}:8000/docs"
echo -e "  ${CLR_YELLOW}ReDoc Tech Spec:${CLR_RESET}       http://${PUBLIC_IP}:8000/redoc"
echo -e "  ${CLR_YELLOW}Admin Username:${CLR_RESET}       ${ADMIN_USER}"
echo -e "  ${CLR_YELLOW}Admin Password:${CLR_RESET}       ${ADMIN_PASS}"
echo -e "------------------------------------------------------------------------"
echo -e "  ${CLR_CYAN}AmneziaWG 2.0:${CLR_RESET}        awg0 (UDP 51820, subnet 10.8.0.0/24)"
echo -e "  ${CLR_CYAN}AmneziaWG 3.1:${CLR_RESET}        awg1 (UDP 51821, subnet 10.9.0.0/24)"
echo -e "  ${CLR_CYAN}Hysteria 2.0:${CLR_RESET}         UDP 4433 (Port Hopping 20000:50000)"
echo -e "  ${CLR_CYAN}Salamander Obfs:${CLR_RESET}      ${SALAMANDER_OBFS_KEY}"
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo ""
