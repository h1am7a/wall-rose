#!/usr/bin/env bash
# ==============================================================================
# Wall Rose (ウォール・ローゼ) Multi-Protocol Personal VPN Gateway — Installer
# Supported OS: Ubuntu 24.04 LTS, Ubuntu 26.04 LTS, Debian 12 (Bookworm)
# Architecture: x86_64 (amd64) / aarch64 (arm64)
# Stack: Userspace AmneziaWG (amneziawg-go) + Hysteria 2 (single UDP 443)
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

# 2. System Packages & Prerequisites (Pure Userspace — NO kernel modules / dkms)
log_info "Updating system package repositories..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  curl wget git tar gzip openssl \
  python3 python3-pip python3-venv python3-setuptools python3-cryptography \
  iptables iptables-persistent netfilter-persistent \
  unbound qrencode ca-certificates gnupg \
  software-properties-common build-essential || true

if [[ "$OS_ID" == "ubuntu" ]]; then
  # Official Launchpad PPA native to Ubuntu for awg CLI tools
  add-apt-repository -y ppa:amnezia/ppa || true
  apt-get update -y
  apt-get install -y amneziawg-tools wireguard-tools || true
else
  apt-get install -y wireguard-tools || true
fi

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

# 4. Userspace AmneziaWG (amneziawg-go) Setup
log_info "Configuring AmneziaWG userspace engine (amneziawg-go)..."

# Detect pre-installed official userspace binary
if [[ -f /usr/local/bin/amneziawg-go-official && ! -f /usr/local/bin/amneziawg-go ]]; then
  ln -sf /usr/local/bin/amneziawg-go-official /usr/local/bin/amneziawg-go
fi

# If binary is missing, compile amneziawg-go from official source
if ! command -v amneziawg-go &>/dev/null && [[ ! -f /usr/local/bin/amneziawg-go && ! -f /usr/local/bin/amneziawg-go-official ]]; then
  log_info "Compiling amneziawg-go userspace binary from official repository..."
  apt-get install -y golang-go make git || true
  TMP_GO_DIR=$(mktemp -d)
  if git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git "$TMP_GO_DIR" 2>/dev/null; then
    (cd "$TMP_GO_DIR" && make && cp amneziawg-go /usr/local/bin/amneziawg-go && chmod +x /usr/local/bin/amneziawg-go) || true
  fi
  rm -rf "$TMP_GO_DIR"
fi

if [[ -f /usr/local/bin/amneziawg-go-official && ! -f /usr/local/bin/amneziawg-go ]]; then
  ln -sf /usr/local/bin/amneziawg-go-official /usr/local/bin/amneziawg-go
fi

# Deploy robust userspace daemon runner script
cat > /usr/local/bin/awg-go-service << 'EOF'
#!/usr/bin/env bash
set -e
IFACE="$1"
CONF="$2"
ADDR="$3"

mkdir -p /var/run/wireguard /var/run/amneziawg
ip link delete dev "$IFACE" 2>/dev/null || true

AWG_GO=$(command -v amneziawg-go || echo "/usr/local/bin/amneziawg-go")
if [ ! -x "$AWG_GO" ] && [ -x /usr/local/bin/amneziawg-go-official ]; then
  AWG_GO="/usr/local/bin/amneziawg-go-official"
fi

# Start userspace amneziawg-go in foreground inside managed process
"$AWG_GO" -f "$IFACE" &
DAEMON_PID=$!

cleanup() {
  kill "$DAEMON_PID" 2>/dev/null || true
  ip link delete dev "$IFACE" 2>/dev/null || true
  rm -f "/var/run/wireguard/${IFACE}.sock" "/var/run/amneziawg/${IFACE}.sock" "/var/run/${IFACE}.sock" 2>/dev/null || true
}
trap cleanup SIGINT SIGTERM EXIT

# Wait for UAPI domain socket to appear
for i in {1..40}; do
  if [ -S "/var/run/wireguard/${IFACE}.sock" ] || [ -S "/var/run/amneziawg/${IFACE}.sock" ] || [ -S "/var/run/${IFACE}.sock" ]; then
    break
  fi
  sleep 0.1
done

# Ensure UAPI sockets exist in all candidate locations for zero-hang queries
if [ -S "/var/run/wireguard/${IFACE}.sock" ]; then
  ln -sf "/var/run/wireguard/${IFACE}.sock" "/var/run/amneziawg/${IFACE}.sock" 2>/dev/null || true
  ln -sf "/var/run/wireguard/${IFACE}.sock" "/var/run/${IFACE}.sock" 2>/dev/null || true
elif [ -S "/var/run/amneziawg/${IFACE}.sock" ]; then
  ln -sf "/var/run/amneziawg/${IFACE}.sock" "/var/run/wireguard/${IFACE}.sock" 2>/dev/null || true
  ln -sf "/var/run/amneziawg/${IFACE}.sock" "/var/run/${IFACE}.sock" 2>/dev/null || true
fi

# Configure interface via awg / wg CLI (strip quick-only Address/MTU/DNS to prevent setconf abort)
CLEAN_CONF=$(mktemp)
grep -vE '^[[:space:]]*(Address|MTU|DNS)[[:space:]]*=' "$CONF" > "$CLEAN_CONF"

if command -v awg &>/dev/null; then
  awg setconf "$IFACE" "$CLEAN_CONF"
elif command -v wg &>/dev/null; then
  wg setconf "$IFACE" "$CLEAN_CONF"
else
  echo "[FATAL] Neither awg nor wg binary found to configure $IFACE" >&2
  rm -f "$CLEAN_CONF"
  exit 1
fi
rm -f "$CLEAN_CONF"

ip address replace "$ADDR" dev "$IFACE" 2>/dev/null || ip address add "$ADDR" dev "$IFACE" 2>/dev/null || true
ip link set mtu 1280 up dev "$IFACE" 2>/dev/null || true

wait "$DAEMON_PID"
EOF
chmod +x /usr/local/bin/awg-go-service

# Deploy systemd units for awg0-go and awg1-go
cat > /etc/systemd/system/awg0-go.service << EOF
[Unit]
Description=AmneziaWG Userspace Daemon (awg0)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/awg-go-service awg0 /etc/amnezia/amneziawg/awg0-userspace.conf 10.8.0.1/24
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/awg1-go.service << EOF
[Unit]
Description=AmneziaWG Userspace Daemon (awg1)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/awg-go-service awg1 /etc/amnezia/amneziawg/awg1-userspace.conf 10.9.0.1/24
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

log_ok "AmneziaWG userspace units configured."

# 5. Cryptographically Random Server Configuration Generation
log_info "Generating cryptographically random server parameters and configurations..."
mkdir -p /etc/amnezia/amneziawg /etc/hysteria
chmod 700 /etc/amnezia/amneziawg /etc/hysteria

PANEL_PORT="${PORT:-8000}"
export PANEL_PORT
export PUBLIC_IP

python3 - << 'PYEOF'
import os, sys, secrets, base64, re

def gen_x25519_keypair():
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        priv = x25519.X25519PrivateKey.generate()
        priv_b64 = base64.b64encode(priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )).decode("ascii")
        pub_b64 = base64.b64encode(priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode("ascii")
        return priv_b64, pub_b64
    except Exception:
        import subprocess
        for tool in ["awg", "wg"]:
            try:
                res = subprocess.run([tool, "genkey"], capture_output=True, text=True, check=True)
                priv_b64 = res.stdout.strip()
                res_pub = subprocess.run([tool, "pubkey"], input=priv_b64, capture_output=True, text=True, check=True)
                pub_b64 = res_pub.stdout.strip()
                return priv_b64, pub_b64
            except Exception:
                continue
        der = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"], capture_output=True, check=True).stdout
        priv_b64 = base64.b64encode(der[-32:]).decode("ascii")
        pub_der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=der, capture_output=True, check=True).stdout
        pub_b64 = base64.b64encode(pub_der[-32:]).decode("ascii")
        return priv_b64, pub_b64

def derive_pubkey_from_priv(priv_b64):
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives import serialization
        priv_bytes = base64.b64decode(priv_b64)
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        return base64.b64encode(priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode("ascii")
    except Exception:
        import subprocess
        for tool in ["awg", "wg"]:
            try:
                res = subprocess.run([tool, "pubkey"], input=priv_b64, capture_output=True, text=True, check=True)
                return res.stdout.strip()
            except Exception:
                pass
        return ""

def get_free_udp_port(exclude_ports=None):
    import socket
    import random
    exclude = set(exclude_ports or [])
    ports = [p for p in range(40000, 60001) if p not in exclude]
    random.shuffle(ports)
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(('', p))
                return str(p)
        except OSError:
            continue
    raise RuntimeError("No free UDP port found in 40000-60000 range")

def gen_collision_free_s():
    while True:
        s1 = secrets.randbelow(181) + 20
        s2 = secrets.randbelow(181) + 20
        s3 = secrets.randbelow(181) + 20
        s4 = secrets.randbelow(181) + 20
        if len({148 + s1, 92 + s2, 64 + s3, 32 + s4}) == 4:
            return str(s1), str(s2), str(s3), str(s4)

# --- AWG0 (v2) Configuration ---
awg0_conf = "/etc/amnezia/amneziawg/awg0-userspace.conf"
awg0_priv, awg0_pub = gen_x25519_keypair()
awg0_port = get_free_udp_port()
awg0_jc = str(secrets.randbelow(9) + 4)          # 4..12 (Amnezia recommended)
awg0_jmin = str(secrets.randbelow(21) + 10)       # 10..30
awg0_jmax = str(secrets.randbelow(51) + 40)       # 40..90 (< 1280 MTU)
awg0_s1, awg0_s2, awg0_s3, awg0_s4 = gen_collision_free_s()
awg0_h1 = str(secrets.randbelow(1000000000) + 1000000000)
awg0_h2 = str(secrets.randbelow(1000000000) + 1000000000)
awg0_h3 = str(secrets.randbelow(1000000000) + 1000000000)
awg0_h4 = str(secrets.randbelow(1000000000) + 1000000000)

with open(awg0_conf, "w", encoding="utf-8") as f:
    f.write(f"""[Interface]
Address = 10.8.0.1/24
ListenPort = {awg0_port}
PrivateKey = {awg0_priv}
Jc = {awg0_jc}
Jmin = {awg0_jmin}
Jmax = {awg0_jmax}
S1 = {awg0_s1}
S2 = {awg0_s2}
S3 = {awg0_s3}
S4 = {awg0_s4}
H1 = {awg0_h1}
H2 = {awg0_h2}
H3 = {awg0_h3}
H4 = {awg0_h4}
""")
os.chmod(awg0_conf, 0o600)

# --- AWG1 (v3) Configuration ---
awg1_conf = "/etc/amnezia/amneziawg/awg1-userspace.conf"
awg1_priv, awg1_pub = gen_x25519_keypair()
awg1_port = get_free_udp_port(exclude_ports={int(awg0_port)})
awg1_jc = str(secrets.randbelow(9) + 4)          # 4..12 (Amnezia recommended)
awg1_jmin = str(secrets.randbelow(21) + 10)       # 10..30
awg1_jmax = str(secrets.randbelow(51) + 40)       # 40..90 (< 1280 MTU)
awg1_s1, awg1_s2, awg1_s3, awg1_s4 = gen_collision_free_s()
awg1_h1 = str(secrets.randbelow(1000000000) + 1000000000)
awg1_h2 = str(secrets.randbelow(1000000000) + 1000000000)
awg1_h3 = str(secrets.randbelow(1000000000) + 1000000000)
awg1_h4 = str(secrets.randbelow(1000000000) + 1000000000)
awg1_hpk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
awg1_cpa = "32-128"

with open(awg1_conf, "w", encoding="utf-8") as f:
    f.write(f"""[Interface]
Address = 10.9.0.1/24
ListenPort = {awg1_port}
PrivateKey = {awg1_priv}
Jc = {awg1_jc}
Jmin = {awg1_jmin}
Jmax = {awg1_jmax}
S1 = {awg1_s1}
S2 = {awg1_s2}
S3 = {awg1_s3}
S4 = {awg1_s4}
H1 = {awg1_h1}
H2 = {awg1_h2}
H3 = {awg1_h3}
H4 = {awg1_h4}
HeaderProtectionKey = {awg1_hpk}
ContentPaddingAddition = 32-128
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
""")
os.chmod(awg1_conf, 0o600)

# --- Hysteria 2 Configuration ---
hy2_conf = "/etc/hysteria/config.yaml"
hy2_port = "443"
gecko_key = secrets.token_hex(16)
panel_port = os.environ.get("PANEL_PORT", "8000")

with open(hy2_conf, "w", encoding="utf-8") as f:
    f.write(f"""listen: :{hy2_port}

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 120s
  maxIncomingStreams: 1024

bandwidth:
  up: 500 mbps
  down: 500 mbps

ignoreClientBandwidth: true

obfs:
  type: gecko
  gecko:
    password: {gecko_key}
    minPacketSize: 512
    maxPacketSize: 1200

auth:
  type: http
  http:
    url: http://127.0.0.1:{panel_port}/api/v1/hysteria/auth

trafficStats:
  listen: 127.0.0.1:9999
""")
os.chmod(hy2_conf, 0o600)

# Export variables to shell environment
with open("/tmp/wallrose_env_vars.sh", "w", encoding="utf-8") as f:
    f.write(f"""
export AWG0_SERVER_PRIVKEY='{awg0_priv}'
export AWG0_SERVER_PUBKEY='{awg0_pub}'
export AWG0_PORT='{awg0_port}'
export AWG0_JC='{awg0_jc}'
export AWG0_JMIN='{awg0_jmin}'
export AWG0_JMAX='{awg0_jmax}'
export AWG0_S1='{awg0_s1}'
export AWG0_S2='{awg0_s2}'
export AWG0_S3='{awg0_s3}'
export AWG0_S4='{awg0_s4}'
export AWG0_H1='{awg0_h1}'
export AWG0_H2='{awg0_h2}'
export AWG0_H3='{awg0_h3}'
export AWG0_H4='{awg0_h4}'

export AWG1_SERVER_PRIVKEY='{awg1_priv}'
export AWG1_SERVER_PUBKEY='{awg1_pub}'
export AWG1_PORT='{awg1_port}'
export AWG1_JC='{awg1_jc}'
export AWG1_JMIN='{awg1_jmin}'
export AWG1_JMAX='{awg1_jmax}'
export AWG1_S1='{awg1_s1}'
export AWG1_S2='{awg1_s2}'
export AWG1_S3='{awg1_s3}'
export AWG1_S4='{awg1_s4}'
export AWG1_H1='{awg1_h1}'
export AWG1_H2='{awg1_h2}'
export AWG1_H3='{awg1_h3}'
export AWG1_H4='{awg1_h4}'
export AWG1_HEADER_PROTECTION_KEY='{awg1_hpk}'
export AWG1_CONTENT_PADDING_ADDITION='{awg1_cpa}'

export HY2_PORT='{hy2_port}'
export GECKO_OBFS_KEY='{gecko_key}'
""")
PYEOF

source /tmp/wallrose_env_vars.sh
rm -f /tmp/wallrose_env_vars.sh
log_ok "Configurations and random cryptographic parameters initialized."

# 6. Hysteria 2 Binary & Self-Signed TLS Certificate
log_info "Verifying Hysteria 2 daemon binary..."
HY2_VERSION="v2.13.0"
HY2_URL="https://github.com/apernet/hysteria/releases/download/app%2F${HY2_VERSION}/hysteria-linux-${HY2_ARCH}"

mkdir -p /etc/hysteria /var/log/hysteria
if [[ ! -f /usr/local/bin/hysteria ]]; then
  curl -fsSL "$HY2_URL" -o /usr/local/bin/hysteria || {
    log_warn "Direct download failed. Attempting official get script..."
    bash <(curl -fsSL https://get.hy2.sh/) || true
  }
  chmod +x /usr/local/bin/hysteria 2>/dev/null || true
fi

# Self-signed RSA-2048 Certificate generation with IP SAN (DNS first, IP second)
if [[ ! -f /etc/hysteria/server.crt || ! -f /etc/hysteria/server.key ]]; then
  log_info "Generating self-signed RSA-2048 TLS certificate with IP SAN ($PUBLIC_IP)..."
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/hysteria/server.key \
    -out /etc/hysteria/server.crt \
    -days 3650 \
    -subj "/CN=gateway.cloudflare.com" \
    -addext "subjectAltName=DNS:gateway.cloudflare.com,IP:$PUBLIC_IP" > /dev/null 2>&1
  chmod 600 /etc/hysteria/server.key
  chmod 644 /etc/hysteria/server.crt
fi

# 7. Unbound Local DNS Resolver (AppArmor Guard & IP Freebind)
log_info "Configuring Unbound DoT DNS resolver (10.8.0.1 / 10.9.0.1)..."

mkdir -p /etc/apparmor.d/local
if [ ! -f /etc/apparmor.d/local/usr.sbin.unbound ]; then
  echo "capability net_admin," > /etc/apparmor.d/local/usr.sbin.unbound
elif ! grep -q "capability net_admin" /etc/apparmor.d/local/usr.sbin.unbound; then
  echo "capability net_admin," >> /etc/apparmor.d/local/usr.sbin.unbound
fi

if command -v apparmor_parser &>/dev/null && [ -f /etc/apparmor.d/usr.sbin.unbound ]; then
  apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
fi
if command -v aa-complain &>/dev/null && [ -f /etc/apparmor.d/usr.sbin.unbound ]; then
  aa-complain /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
fi

cat > /etc/unbound/unbound.conf.d/wallrose.conf << 'EOF'
server:
  interface: 10.8.0.1
  interface: 10.9.0.1
  interface: 127.0.0.1
  port: 53
  ip-freebind: yes
  so-rcvbuf: 4m
  so-sndbuf: 4m
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

systemctl restart unbound || log_warn "Unbound restart pending tunnel initialization."

# 8. Netfilter Firewall & MSS Clamping (NO Port Hopping)
log_info "Configuring iptables NAT and MSS Clamping..."

# Purge any legacy port-hopping redirect rule
iptables -t nat -D PREROUTING -i "$WAN_IF" -p udp --dport 20000:50000 -j REDIRECT --to-ports 4433 2>/dev/null || true
iptables -t nat -D PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 4433 2>/dev/null || true

# Enable NAT Masquerade for VPN Subnets
iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE

iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$WAN_IF" -j MASQUERADE

# TCP MSS Clamping to prevent packet fragmentation on mobile links
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

# Allow incoming protocol ports
iptables -C INPUT -p udp --dport "$AWG0_PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$AWG0_PORT" -j ACCEPT 2>/dev/null || true
iptables -C INPUT -p udp --dport "$AWG1_PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$AWG1_PORT" -j ACCEPT 2>/dev/null || true
iptables -C INPUT -p udp --dport "$HY2_PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$HY2_PORT" -j ACCEPT 2>/dev/null || true
iptables -C INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$PANEL_PORT" -j ACCEPT 2>/dev/null || true

netfilter-persistent save 2>/dev/null || true
log_ok "Firewall rules activated and persisted."

# 9. Deploy Wall Rose Python Backend
if [[ -d "backend" && -d "static" ]]; then
  INSTALL_DIR="${INSTALL_DIR:-$(pwd)}"
  SOURCE_DIR="."
else
  INSTALL_DIR="${INSTALL_DIR:-$HOME/wallrose}"
  log_info "Fetching Wall Rose repository from GitHub (https://github.com/h1am7a/wall-rose)..."
  TMP_REPO=$(mktemp -d)
  git clone --depth 1 https://github.com/h1am7a/wall-rose.git "$TMP_REPO"
  SOURCE_DIR="$TMP_REPO"
fi

log_info "Installing Wall Rose backend to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR/backend/data"
if [[ "$SOURCE_DIR" != "$INSTALL_DIR" ]]; then
  cp -r "$SOURCE_DIR/backend"/* "$INSTALL_DIR/backend/"
  cp -r "$SOURCE_DIR/static" "$INSTALL_DIR/"
fi
if [[ -n "${TMP_REPO:-}" && -d "${TMP_REPO:-}" ]]; then
  rm -rf "$TMP_REPO"
fi

# Create isolated Python virtual environment (PEP 668 compliant)
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"

# Admin Master Password & Session Secret Token
EXISTING_ADMIN_PASS=""
EXISTING_SECRET_KEY=""
if [[ -f "$INSTALL_DIR/backend/.env" ]]; then
  EXISTING_ADMIN_PASS=$(grep -E '^[[:space:]]*ADMIN_PASSWORD=' "$INSTALL_DIR/backend/.env" | cut -d'=' -f2- | tr -d ' "\r\n' || true)
  EXISTING_SECRET_KEY=$(grep -E '^[[:space:]]*SECRET_KEY=' "$INSTALL_DIR/backend/.env" | cut -d'=' -f2- | tr -d ' "\r\n' || true)
fi

if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
  ADMIN_PASS="$ADMIN_PASSWORD"
elif [[ -n "${EXISTING_ADMIN_PASS:-}" ]]; then
  ADMIN_PASS="$EXISTING_ADMIN_PASS"
else
  ADMIN_PASS=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 16)
fi

if [[ -n "${SECRET_KEY:-}" ]]; then
  SECRET_TOKEN="$SECRET_KEY"
elif [[ -n "${EXISTING_SECRET_KEY:-}" ]]; then
  SECRET_TOKEN="$EXISTING_SECRET_KEY"
else
  SECRET_TOKEN=$(openssl rand -hex 32)
fi

# Single Source of Truth: write exact synchronized variables to .env
cat > "$INSTALL_DIR/backend/.env" << EOF
HOST=0.0.0.0
PORT=${PANEL_PORT}
SERVER_PUBLIC_IP=${PUBLIC_IP}
ADMIN_PASSWORD=${ADMIN_PASS}
SECRET_KEY=${SECRET_TOKEN}
DATABASE_PATH=${INSTALL_DIR}/backend/data/wallrose.db

AWG0_PORT=${AWG0_PORT}
AWG0_CONFIG_PATH=/etc/amnezia/amneziawg/awg0-userspace.conf
AWG0_SERVER_PUBLIC_KEY=${AWG0_SERVER_PUBKEY}
AWG0_JC=${AWG0_JC}
AWG0_JMIN=${AWG0_JMIN}
AWG0_JMAX=${AWG0_JMAX}
AWG0_S1=${AWG0_S1}
AWG0_S2=${AWG0_S2}
AWG0_S3=${AWG0_S3}
AWG0_S4=${AWG0_S4}
AWG0_H1=${AWG0_H1}
AWG0_H2=${AWG0_H2}
AWG0_H3=${AWG0_H3}
AWG0_H4=${AWG0_H4}

AWG1_PORT=${AWG1_PORT}
AWG1_CONFIG_PATH=/etc/amnezia/amneziawg/awg1-userspace.conf
AWG1_SERVER_PUBLIC_KEY=${AWG1_SERVER_PUBKEY}
AWG1_JC=${AWG1_JC}
AWG1_JMIN=${AWG1_JMIN}
AWG1_JMAX=${AWG1_JMAX}
AWG1_S1=${AWG1_S1}
AWG1_S2=${AWG1_S2}
AWG1_S3=${AWG1_S3}
AWG1_S4=${AWG1_S4}
AWG1_H1=${AWG1_H1}
AWG1_H2=${AWG1_H2}
AWG1_H3=${AWG1_H3}
AWG1_H4=${AWG1_H4}
AWG1_HEADER_PROTECTION_KEY=${AWG1_HEADER_PROTECTION_KEY}
AWG1_CONTENT_PADDING_ADDITION=${AWG1_CONTENT_PADDING_ADDITION}

HY2_PORT=${HY2_PORT}
HY2_CONFIG_PATH=/etc/hysteria/config.yaml
HY2_OBFS_TYPE=gecko
HY2_OBFS_PASSWORD=${GECKO_OBFS_KEY}
HY2_OBFS_MIN_PACKET=512
HY2_OBFS_MAX_PACKET=1200
EOF
chmod 600 "$INSTALL_DIR/backend/.env"

# Save administrative credentials copy
WALLROSE_CONF_DIR="${WALLROSE_CONF_DIR:-$HOME/.wallrose}"
mkdir -p "$WALLROSE_CONF_DIR"
CREDENTIALS_FILE="${WALLROSE_CONF_DIR}/credentials.txt"
cat > "$CREDENTIALS_FILE" << EOF
URL: http://${PUBLIC_IP}:${PANEL_PORT}/
MASTER_PASSWORD: ${ADMIN_PASS}
HYSTERIA_PORT: ${HY2_PORT}
HYSTERIA_GECKO_KEY: ${GECKO_OBFS_KEY}
AWG0_PORT: ${AWG0_PORT}
AWG1_PORT: ${AWG1_PORT}
EOF
chmod 600 "$CREDENTIALS_FILE"

# 10. Systemd Services Deployment & Startup
log_info "Deploying systemd service units..."
cat > /etc/systemd/system/wallrose-panel.service << EOF
[Unit]
Description=Wall Rose (ウォール・ローゼ) Multi-Protocol Personal VPN Gateway Panel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/backend
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PANEL_PORT}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria 2 QUIC VPN Daemon
After=network.target network-online.target
Wants=network-online.target

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
systemctl enable --now awg0-go || true
systemctl enable --now awg1-go || true
systemctl enable --now hysteria-server || true
systemctl enable --now wallrose-panel

# 11. Final Verification & Output
sleep 2
echo ""
print_banner
echo ""
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo -e "${CLR_BOLD}Wall Rose (ウォール・ローゼ) VPN Gateway successfully deployed!${CLR_RESET}"
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo -e "  ${CLR_YELLOW}Web Panel UI:${CLR_RESET}        http://${PUBLIC_IP}:${PANEL_PORT}/"
echo -e "  ${CLR_YELLOW}Master Password:${CLR_RESET}     ${ADMIN_PASS}"
echo -e "  ${CLR_CYAN}Auth Note:${CLR_RESET}           No username required (single master password entry)"
echo -e "  ${CLR_YELLOW}OpenAPI Spec:${CLR_RESET}        http://${PUBLIC_IP}:${PANEL_PORT}/docs"
echo -e "  ${CLR_CYAN}Saved Creds:${CLR_RESET}          ${CREDENTIALS_FILE} (chmod 600)"
echo -e "${CLR_GREEN}========================================================================${CLR_RESET}"
echo ""
