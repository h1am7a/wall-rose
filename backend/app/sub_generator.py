import json
import yaml
from typing import Dict, Any
from app.config import settings
from app.models import Peer
from app.core_manager import (
    get_server_public_key,
    get_awg_server_params,
    get_hysteria_server_params,
)

def generate_awg_client_conf(peer: Peer, version: str = "3.1", server_ip: str = None) -> str:
    """Generate raw AmneziaWG client .conf file for userspace or mobile clients."""
    ip = server_ip or settings.SERVER_PUBLIC_IP
    
    if version == "2.0":
        p = get_awg_server_params("awg0")
        pub = get_server_public_key("awg0")
        return f"""[Interface]
Address = {peer.awg0_ip}/32
PrivateKey = {peer.awg0_privkey}
DNS = 10.8.0.1, 1.1.1.1
Jc = {p['jc']}
Jmin = {p['jmin']}
Jmax = {p['jmax']}
S1 = {p['s1']}
S2 = {p['s2']}
S3 = {p['s3']}
S4 = {p['s4']}
H1 = {p['h1']}
H2 = {p['h2']}
H3 = {p['h3']}
H4 = {p['h4']}

[Peer]
PublicKey = {pub}
PresharedKey = {peer.awg0_psk}
Endpoint = {ip}:{p['port']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    else:
        # AWG 3.1 (version 3 with header protection)
        p = get_awg_server_params("awg1")
        pub = get_server_public_key("awg1")
        return f"""[Interface]
Address = {peer.awg1_ip}/32
PrivateKey = {peer.awg1_privkey}
DNS = 10.9.0.1, 1.1.1.1
Jc = {p['jc']}
Jmin = {p['jmin']}
Jmax = {p['jmax']}
S1 = {p['s1']}
S2 = {p['s2']}
S3 = {p['s3']}
S4 = {p['s4']}
H1 = {p['h1']}
H2 = {p['h2']}
H3 = {p['h3']}
H4 = {p['h4']}
HeaderProtectionKey = {p.get('header_protection_key', '')}

[Peer]
PublicKey = {pub}
PresharedKey = {peer.awg1_psk}
Endpoint = {ip}:{p['port']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

def generate_mihomo_yaml(peer: Peer, server_ip: str = None) -> str:
    """
    Generates complete Mihomo (Clash.Meta) YAML subscription matching
    the exact Trinity etalon specification with smart split routing.
    """
    ip = server_ip or settings.SERVER_PUBLIC_IP

    awg1_params = get_awg_server_params("awg1")
    awg0_params = get_awg_server_params("awg0")
    hy2_params = get_hysteria_server_params()

    awg1_server_pub = get_server_public_key("awg1")
    awg0_server_pub = get_server_public_key("awg0")

    return f"""mixed-port: 7890
tcp-concurrent: true
mode: rule
log-level: info
ipv6: false
keep-alive-interval: 30
unified-delay: false

profile:
  store-selected: true
  store-fake-ip: true

tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
  strict-route: true
  mtu: 1500

dns:
  enable: true
  prefer-h3: true
  use-hosts: true
  use-system-hosts: true
  listen: 127.0.0.1:6868
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 1.1.1.1
    - 1.0.0.1
  proxy-server-nameserver:
    - 1.1.1.1
    - 1.0.0.1
  direct-nameserver:
    - 1.1.1.1
    - 1.0.0.1
  nameserver:
    - 1.1.1.1
    - 1.0.0.1

proxies:
  - name: "AWG1-v3"
    type: wireguard
    server: {ip}
    port: {awg1_params['port']}
    ip: {peer.awg1_ip}
    ipv6: ""
    private-key: "{peer.awg1_privkey}"
    pre-shared-key: "{peer.awg1_psk}"
    allowed-ips: [0.0.0.0/0, "::/0"]
    udp: true
    mtu: 1280
    persistent-keepalive: 25
    public-key: "{awg1_server_pub}"
    amnezia-wg-option:
      version: {awg1_params['version']}
      jc: {awg1_params['jc']}
      jmin: {awg1_params['jmin']}
      jmax: {awg1_params['jmax']}
      s1: {awg1_params['s1']}
      s2: {awg1_params['s2']}
      s3: {awg1_params['s3']}
      s4: {awg1_params['s4']}
      h1: "{awg1_params['h1']}"
      h2: "{awg1_params['h2']}"
      h3: "{awg1_params['h3']}"
      h4: "{awg1_params['h4']}"
      header-protection-key: "{awg1_params['header_protection_key']}"
      content-padding-addition: {awg1_params['content_padding_addition']}
      rekey-after-time: {awg1_params['rekey_after_time']}
      rekey-timeout: {awg1_params['rekey_timeout']}
      reject-after-time: {awg1_params['reject_after_time']}
      keepalive-timeout: {awg1_params['keepalive_timeout']}
      max-handshake-attempts: {awg1_params['max_handshake_attempts']}
      random-trailers: true
      disable-cookies: true

  - name: "AWG0-v2"
    type: wireguard
    private-key: {peer.awg0_privkey}
    server: {ip}
    port: {awg0_params['port']}
    ip: {peer.awg0_ip}
    public-key: {awg0_server_pub}
    pre-shared-key: {peer.awg0_psk}
    allowed-ips: ["0.0.0.0/0", "::/0"]
    udp: true
    mtu: 1280
    persistent-keepalive: 25
    amnezia-wg-option:
      version: {awg0_params['version']}
      jc: {awg0_params['jc']}
      jmin: {awg0_params['jmin']}
      jmax: {awg0_params['jmax']}
      s1: {awg0_params['s1']}
      s2: {awg0_params['s2']}
      s3: {awg0_params['s3']}
      s4: {awg0_params['s4']}
      h1: '{awg0_params['h1']}'
      h2: '{awg0_params['h2']}'
      h3: '{awg0_params['h3']}'
      h4: '{awg0_params['h4']}'

  - name: "Hy2-gecko"
    type: hysteria2
    server: {ip}
    port: {hy2_params['port']}
    password: {peer.hy2_pass}
    obfs: gecko
    obfs-password: {hy2_params['obfs_password']}
    obfs-min-packet-size: {hy2_params['obfs_min_packet_size']}
    obfs-max-packet-size: {hy2_params['obfs_max_packet_size']}
    sni: {hy2_params['sni']}
    skip-cert-verify: true
    client-fingerprint: chrome
    bbr-profile: bbr
    handshake-timeout: 5
    alpn:
      - h3

proxy-groups:
  - name: "AUTO-FAILOVER"
    type: fallback
    disable-udp: false
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5
    lazy: false
    proxies:
      - "AWG1-v3"
      - "AWG0-v2"
      - "Hy2-gecko"

  - name: "TRINITY"
    type: select
    proxies:
      - "AUTO-FAILOVER"
      - "AWG1-v3"
      - "Hy2-gecko"
      - "AWG0-v2"

rule-providers:
  category-ru:
    type: http
    behavior: domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.yaml"
    path: ./ruleset/category-ru.yaml
    interval: 86400
  geoip-ru:
    type: http
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.yaml"
    path: ./ruleset/geoip-ru.yaml
    interval: 86400

rules:
  - RULE-SET,category-ru,DIRECT
  - DOMAIN-SUFFIX,gov.ru,DIRECT
  - RULE-SET,geoip-ru,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - IP-CIDR,198.18.0.0/15,DIRECT,no-resolve
  - MATCH,TRINITY
"""

def generate_singbox_json(peer: Peer, server_ip: str = None) -> str:
    """Generate universal Sing-box 1.9+ client profile."""
    ip = server_ip or settings.SERVER_PUBLIC_IP
    hy2_params = get_hysteria_server_params()

    cfg: Dict[str, Any] = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote-dns", "address": "tls://1.1.1.1"},
                {"tag": "local-dns", "address": "local", "detour": "direct"}
            ],
            "rules": [
                {"outbound": "any", "server": "local-dns"},
                {"clash_mode": "Global", "server": "remote-dns"}
            ],
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                "sniff": True
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "select-out",
                "outbounds": ["fallback-out", "hy2-out", "direct"]
            },
            {
                "type": "urltest",
                "tag": "fallback-out",
                "outbounds": ["hy2-out"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m"
            },
            {
                "type": "hysteria2",
                "tag": "hy2-out",
                "server": ip,
                "server_port": hy2_params["port"],
                "password": peer.hy2_pass,
                "tls": {
                    "enabled": True,
                    "server_name": hy2_params.get("sni", "gateway.cloudflare.com"),
                    "insecure": True
                },
                "obfs": {
                    "type": "gecko",
                    "password": hy2_params["obfs_password"],
                    "min_packet_size": hy2_params["obfs_min_packet_size"],
                    "max_packet_size": hy2_params["obfs_max_packet_size"],
                }
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ]
    }
    return json.dumps(cfg, indent=2)

def generate_mobile_landing_html(peer: Peer, subscription_url: str) -> str:
    """
    Renders Manga Comic Tankōbon Edition mobile landing page
    with 1-click import buttons and QR code for browser visitors.
    """
    rx = getattr(peer, "transfer_rx", 0) or 0
    tx = getattr(peer, "transfer_tx", 0) or 0
    from app.security import format_bytes
    total_data = format_bytes(rx + tx)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{peer.name} — ウォール・ローゼ (Wall Rose)</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f8f6f0;
      color: #141416;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 16px;
    }}
    .card {{
      background: #fff;
      border: 3.5px solid #141416;
      border-radius: 12px;
      box-shadow: 6px 6px 0px #141416;
      width: 100%;
      max-width: 440px;
      padding: 24px 20px;
      text-align: center;
    }}
    .title {{
      font-size: 1.6rem;
      font-weight: 900;
      text-transform: uppercase;
      letter-spacing: -0.5px;
      margin-bottom: 4px;
    }}
    .subtitle {{
      font-size: 0.85rem;
      color: #6c727f;
      margin-bottom: 20px;
    }}
    .badge {{
      display: inline-block;
      background: #e63946;
      color: #fff;
      font-weight: 800;
      font-size: 0.75rem;
      padding: 3px 8px;
      border: 2px solid #141416;
      border-radius: 4px;
      margin-bottom: 16px;
      box-shadow: 2px 2px 0px #141416;
    }}
    .btn {{
      display: block;
      width: 100%;
      padding: 14px;
      margin-bottom: 12px;
      font-size: 0.95rem;
      font-weight: 800;
      text-decoration: none;
      color: #141416;
      border: 3px solid #141416;
      border-radius: 8px;
      box-shadow: 4px 4px 0px #141416;
      transition: all 0.1s;
      cursor: pointer;
    }}
    .btn:active {{
      transform: translate(2px, 2px);
      box-shadow: 2px 2px 0px #141416;
    }}
    .btn-clash {{ background: #f39c12; color: #fff; }}
    .btn-singbox {{ background: #2980b9; color: #fff; }}
    .btn-copy {{ background: #fff; }}
    .specs {{
      margin-top: 18px;
      text-align: left;
      font-size: 0.8rem;
      border-top: 2px dashed #141416;
      padding-top: 14px;
      color: #555;
    }}
    .spec-row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">TRINITY GATEWAY</div>
    <div class="title">{peer.name}</div>
    <div class="subtitle">{peer.device_desc}</div>

    <a href="clash://install-config?url={subscription_url}" class="btn btn-clash">
      Import to Clash / Mihomo
    </a>
    <a href="sing-box://import-remote-profile?url={subscription_url}?format=json" class="btn btn-singbox">
      Import to Sing-box
    </a>
    <button onclick="navigator.clipboard.writeText('{subscription_url}'); alert('Subscription URL copied!');" class="btn btn-copy">
      Copy Subscription Link
    </button>

    <div class="specs">
      <div class="spec-row"><span>AWG 3.1 IP:</span><b>{peer.awg1_ip}</b></div>
      <div class="spec-row"><span>AWG 2.0 IP:</span><b>{peer.awg0_ip}</b></div>
      <div class="spec-row"><span>Hysteria 2:</span><b>QUIC Gecko</b></div>
      <div class="spec-row"><span>Total Data:</span><b>{total_data}</b></div>
    </div>
  </div>
</body>
</html>
"""
