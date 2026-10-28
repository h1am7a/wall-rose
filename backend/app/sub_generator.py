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
        # AWG 3.1 (version 3 with header protection and advanced stealth parameters)
        p = get_awg_server_params("awg1")
        pub = get_server_public_key("awg1")
        rt_val = p.get('random_trailers')
        rt_str = "on" if rt_val in (True, "on", "true", "1") else (rt_val or "on")
        dc_val = p.get('disable_cookies')
        dc_str = "on" if dc_val in (True, "on", "true", "1") else (dc_val or "on")

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
ContentPaddingAddition = {p.get('content_padding_addition', '32-128')}
RekeyAfterTime = {p.get('rekey_after_time', '100-120')}
RekeyTimeout = {p.get('rekey_timeout', '3-7')}
RejectAfterTime = {p.get('reject_after_time', '150-180')}
KeepaliveTimeout = {p.get('keepalive_timeout', '5-15')}
MaxHandshakeAttempts = {p.get('max_handshake_attempts', '15-20')}
RandomTrailers = {rt_str}
DisableCookies = {dc_str}

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
    keep-alive-period: 15
    alpn:
      - h3

proxy-groups:
  - name: "GLOBAL"
    type: select
    default-selected: "TRINITY"
    proxies:
      - "TRINITY"
      - "AUTO-FAILOVER"
      - "AWG1-v3"
      - "AWG0-v2"
      - "Hy2-gecko"
      - "DIRECT"

  - name: "TRINITY"
    type: select
    default-selected: "AUTO-FAILOVER"
    proxies:
      - "AUTO-FAILOVER"
      - "AWG1-v3"
      - "Hy2-gecko"
      - "AWG0-v2"

  - name: "AUTO-FAILOVER"
    type: fallback
    disable-udp: false
    url: "https://www.gstatic.com/generate_204"
    interval: 30
    timeout: 3000
    max-failed-times: 2
    lazy: false
    proxies:
      - "AWG1-v3"
      - "AWG0-v2"
      - "Hy2-gecko"

rules:
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
    import urllib.parse
    import re
    from app.security import format_bytes

    rx = getattr(peer, "transfer_rx", 0) or 0
    tx = getattr(peer, "transfer_tx", 0) or 0
    total_data = format_bytes(rx + tx)
    clean_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', peer.name).strip('_') or 'device'
    singbox_raw = f"{subscription_url}?format=json"
    singbox_target = urllib.parse.quote(singbox_raw, safe="")
    hy2_port_display = f"UDP {settings.HY2_PORT}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{peer.name} — ウォール・ローゼ (Wall Rose)</title>
  <style>
    @font-face {{
      font-family: 'Komika Axis';
      src: url('/fonts/KOMIKAX_.woff') format('woff'), url('/static/fonts/KOMIKAX_.woff') format('woff');
      font-weight: 400;
      font-style: normal;
      font-display: swap;
    }}
    @font-face {{
      font-family: 'Komika Text';
      src: url('/fonts/KOMTXT__.woff') format('woff'), url('/static/fonts/KOMTXT__.woff') format('woff');
      font-weight: 400;
      font-style: normal;
      font-display: swap;
    }}
    @font-face {{
      font-family: 'Komika Text';
      src: url('/fonts/KOMTXTB_.woff') format('woff'), url('/static/fonts/KOMTXTB_.woff') format('woff');
      font-weight: 700;
      font-style: normal;
      font-display: swap;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Komika Text', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f8f6f0;
      color: #141416;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 16px;
    }}
    .card {{
      background: #ffffff;
      border: 3.5px solid #141416;
      border-radius: 0;
      box-shadow: 6px 6px 0px #141416;
      width: 100%;
      max-width: 440px;
      padding: 20px 18px;
      text-align: center;
    }}
    .brand-bar {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      background: #e63946;
      color: #ffffff;
      border: 2.5px solid #141416;
      border-radius: 0;
      padding: 6px 14px;
      box-shadow: 3.5px 3.5px 0px #141416;
      margin-bottom: 10px;
    }}
    .manga-stamp {{
      background: #ffffff;
      color: #e63946;
      width: 22px;
      height: 22px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 0.95rem;
      font-weight: 900;
      line-height: 1;
      font-family: 'Yu Gothic', 'Hiragino Sans', 'Meiryo', sans-serif;
      border: 2px solid #141416;
      border-radius: 0;
      box-shadow: 1.5px 1.5px 0px #141416;
      flex-shrink: 0;
    }}
    .brand-ja {{
      font-family: 'Yu Gothic', 'Hiragino Sans', 'Meiryo', 'Noto Sans JP', sans-serif;
      font-weight: 900;
      font-size: 1.05rem;
      letter-spacing: 1.5px;
      color: #ffffff;
      text-transform: uppercase;
      text-shadow: 1.5px 1.5px 0px #141416;
    }}
    .peer-header {{
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-bottom: 12px;
    }}
    .peer-title {{
      font-family: 'Komika Axis', Impact, sans-serif;
      font-size: 1.35rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #141416;
      margin: 0;
      line-height: 1.1;
    }}
    .status-pill {{
      font-family: 'Komika Axis', sans-serif;
      font-size: 0.6rem;
      background: #10b981;
      color: #ffffff;
      padding: 2.5px 6px;
      border: 1.8px solid #141416;
      border-radius: 0;
      box-shadow: 1.5px 1.5px 0px #141416;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }}
    .qr-section {{
      display: flex;
      flex-direction: column;
      align-items: center;
      margin-bottom: 16px;
    }}
    .qr-box {{
      background: #ffffff;
      padding: 10px;
      border: 3.5px solid #141416;
      border-radius: 0;
      box-shadow: 5px 5px 0px #141416;
      display: inline-flex;
      justify-content: center;
      align-items: center;
      min-width: 215px;
      min-height: 215px;
    }}
    .qr-box canvas, .qr-box img {{
      display: block;
      width: 195px !important;
      height: 195px !important;
    }}
    .btn-grid {{
      display: grid;
      grid-template-columns: 1.55fr 1fr;
      gap: 10px;
      margin-bottom: 16px;
    }}
    .btn-col {{
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .comic-btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 10px 6px;
      font-family: 'Komika Axis', Impact, sans-serif;
      font-size: 0.72rem;
      letter-spacing: 0.3px;
      text-transform: uppercase;
      text-decoration: none;
      border: 2.5px solid #141416;
      border-radius: 0;
      box-shadow: 3.5px 3.5px 0px #141416;
      transition: transform 0.08s ease, box-shadow 0.08s ease;
      cursor: pointer;
      flex: 1;
      min-height: 42px;
      box-sizing: border-box;
      text-align: center;
    }}
    .btn-col-side .comic-btn {{
      font-size: 0.8rem;
    }}
    .comic-btn:hover {{
      transform: translate(-1px, -1px);
      box-shadow: 4.5px 4.5px 0px #141416;
    }}
    .comic-btn:active {{
      transform: translate(2px, 2px);
      box-shadow: 1.5px 1.5px 0px #141416;
    }}
    .comic-btn svg {{
      width: 14px;
      height: 14px;
      stroke: currentColor;
      stroke-width: 2.4;
      fill: none;
      flex-shrink: 0;
    }}
    .btn-clash {{ background: #f59e0b; color: #141416; }}
    .btn-singbox {{ background: #0284c7; color: #ffffff; }}
    .btn-awg {{ background: #141416; color: #ffffff; }}
    .btn-copy {{ background: #ffffff; color: #141416; }}
    .specs-box {{
      background: #f6f3ea;
      border: 2.5px solid #141416;
      border-radius: 0;
      padding: 11px 14px;
      box-shadow: 3.5px 3.5px 0px #141416;
      text-align: left;
    }}
    .spec-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 5px 0;
      border-bottom: 1.5px dashed rgba(20, 20, 22, 0.2);
    }}
    .spec-row:first-child {{ padding-top: 0; }}
    .spec-row:last-child {{ border-bottom: none; padding-bottom: 0; }}
    .spec-key {{
      font-family: 'Komika Text', sans-serif;
      font-size: 0.82rem;
      font-weight: 700;
      font-style: normal;
      color: #555555;
      text-transform: uppercase;
    }}
    .spec-val {{
      font-family: 'Komika Text', sans-serif;
      font-size: 0.88rem;
      font-weight: 700;
      font-style: normal;
      color: #141416;
      text-align: right;
    }}

    /* Minimal AWG Version Picker Modal */
    .mini-modal-overlay {{
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(20, 20, 22, 0.65);
      backdrop-filter: blur(2px);
      display: none;
      align-items: center;
      justify-content: center;
      padding: 16px;
      z-index: 1000;
    }}
    .mini-modal-overlay.open {{
      display: flex;
    }}
    .mini-modal {{
      background: #ffffff;
      border: 3.5px solid #141416;
      border-radius: 0;
      box-shadow: 7px 7px 0px #141416;
      width: 100%;
      max-width: 380px;
      animation: modalPop 0.15s cubic-bezier(0.16, 1, 0.3, 1);
      text-align: left;
    }}
    @keyframes modalPop {{
      from {{ transform: scale(0.95); opacity: 0; }}
      to {{ transform: scale(1); opacity: 1; }}
    }}
    .mini-modal-head {{
      background: #f6f3ea;
      border-bottom: 2.5px solid #141416;
      padding: 10px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .mini-modal-title {{
      font-family: 'Komika Axis', Impact, sans-serif;
      font-size: 0.88rem;
      letter-spacing: 0.5px;
      color: #141416;
      text-transform: uppercase;
    }}
    .mini-close-btn {{
      background: #e63946;
      color: #ffffff;
      border: 2px solid #141416;
      border-radius: 0;
      box-shadow: 2px 2px 0px #141416;
      width: 24px;
      height: 24px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.8rem;
      font-weight: 900;
      cursor: pointer;
      line-height: 1;
    }}
    .mini-close-btn:active {{
      transform: translate(1px, 1px);
      box-shadow: 1px 1px 0px #141416;
    }}
    .mini-modal-body {{
      padding: 16px 14px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .mini-modal-hint {{
      font-family: 'Komika Text', sans-serif;
      font-size: 0.74rem;
      color: #666;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      margin-bottom: 2px;
    }}
    .btn-modal-opt {{
      display: flex !important;
      align-items: center !important;
      justify-content: space-between !important;
      padding: 10px 12px !important;
      text-align: left !important;
      gap: 10px !important;
      min-height: 52px;
      text-decoration: none;
    }}
    .btn-modal-v3 {{
      background: #141416;
      color: #ffffff;
    }}
    .btn-modal-v2 {{
      background: #ffffff;
      color: #141416;
    }}
    .opt-badge {{
      background: #e63946;
      border: 1.5px solid #141416;
      color: #ffffff;
      font-family: 'Komika Axis', sans-serif;
      font-size: 0.68rem;
      padding: 3px 6px;
      flex-shrink: 0;
      box-shadow: 1.5px 1.5px 0px #141416;
    }}
    .btn-modal-v3 .opt-badge {{
      background: #e63946;
      border-color: #ffffff;
      color: #ffffff;
    }}
    .btn-modal-v2 .opt-badge {{
      background: #e63946;
      border-color: #141416;
      color: #ffffff;
    }}
    .opt-info {{
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }}
    .opt-title {{
      font-family: 'Komika Axis', Impact, sans-serif;
      font-size: 0.84rem;
      letter-spacing: 0.4px;
      line-height: 1.1;
    }}
    .opt-desc {{
      font-family: 'Komika Text', sans-serif;
      font-size: 0.66rem;
      font-weight: 400;
      opacity: 0.85;
      text-transform: none;
      letter-spacing: 0;
    }}
    .opt-icon {{
      width: 16px;
      height: 16px;
      stroke: currentColor;
      stroke-width: 2.2;
      fill: none;
      flex-shrink: 0;
    }}
    .mini-modal-foot {{
      background: #f6f3ea;
      border-top: 2.5px solid #141416;
      padding: 8px 14px;
      display: flex;
      justify-content: flex-end;
    }}
  </style>
  <script src="/static/qrcode.min.js"></script>
</head>
<body>
  <div class="card">
    <div>
      <div class="brand-bar">
        <span class="manga-stamp">ロ</span>
        <span class="brand-ja">ウォール・ローゼ</span>
      </div>
    </div>
    <div class="peer-header">
      <h1 class="peer-title">{peer.name}</h1>
      <span class="status-pill">ACTIVE</span>
    </div>

    <div class="qr-section">
      <div class="qr-box">
        <div id="qrcode"></div>
      </div>
    </div>

    <div class="btn-grid">
      <div class="btn-col btn-col-main">
        <a href="clash://install-config?url={subscription_url}" class="comic-btn btn-clash" title="Import to Clash / Mihomo">
          <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          <span>Import to Clash / Mihomo</span>
        </a>
        <a href="sing-box://import-remote-profile?url={singbox_target}" onclick="handleSingboxClick(event, '{singbox_raw}')" class="comic-btn btn-singbox" title="Import Hy2 to Sing-box">
          <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          <span class="singbox-label">Import Hy2 to Sing-box</span>
        </a>
      </div>
      <div class="btn-col btn-col-side">
        <button type="button" onclick="copySubUrl(this)" class="comic-btn btn-copy" title="Copy Subscription URL to clipboard">
          <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span class="copy-label">Copy URL</span>
        </button>
        <button type="button" onclick="openAwgPicker()" class="comic-btn btn-awg" title="Download AWG .conf profile (Choose 2.0 or 3.1)">
          <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          <span>AWG .conf</span>
        </button>
      </div>
    </div>

    <div class="specs-box">
      <div class="spec-row">
        <span class="spec-key">AWG 3.1 IP:</span>
        <span class="spec-val">{peer.awg1_ip}</span>
      </div>
      <div class="spec-row">
        <span class="spec-key">AWG 2.0 IP:</span>
        <span class="spec-val">{peer.awg0_ip}</span>
      </div>
      <div class="spec-row">
        <span class="spec-key">Hysteria 2:</span>
        <span class="spec-val">{hy2_port_display}</span>
      </div>
      <div class="spec-row">
        <span class="spec-key">Total Data:</span>
        <span class="spec-val">{total_data}</span>
      </div>
    </div>
  </div>

  <!-- Minimal AWG Version Selection Modal -->
  <div id="awgPickerModal" class="mini-modal-overlay" onclick="closeAwgPicker(event)">
    <div class="mini-modal" onclick="event.stopPropagation()">
      <div class="mini-modal-head">
        <span class="mini-modal-title">AMNEZIAWG .CONF</span>
        <button type="button" class="mini-close-btn" onclick="closeAwgPicker()">✕</button>
      </div>
      <div class="mini-modal-body">
        <div class="mini-modal-hint">Choose protocol version for your client:</div>
        <a href="{subscription_url}?format=conf&version=3.1" download="{clean_name}-awg3.1.conf" class="comic-btn btn-modal-opt btn-modal-v3" onclick="closeAwgPicker()">
          <div class="opt-badge">v3.1</div>
          <div class="opt-info">
            <div class="opt-title">AmneziaWG 3.1</div>
            <div class="opt-desc">Bypasses aggressive DPI blocking with header encryption and junk padding.</div>
          </div>
          <svg viewBox="0 0 24 24" class="opt-icon"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </a>
        <a href="{subscription_url}?format=conf&version=2.0" download="{clean_name}-awg2.0.conf" class="comic-btn btn-modal-opt btn-modal-v2" onclick="closeAwgPicker()">
          <div class="opt-badge">v2.0</div>
          <div class="opt-info">
            <div class="opt-title">AmneziaWG 2.0</div>
            <div class="opt-desc">Provides standard packet obfuscation compatible with legacy apps and home routers.</div>
          </div>
          <svg viewBox="0 0 24 24" class="opt-icon"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </a>
      </div>
      <div class="mini-modal-foot">
        <button type="button" class="comic-btn btn-copy" onclick="closeAwgPicker()" style="flex: none; padding: 6px 18px; font-size: 0.72rem;">
          CLOSE
        </button>
      </div>
    </div>
  </div>

  <script>
    function renderQr() {{
      var el = document.getElementById("qrcode");
      if (!el || el.dataset.rendered) return;
      if (typeof QRCode !== 'undefined') {{
        el.innerHTML = "";
        new QRCode(el, {{
          text: "{subscription_url}",
          width: 195,
          height: 195,
          colorDark: "#141416",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.M
        }});
        el.dataset.rendered = "true";
      }}
    }}

    if (document.readyState === 'loading') {{
      document.addEventListener('DOMContentLoaded', renderQr);
    }} else {{
      renderQr();
    }}
    setTimeout(renderQr, 100);
    setTimeout(renderQr, 400);

    function copySubUrl(btn) {{
      var url = "{subscription_url}";
      var label = btn.querySelector('.copy-label');
      function markSuccess() {{
        if (label) {{
          var prev = label.textContent;
          label.textContent = "COPIED! ✓";
          setTimeout(function() {{ label.textContent = prev; }}, 1600);
        }}
      }}
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(url).then(markSuccess, fallback);
      }} else {{
        fallback();
      }}
      function fallback() {{
        var ta = document.createElement("textarea");
        ta.value = url;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {{
          document.execCommand("copy");
          markSuccess();
        }} catch (e) {{
          prompt("Copy Subscription URL:", url);
        }}
        document.body.removeChild(ta);
      }}
    }}

    function handleSingboxClick(e, rawUrl) {{
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(rawUrl);
      }}
      var label = e.currentTarget.querySelector('.singbox-label');
      if (label) {{
        var prev = label.textContent;
        label.textContent = "COPIED! ✓";
        setTimeout(function() {{ label.textContent = prev; }}, 1600);
      }}
    }}

    function openAwgPicker() {{
      var m = document.getElementById("awgPickerModal");
      if (m) m.classList.add("open");
    }}
    function closeAwgPicker(e) {{
      if (e && e.target && e.target !== e.currentTarget) return;
      var m = document.getElementById("awgPickerModal");
      if (m) m.classList.remove("open");
    }}
    document.addEventListener("keydown", function(e) {{
      if (e.key === "Escape") closeAwgPicker();
    }});
  </script>
</body>
</html>
"""
