import json
import yaml
from typing import Dict, Any
from app.config import settings
from app.models import Peer

def generate_awg_client_conf(peer: Peer, version: str = "3.1", server_ip: str = None) -> str:
    """Generate raw AmneziaWG .conf file."""
    ip = server_ip or settings.SERVER_PUBLIC_IP
    
    if version == "2.0":
        return f"""[Interface]
Address = {peer.awg0_ip}/32
PrivateKey = {peer.awg0_privkey}
DNS = 10.8.0.1, 1.1.1.1
Jc = {settings.AWG0_JC}
Jmin = {settings.AWG0_JMIN}
Jmax = {settings.AWG0_JMAX}
S1 = {settings.AWG0_S1}
S2 = {settings.AWG0_S2}
H1 = {settings.AWG0_H1}
H2 = {settings.AWG0_H2}
H3 = {settings.AWG0_H3}
H4 = {settings.AWG0_H4}

[Peer]
PublicKey = SERVER_AWG0_PUBKEY_PLACEHOLDER
PresharedKey = {peer.awg0_psk}
Endpoint = {ip}:{settings.AWG0_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    else:
        # AWG 3.1
        return f"""[Interface]
Address = {peer.awg1_ip}/32
PrivateKey = {peer.awg1_privkey}
DNS = 10.9.0.1, 1.1.1.1
Jc = {settings.AWG1_JC}
Jmin = {settings.AWG1_JMIN}
Jmax = {settings.AWG1_JMAX}
S1 = {settings.AWG1_S1}
S2 = {settings.AWG1_S2}
H1 = {settings.AWG1_H1}
H2 = {settings.AWG1_H2}
H3 = {settings.AWG1_H3}
H4 = {settings.AWG1_H4}

[Peer]
PublicKey = SERVER_AWG1_PUBKEY_PLACEHOLDER
PresharedKey = {peer.awg1_psk}
Endpoint = {ip}:{settings.AWG1_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

def generate_mihomo_yaml(peer: Peer, server_ip: str = None) -> str:
    """Generate complete Mihomo (Clash.Meta) YAML subscription with Smart Routing and Fallback."""
    ip = server_ip or settings.SERVER_PUBLIC_IP

    conf: Dict[str, Any] = {
        "port": 7890,
        "socks-port": 7891,
        "mixed-port": 7892,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "external-controller": "127.0.0.1:9090",
        
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": [
                "1.1.1.1",
                "8.8.8.8"
            ],
            "fallback": [
                "tls://1.1.1.1:853",
                "tls://8.8.8.8:853"
            ]
        },

        "proxies": [
            # Primary: AmneziaWG 3.1 (ChaCha20 header protection)
            {
                "name": "AWG-3.1-Primary",
                "type": "wireguard",
                "server": ip,
                "port": settings.AWG1_PORT,
                "ip": peer.awg1_ip,
                "public-key": "SERVER_AWG1_PUBKEY_PLACEHOLDER",
                "private-key": peer.awg1_privkey,
                "preshared-key": peer.awg1_psk,
                "udp": True,
                "remote-dns-resolve": True,
                "dns": ["10.9.0.1"],
                # AmneziaWG Obfuscation parameters
                "amnezia": {
                    "jc": settings.AWG1_JC,
                    "jmin": settings.AWG1_JMIN,
                    "jmax": settings.AWG1_JMAX,
                    "s1": settings.AWG1_S1,
                    "s2": settings.AWG1_S2,
                    "h1": settings.AWG1_H1,
                    "h2": settings.AWG1_H2,
                    "h3": settings.AWG1_H3,
                    "h4": settings.AWG1_H4,
                }
            },
            # Secondary: AmneziaWG 2.0 (Compatible socket)
            {
                "name": "AWG-2.0-Secondary",
                "type": "wireguard",
                "server": ip,
                "port": settings.AWG0_PORT,
                "ip": peer.awg0_ip,
                "public-key": "SERVER_AWG0_PUBKEY_PLACEHOLDER",
                "private-key": peer.awg0_privkey,
                "preshared-key": peer.awg0_psk,
                "udp": True,
                "remote-dns-resolve": True,
                "dns": ["10.8.0.1"],
                "amnezia": {
                    "jc": settings.AWG0_JC,
                    "jmin": settings.AWG0_JMIN,
                    "jmax": settings.AWG0_JMAX,
                    "s1": settings.AWG0_S1,
                    "s2": settings.AWG0_S2,
                    "h1": settings.AWG0_H1,
                    "h2": settings.AWG0_H2,
                    "h3": settings.AWG0_H3,
                    "h4": settings.AWG0_H4,
                }
            },
            # Fallback Backup: Hysteria 2 (QUIC + Salamander Obfs + Port Hopping)
            {
                "name": "Hy2-Salamander-Backup",
                "type": "hysteria2",
                "server": ip,
                "port": settings.HY2_PORT,
                "ports": f"{settings.HY2_PORT_HOP_START}-{settings.HY2_PORT_HOP_END}",
                "password": peer.hy2_pass,
                "sni": "gateway.cloudflare.com",
                "skip-cert-verify": True,
                "obfs": {
                    "type": "salamander",
                    "password": settings.HY2_OBFS_PASSWORD
                }
            }
        ],

        "proxy-groups": [
            {
                "name": "AUTO-FAILOVER",
                "type": "fallback",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "lazy": True,
                "proxies": [
                    "AWG-3.1-Primary",
                    "AWG-2.0-Secondary",
                    "Hy2-Salamander-Backup"
                ]
            },
            {
                "name": "MANUAL-SELECT",
                "type": "select",
                "proxies": [
                    "AUTO-FAILOVER",
                    "AWG-3.1-Primary",
                    "AWG-2.0-Secondary",
                    "Hy2-Salamander-Backup",
                    "DIRECT"
                ]
            }
        ],

        "rule-providers": {
            "youtube": {
                "type": "http",
                "behavior": "classical",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.yaml",
                "path": "./ruleset/youtube.yaml",
                "interval": 86400
            },
            "discord": {
                "type": "http",
                "behavior": "classical",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.yaml",
                "path": "./ruleset/discord.yaml",
                "interval": 86400
            },
            "telegram": {
                "type": "http",
                "behavior": "classical",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.yaml",
                "path": "./ruleset/telegram.yaml",
                "interval": 86400
            },
            "antifilter": {
                "type": "http",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/savely-krasovsky/antizapret-sing-box/master/rules/antizapret.yaml",
                "path": "./ruleset/antifilter.yaml",
                "interval": 86400
            },
            "category-ru": {
                "type": "http",
                "behavior": "domain",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ru.yaml",
                "path": "./ruleset/category-ru.yaml",
                "interval": 86400
            },
            "geoip-ru": {
                "type": "http",
                "behavior": "ipcidr",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ru.yaml",
                "path": "./ruleset/geoip-ru.yaml",
                "interval": 86400
            }
        },

        "rules": [
            # 1. Local Network Protection
            "GEOIP,private,DIRECT,no-resolve",
            # 2. Critical bypasses (unthrottle YouTube, Discord, Telegram)
            "RULE-SET,youtube,AUTO-FAILOVER",
            "RULE-SET,discord,AUTO-FAILOVER",
            "RULE-SET,telegram,AUTO-FAILOVER",
            "GEOIP,telegram,AUTO-FAILOVER,no-resolve",
            # 3. RKN Blocked Sites Registry (Antifilter)
            "RULE-SET,antifilter,AUTO-FAILOVER",
            # 4. Russian domestic services directly via local ISP
            "RULE-SET,category-ru,DIRECT",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
            "RULE-SET,geoip-ru,DIRECT",
            # 5. Global fallthrough
            "MATCH,AUTO-FAILOVER"
        ]
    }

    return yaml.dump(conf, sort_keys=False, allow_unicode=True)

def generate_singbox_json(peer: Peer, server_ip: str = None) -> str:
    """Generate Sing-box compatible JSON profile."""
    ip = server_ip or settings.SERVER_PUBLIC_IP
    cfg = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "tls://1.1.1.1", "detour": "select-out"},
                {"tag": "local", "address": "local", "detour": "direct"}
            ]
        },
        "inbounds": [
            {"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True}
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
                "server_port": settings.HY2_PORT,
                "password": peer.hy2_pass,
                "tls": {
                    "enabled": True,
                    "server_name": "gateway.cloudflare.com",
                    "insecure": True
                },
                "obfs": {
                    "type": "salamander",
                    "password": settings.HY2_OBFS_PASSWORD
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
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{peer.name} — CoreGate Client Enrollment</title>
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
      background: #ffffff;
      border: 3.5px solid #141416;
      border-radius: 12px;
      box-shadow: 6px 6px 0 #141416;
      max-width: 440px;
      width: 100%;
      padding: 24px;
      text-align: center;
    }}
    .badge {{
      display: inline-block;
      background: #ffb703;
      border: 2px solid #141416;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 6px;
      margin-bottom: 12px;
    }}
    h1 {{
      font-size: 20px;
      font-weight: 900;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
      word-break: break-all;
    }}
    .desc {{
      font-size: 13px;
      color: #666;
      margin-bottom: 20px;
    }}
    .qr-box {{
      background: #fafafa;
      border: 2px dashed #141416;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 20px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }}
    .qr-img {{
      width: 180px;
      height: 180px;
      background: #fff;
      border: 2px solid #141416;
      border-radius: 4px;
    }}
    .btn {{
      display: block;
      width: 100%;
      text-decoration: none;
      font-weight: 800;
      font-size: 14px;
      text-transform: uppercase;
      padding: 12px;
      border-radius: 8px;
      border: 2.5px solid #141416;
      margin-bottom: 10px;
      transition: transform 0.1s ease;
    }}
    .btn:active {{
      transform: translate(2px, 2px);
    }}
    .btn-clash {{
      background: #ffb703;
      color: #141416;
      box-shadow: 3px 3px 0 #141416;
    }}
    .btn-singbox {{
      background: #0077b6;
      color: #ffffff;
      box-shadow: 3px 3px 0 #141416;
    }}
    .btn-copy {{
      background: #e9ecef;
      color: #141416;
      border: 2px solid #141416;
      cursor: pointer;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">CoreGate Active Profile</div>
    <h1>{peer.name}</h1>
    <p class="desc">{peer.device_desc} &bull; Mesh IP: {peer.awg1_ip}</p>

    <div class="qr-box">
      <img class="qr-img" src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data={subscription_url}" alt="QR Subscription">
      <span style="font-size: 11px; font-weight: 700; color: #555;">Scan with Mihomo / Clash / Sing-box camera</span>
    </div>

    <a class="btn btn-clash" href="clash://install-config?url={subscription_url}&name={peer.name}">
      Import to Clash / Mihomo
    </a>
    
    <a class="btn btn-singbox" href="sing-box://import-remote-profile?url={subscription_url}#name={peer.name}">
      Import to Sing-box
    </a>

    <button class="btn btn-copy" onclick="navigator.clipboard.writeText('{subscription_url}'); alert('Subscription URL copied!');">
      Copy Subscription Link
    </button>
  </div>
</body>
</html>"""
