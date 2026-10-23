<p align="center">
  <img src="assets/images/banner.svg" alt="ウォール・ローゼ (Wall Rose)" width="100%">
</p>

# ウォール・ローゼ (Wall Rose)

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License MIT"></a>
  <a href="#release"><img src="https://img.shields.io/badge/Version-v1.0.0-yellow.svg?style=flat-square" alt="Version v1.0.0"></a>
  <a href="#test-suite"><img src="https://img.shields.io/badge/Tests-19%20Passed%20(100%25)-brightgreen.svg?style=flat-square" alt="Tests"></a>
  <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat-square" alt="FastAPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12-3776AB.svg?style=flat-square" alt="Python"></a>
  <a href="#supported-platforms"><img src="https://img.shields.io/badge/Platforms-Ubuntu%2024.04%20%7C%2026.04%20%7C%20Debian%2012-orange.svg?style=flat-square" alt="Platforms"></a>
  <a href="#core-protocols"><img src="https://img.shields.io/badge/Protocols-AWG%202.0%2F3.1%20%7C%20Hysteria%202.9-red.svg?style=flat-square" alt="Protocols"></a>
  <a href="#overview"><img src="https://img.shields.io/badge/RAM-Footprint%20%3C45%20MB-success.svg?style=flat-square" alt="RAM Footprint"></a>
</p>

---

## Overview

Wall Rose (`ウォール・ローゼ`) is a lightweight personal multi-protocol VPN gateway and administrative dashboard built for hostile network environments subject to active Deep Packet Inspection (DPI), stateful throttling, and protocol probing.

Unlike multi-tenant web panels (3X-UI, Marzban, Hiddify) that consume 400-700 MB of RAM with external database daemons, Wall Rose uses an embedded FastAPI and SQLite WAL stack with an idle memory footprint under 45 MB.

### Core Protocols

1. **AmneziaWG 3.1 (`awg1`):** ChaCha20 encrypted header protection (`header-protection-key`) with randomized packet padding (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`-`H4`) to resist statistical heuristic classifiers.
2. **AmneziaWG 2.0 (`awg0`):** Standard WireGuard socket compatibility for hardware routers (Keenetic, OpenWrt, Mikrotik) and legacy clients.
3. **Hysteria 2.9 (`hy2`):** QUIC-based transport with Salamander obfuscation and randomized port hopping (`20000:50000 -> 4433`) for high-loss, throttled cellular networks.

### Key Characteristics

- **Live Kernel State Mutation:** Device activation and revocation apply directly via `awg set` without interface restarts or session drops.
- **Fast Auth Webhook:** Hysteria 2 authenticates against an in-memory TTL cache in `<0.2 ms`.
- **Zero-Dependency Web UI:** Static Manga Comic dashboard (~75 KB, 100% vector SVG, local typography) with zero external CDN calls.
- **Auto-Detection Device Enrollment:** Single-input enrollment with automatic client and OS fingerprinting on first subscription fetch.
- **Deterministic Routing:** Mihomo (Clash.Meta) and Sing-box configs with `fallback` failover, local Unbound DoT DNS leak prevention, and split-tunneling rule providers.

---

## Architecture

```mermaid
flowchart TD
    Client["Client Device
Clash / Mihomo / Sing-box / AWG"] -->|GET /sub/{token}| SubEndpoint["/sub/{token}
Auto User-Agent Detection"]

    subgraph Server ["Wall Rose VPS Stack"]
        subgraph UI ["Static Web UI (~75 KB)"]
            Web["Single-Page Dashboard
Light / Dark Noir Themes"]
        end

        subgraph Backend ["FastAPI Engine (<45 MB RAM)"]
            API["REST API and SQLite WAL"]
            Cache["In-Memory Auth Cache (<0.2 ms)"]
            IPAM["IP Allocator (10.8.0.x / 10.9.0.x)"]
        end

        subgraph Daemons ["Protocol Daemons"]
            AWG31["AmneziaWG 3.1 (awg1)
ChaCha20 Headers | UDP 51821"]
            AWG20["AmneziaWG 2.0 (awg0)
Fixed Socket | UDP 51820"]
            HY2["Hysteria 2.9 (hy2)
Salamander QUIC | Port Hop 20000:50000"]
        end

        subgraph DNS ["DNS Subsystem"]
            Unbound["Unbound DoT Resolver
10.8.0.1 / 10.9.0.1 (Quad9 / Cloudflare)"]
        end
    end

    SubEndpoint --> Backend
    API -->|awg set| Daemons
    HY2 -->|POST /api/v1/hysteria/auth| Cache
    Daemons --> Unbound
```

---

## Supported Platforms

| OS | Status | Notes |
| :--- | :--- | :--- |
| **Ubuntu 24.04 LTS** | Recommended | Native `ppa:amnezia/ppa`, Kernel 6.8+ BBRv3 |
| **Ubuntu 26.04 LTS** | Supported | PEP 668 compliant, native netfilter DKMS |
| **Debian 12 (Bookworm)** | Supported | DKMS module build, Linux 6.1+ LTS, iptables-persistent |

---

## Deployment

Deploy on a clean Ubuntu/Debian instance:

```bash
curl -fsSL https://raw.githubusercontent.com/<user>/wall-rose/main/install.sh | sudo bash
```

The script performs the following setup:
1. Enables BBR congestion control and tunes UDP socket buffers in `/etc/sysctl.d/99-wallrose.conf`.
2. Installs `amneziawg`, `amneziawg-dkms`, and `amneziawg-tools`.
3. Downloads the Hysteria 2 static binary and creates an ECDSA self-signed certificate with IP SAN.
4. Configures Unbound DNS-over-TLS on `10.8.0.1:53` and `10.9.0.1:53`.
5. Configures `iptables` NAT masquerading, MSS clamping, and port hopping (`20000:50000 -> 4433`).
6. Creates the Python virtual environment and starts systemd units (`wallrose-panel.service`, `hysteria-server.service`).

---

## REST API Reference

Interactive API documentation is served at `/docs` (Swagger) and `/redoc` (ReDoc).

| Endpoint | Method | Function |
| :--- | :--- | :--- |
| `/api/peers` | `GET` | List all peers with live handshake, transfer stats, and state |
| `/api/peers` | `POST` | Enroll device (allocates IP, generates x25519 keys, applies `awg set`) |
| `/api/peers/{id}` | `GET` | Peer detail, private keys, subscription tokens |
| `/api/peers/{id}` | `PUT` | Update peer name |
| `/api/peers/{id}/status` | `PATCH` | Toggle active/suspended state in kernel live |
| `/api/peers/{id}` | `DELETE` | Revoke credentials, remove from kernel, free IP address |
| `/api/peers/{id}/awg.conf` | `GET` | Download WireGuard configuration (AWG 3.1 or 2.0 format) |
| `/api/cores` | `GET` | Daemon statuses (`awg0`, `awg1`, `hy2`) |
| `/api/cores/{id}/config` | `GET`, `PUT` | Read or update daemon config file |
| `/api/cores/{id}/restart` | `POST` | Restart daemon systemd unit |
| `/api/telemetry` | `GET` | Host CPU, RAM, WAN throughput, active peer counts |
| `/sub/{token}` | `GET` | Smart subscription endpoint (serves Mihomo YAML or Sing-box JSON) |
| `/api/v1/hysteria/auth` | `POST` | Hysteria 2 HTTP auth webhook (in-memory lookup, `<0.2 ms`) |
| `/api/v1/hysteria/sync-traffic` | `POST` | Sync bandwidth counters from Hysteria 2 to SQLite |
| `/api/backup/export` | `GET` | Download point-in-time database snapshot (`.tar.gz`) |
| `/api/backup/restore` | `POST` | Restore database snapshot with path traversal safeguards |

---

## Routing and Failover

Mihomo subscriptions use deterministic `fallback` with `lazy: true`:

```yaml
proxy-groups:
  - name: "AUTO-FAILOVER"
    type: fallback
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    lazy: true
    proxies:
      - "AWG-3.1-Primary"       # ChaCha20 headers (DPI protection)
      - "AWG-2.0-Secondary"     # Static socket (Broad compatibility)
      - "Hy2-Salamander-Backup" # QUIC + Salamander Obfs + Port Hop
```

Priority order:
1. `private` IP CIDR ranges -> `DIRECT`
2. Blocked / throttled services (Antifilter, YouTube, Discord, Telegram) -> `AUTO-FAILOVER`
3. Domestic traffic (`category-ru`, `.ru`, `.xn--p1ai`, `geoip:ru`) -> `DIRECT`
4. Global traffic -> `AUTO-FAILOVER`

---

## Client Setup

### Mihomo / Clash Verge Rev / Flclash
1. In the dashboard, click **Mihomo Sub** on the device card.
2. In the client, add profile via URL: `http://<SERVER_IP>:8000/sub/<TOKEN>`
3. Set update interval to 24 hours.

### Sing-box (iOS, Android, macOS, Linux)
1. In the dashboard, click **Sing-box** on the device card.
2. Add remote profile with URL: `http://<SERVER_IP>:8000/sub/<TOKEN>?format=json`

### Official AmneziaWG Client
1. Click **AWG .conf** on the device card.
2. Select version (**AWG 3.1** for stealth or **AWG 2.0** for routers) and download `.conf`.

---

## Development

```bash
# Clone repository
git clone https://github.com/<user>/wall-rose.git
cd wall-rose/vpn-panel

# Setup environment
python3 -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

# Run test suite
pytest backend/tests -v

# Start development server
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Security

- **Safe Subprocess Calls:** System utilities are invoked strictly via list arguments (`shell=False`) to avoid shell interpolation.
- **Path Traversal Protection:** Tar extraction checks target members with `os.path.commonpath()` and uses Python 3.12 `filter="data"`.
- **Query Parameterization:** All database operations run through SQLAlchemy 2.0 async ORM queries with bound parameters.
- **Token Entropy:** Subscription tokens are generated using `secrets.token_urlsafe(32)` (256-bit CSPRNG entropy).
- **Subnet Isolation:** Forwarding rules isolate client subnets (`10.8.0.0/24`, `10.9.0.0/24`) to block peer-to-peer traversal.

---

## Test Suite

```bash
cd vpn-panel/backend
pytest tests -v
```

All 19 test cases verify:
- API endpoints: peer lifecycle, core management, telemetry, backups.
- Unit logic: x25519 key generation, IPAM allocation, Hysteria auth cache latency, configuration builders.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
