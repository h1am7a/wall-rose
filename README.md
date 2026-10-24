<p align="center">
  <img src="assets/images/banner.svg" alt="ウォール・ローゼ" width="100%">
</p>

<h1 align="center">ウォール・ローゼ</h1>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="License MIT"></a>
  <a href="#release"><img src="https://img.shields.io/badge/Version-v1.0.0-yellow.svg?style=flat-square" alt="Version v1.0.0"></a>
</p>

---

## Overview

Wall Rose (`ウォール・ローゼ`) is a lightweight personal multi-protocol VPN gateway and management dashboard designed for hostile network environments with aggressive Deep Packet Inspection (DPI) and protocol throttling.

The backend is built with FastAPI and SQLite WAL, maintaining an idle memory footprint under 45 MB of RAM.

### Protocols

- **AmneziaWG 3.1:** ChaCha20 encrypted header protection and randomized packet padding to resist heuristic DPI filters.
- **AmneziaWG 2.0:** Fixed WireGuard UDP socket compatibility for Keenetic, OpenWrt, and legacy clients.
- **Hysteria 2.0:** QUIC-based transport with Gecko packet fragmentation obfuscation and port hopping (`20000:50000 -> 4433`) for high-loss cellular connections.

---

## Architecture

```mermaid
flowchart TD
    Client["Client Device<br>Clash / Mihomo / Sing-box / AWG"] -->|"GET /sub/:token"| SubEndpoint["Subscription Endpoint<br>Client Auto-Detection"]

    subgraph Server ["Wall Rose VPS Stack"]
        subgraph UI ["Static Web UI (~75 KB)"]
            Web["Manga Comic Dashboard<br>Light / Dark Themes"]
        end

        subgraph Backend ["FastAPI Engine (Under 45 MB RAM)"]
            API["REST API and SQLite WAL"]
            Cache["In-Memory Auth Cache (Under 0.2 ms)"]
            IPAM["IP Allocator (10.8.0.x / 10.9.0.x)"]
        end

        subgraph Daemons ["Protocol Daemons"]
            AWG31["AmneziaWG 3.1 (awg1)<br>ChaCha20 Headers | UDP 51821"]
            AWG20["AmneziaWG 2.0 (awg0)<br>Fixed Socket | UDP 51820"]
            HY2["Hysteria 2.0 (hy2)<br>Gecko QUIC | Port Hop 20000:50000"]
        end

        subgraph DNS ["DNS Subsystem"]
            Unbound["Unbound DoT Resolver<br>10.8.0.1 / 10.9.0.1"]
        end
    end

    SubEndpoint --> Backend
    API -->|"awg set"| Daemons
    HY2 -->|"POST /api/v1/hysteria/auth"| Cache
    Daemons --> Unbound
```

---

## Installation

Deploy on a fresh Ubuntu or Debian server with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/h1am7a/wall-rose/main/install.sh | sudo bash
```

Custom port and master password overrides are supported via environment variables:

```bash
PORT=8080 ADMIN_PASSWORD="your_secret_password" curl -fsSL https://raw.githubusercontent.com/h1am7a/wall-rose/main/install.sh | sudo -E bash
```

The installer automatically configures:
- BBR congestion control and UDP buffer tuning (`/etc/sysctl.d/99-wallrose.conf`).
- AmneziaWG kernel modules, interface configs (`awg0`, `awg1`), and routing keys.
- Hysteria 2.0 daemon and ECDSA self-signed certificates.
- Local Unbound DNS-over-TLS resolver on `10.8.0.1:53` and `10.9.0.1:53`.
- `iptables` NAT masquerading, MSS clamping, and port hopping (`20000:50000 -> 4433`).
- 16-character CSPRNG master password stored in `/opt/wall-rose/backend/.env` (`chmod 600`).
- Systemd service units (`wallrose-panel.service`, `hysteria-server.service`).

---

## Client Setup

### Mihomo / Clash Verge Rev / Flclash
1. Open dashboard, unlock console, and click **Mihomo Sub** on the device card.
2. In the client, add subscription via URL: `http://<SERVER_IP>:8000/sub/<TOKEN>`
3. Set update interval to 24 hours.

Configurations use deterministic `fallback` with `lazy: true`, routing domestic services directly and routing blocked domains and throttled services through the VPN mesh.

### Sing-box (iOS, Android, macOS, Linux)
1. Click **Sing-box** on the device card.
2. Add remote profile with URL: `http://<SERVER_IP>:8000/sub/<TOKEN>?format=json`

### Official AmneziaWG Client
1. Click **AWG .conf** on the device card.
2. Select **AWG 3.1** (anti-DPI) or **AWG 2.0** (standard) and download configuration.

---

## REST API Reference

Interactive OpenAPI documentation is available at `/docs` (Swagger) and `/redoc` (ReDoc).

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/auth/login` | `POST` | Authenticate master administrator; sets HttpOnly session cookie |
| `/api/auth/logout` | `POST` | Invalidate active session and clear cookie |
| `/api/auth/status` | `GET` | Verify current session health |
| `/api/peers` | `GET`, `POST` | List registered peers; enroll new device with live kernel mutation |
| `/api/peers/{id}` | `GET`, `PUT`, `DELETE` | Peer details, name updates, credential revocation |
| `/api/peers/{id}/status` | `PATCH` | Toggle peer active/suspended state in kernel live |
| `/api/peers/{id}/awg.conf` | `GET` | Export AmneziaWG configuration file |
| `/api/cores` | `GET` | Protocol daemon statuses (`awg0`, `awg1`, `hy2`) |
| `/api/cores/{id}/config` | `GET`, `PUT` | Read or update protocol configuration |
| `/api/cores/{id}/restart` | `POST` | Restart daemon systemd unit |
| `/api/telemetry` | `GET` | Host CPU, RAM, network bandwidth, active peer counters |
| `/sub/{token}` | `GET` | Subscription delivery with User-Agent client auto-detection |
| `/api/backup/export` | `GET` | Download database snapshot archive (`.tar.gz`) |
| `/api/backup/restore` | `POST` | Restore database with traversal validation |

---

## Development & Testing

```bash
# Clone and enter directory
git clone https://github.com/h1am7a/wall-rose.git
cd wall-rose/vpn-panel

# Virtual environment setup
python3 -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt

# Run full test suite (23 tests: units, API contracts, resilience, stress)
pytest backend/tests -v

# Start local server
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Security

- **Zero-Trust Administrative Gate:** All data and configuration APIs require session authorization. Unauthenticated calls return `401 Unauthorized`.
- **Anti-Bruteforce Lockout:** Exceeding 5 failed login attempts activates an immediate 5-minute IP lockout (`429 Too Many Requests`).
- **HttpOnly Session Cookies:** Session tokens are stored in `HttpOnly`, `SameSite=Lax` cookies, preventing client-side script theft.
- **Direct Subprocess Execution:** System commands execute strictly via argument arrays (`shell=False`).
- **Path Traversal Protection:** Backup archives are validated using `os.path.commonpath()` and Python 3.12 `filter="data"`.
- **Query Parameterization:** SQLite queries run exclusively through SQLAlchemy 2.0 async ORM.
- **High-Entropy Tokens:** Subscription tokens are generated via `secrets.token_urlsafe(32)` (256-bit CSPRNG entropy).
- **Subnet Isolation:** Forwarding rules isolate client subnets (`10.8.0.0/24`, `10.9.0.0/24`) to prevent peer traversal.
- **Loopback Internal Protection:** Internal Hysteria authentication callbacks reject external traffic.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
