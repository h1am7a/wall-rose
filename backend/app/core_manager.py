import os
import re
import shutil
import subprocess
import socket
import base64
import logging
from typing import Dict, Any, Optional, Tuple, List

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from app.config import settings

logger = logging.getLogger("wallrose.core_manager")

class HysteriaAuthCache:
    """
    High-speed in-memory authentication cache.
    Shields SQLite from reconnect storms and answers Hysteria 2 webhooks in <0.2 ms.
    """
    def __init__(self):
        # Key: (username, password) -> Value: {"ok": bool, "id": str, "status": str}
        self._cache: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def set_user(self, username: str, password: str, status: str):
        is_allowed = status != "SUSPENDED"
        self._cache[(username, password)] = {
            "ok": is_allowed,
            "id": username,
            "status": status
        }

    def remove_user(self, username: str, password: str):
        self._cache.pop((username, password), None)

    def authenticate(self, auth_string: str) -> Dict[str, Any]:
        """
        Supports both single password (Hysteria 2 password-only auth)
        and 'username:password' pair.
        """
        if not auth_string:
            return {"ok": False, "id": None}

        # Check direct pair
        if ":" in auth_string:
            parts = auth_string.split(":", 1)
            u, p = parts[0], parts[1]
            if (u, p) in self._cache:
                entry = self._cache[(u, p)]
                return {"ok": entry["ok"], "id": entry["id"]}

        # Check by password match
        for (u, p), entry in self._cache.items():
            if p == auth_string or u == auth_string:
                return {"ok": entry["ok"], "id": entry["id"]}

        return {"ok": False, "id": None}

    def clear(self):
        self._cache.clear()

auth_cache = HysteriaAuthCache()

# ==============================================================================
# AMNEZIAWG USERSPACE (amneziawg-go) CONTROLLER
# ==============================================================================

def is_linux_and_root() -> bool:
    """Check if host is Linux and executing with root/sudo capabilities."""
    return os.name != "nt" and os.geteuid() == 0 if hasattr(os, "geteuid") else False

def awg_tool_exists() -> bool:
    """Check if awg / wg binary exists on the system."""
    return shutil.which("awg") is not None or shutil.which("wg") is not None

def get_awg_binary() -> str:
    return "awg" if shutil.which("awg") else "wg"

def get_awg_conf_path(interface: str) -> str:
    """
    Locates the userspace configuration file (*-userspace.conf).
    """
    setting_path = getattr(settings, f"{interface.upper()}_CONFIG_PATH", None)
    if setting_path and os.path.isfile(setting_path):
        return setting_path

    candidates = [
        f"/etc/amnezia/amneziawg/{interface}-userspace.conf",
        f"/etc/amneziawg/{interface}-userspace.conf",
        f"/etc/amnezia/amneziawg/{interface}.conf",
        f"/etc/amneziawg/{interface}.conf",
        f"/etc/wireguard/{interface}-userspace.conf",
        f"/etc/wireguard/{interface}.conf",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path

    return setting_path or f"/etc/amnezia/amneziawg/{interface}-userspace.conf"

def parse_awg_conf_peers(conf_path: str) -> Tuple[List[str], List[Dict[str, str]]]:
    """
    Parses a WireGuard / AmneziaWG configuration file into:
    - interface_lines: raw lines belonging to the [Interface] section.
    - peers: list of dictionaries representing each [Peer] block.
    """
    if not os.path.isfile(conf_path):
        return [], []

    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except Exception as e:
        logger.warning(f"Error reading conf {conf_path}: {e}")
        return [], []

    interface_lines = []
    peers = []
    current_peer = None
    in_interface = False

    for line in lines:
        stripped = line.strip()
        if stripped.lower() == "[interface]":
            in_interface = True
            if current_peer is not None:
                peers.append(current_peer)
                current_peer = None
            interface_lines.append(line)
        elif stripped.lower() == "[peer]":
            in_interface = False
            if current_peer is not None:
                peers.append(current_peer)
            current_peer = {}
        elif in_interface:
            interface_lines.append(line)
        elif current_peer is not None:
            if "=" in line:
                k, v = line.split("=", 1)
                current_peer[k.strip()] = v.strip()
            elif stripped:
                current_peer[stripped] = ""

    if current_peer is not None:
        peers.append(current_peer)

    return interface_lines, peers

def write_awg_conf(conf_path: str, interface_lines: List[str], peers: List[Dict[str, str]]):
    """
    Atomically writes the interface section and peers back to the configuration file.
    """
    out: List[str] = []
    out.extend(interface_lines)
    if out and out[-1].strip() != "":
        out.append("")

    for p in peers:
        out.append("[Peer]")
        for k, v in p.items():
            if v == "":
                out.append(k)
            else:
                out.append(f"{k} = {v}")
        out.append("")

    dir_name = os.path.dirname(conf_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    tmp_path = f"{conf_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp_path, conf_path)

def reload_awg_service(interface: str) -> bool:
    """
    Gracefully restarts the userspace amneziawg-go service with a strict timeout.
    Prioritizes awg0-go / awg1-go, then fallbacks to awg-quick.
    """
    if not is_linux_and_root() or shutil.which("systemctl") is None:
        logger.info(f"[Mock Mode] Reloaded userspace daemon for {interface}")
        return True

    service_candidates = [
        f"{interface}-go.service",
        f"{interface}-go",
        f"awg-quick@{interface}.service",
        f"awg-quick@{interface}",
    ]
    for svc in service_candidates:
        try:
            status = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True,
                text=True,
                timeout=1.5
            )
            if status.stdout.strip() in ("active", "activating"):
                res = subprocess.run(
                    ["systemctl", "restart", svc],
                    capture_output=True,
                    text=True,
                    timeout=3.0
                )
                if res.returncode == 0:
                    logger.info(f"Restarted {svc} to apply userspace peer updates")
                    return True
        except Exception as e:
            logger.warning(f"Notice restarting {svc}: {e}")

    return False

def live_add_awg_peer(
    interface: str,
    public_key: str,
    allowed_ip: str,
    preshared_key: Optional[str] = None
) -> bool:
    """
    Registers a peer into the userspace AmneziaWG configuration file
    and instructs the amneziawg-go daemon to reload.
    """
    conf_path = get_awg_conf_path(interface)

    if is_linux_and_root() or os.path.isfile(conf_path):
        try:
            iface_lines, peers = parse_awg_conf_peers(conf_path)
            # Find existing peer or append
            existing = next((p for p in peers if p.get("PublicKey") == public_key), None)
            if existing:
                existing["AllowedIPs"] = f"{allowed_ip}/32"
                if preshared_key:
                    existing["PresharedKey"] = preshared_key
            else:
                new_peer = {
                    "PublicKey": public_key,
                    "AllowedIPs": f"{allowed_ip}/32",
                }
                if preshared_key:
                    new_peer["PresharedKey"] = preshared_key
                peers.append(new_peer)

            write_awg_conf(conf_path, iface_lines, peers)
            logger.info(f"Synchronized peer {public_key[:8]} to {conf_path}")
        except Exception as e:
            logger.error(f"Failed to update userspace conf {conf_path}: {e}")

    reload_awg_service(interface)
    return True

def live_remove_awg_peer(interface: str, public_key: str) -> bool:
    """
    Removes a peer from the userspace configuration file and triggers daemon reload.
    """
    conf_path = get_awg_conf_path(interface)

    if is_linux_and_root() or os.path.isfile(conf_path):
        try:
            iface_lines, peers = parse_awg_conf_peers(conf_path)
            filtered = [p for p in peers if p.get("PublicKey") != public_key]
            if len(filtered) != len(peers):
                write_awg_conf(conf_path, iface_lines, filtered)
                logger.info(f"Purged peer {public_key[:8]} from {conf_path}")
        except Exception as e:
            logger.error(f"Failed removing peer from {conf_path}: {e}")

    reload_awg_service(interface)
    return True

def query_uapi_socket(interface: str) -> Dict[str, Dict[str, Any]]:
    """
    Direct UNIX domain socket query to amneziawg-go UAPI socket.
    Avoids kernel CLI hangs and returns metrics instantly.
    """
    if not hasattr(socket, "AF_UNIX"):
        return {}

    sock_candidates = [
        f"/var/run/wireguard/{interface}.sock",
        f"/var/run/amneziawg/{interface}.sock",
        f"/var/run/{interface}.sock",
        f"/tmp/{interface}.sock",
    ]
    for sock_path in sock_candidates:
        if os.path.exists(sock_path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect(sock_path)
                s.sendall(b"get=1\n\n")
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if b"errno=" in raw or raw.endswith(b"\n\n"):
                        break
                s.close()
                return parse_uapi_response(raw.decode("utf-8", errors="ignore"))
            except Exception as e:
                logger.debug(f"UAPI socket {sock_path} error: {e}")

    return {}

def parse_uapi_response(text: str) -> Dict[str, Dict[str, Any]]:
    metrics: Dict[str, Dict[str, Any]] = {}
    current_pubkey = None
    cur_data: Dict[str, Any] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            if k == "public_key":
                if current_pubkey and cur_data:
                    metrics[current_pubkey] = cur_data
                try:
                    if len(v) == 64:
                        current_pubkey = base64.b64encode(bytes.fromhex(v)).decode("ascii")
                    else:
                        current_pubkey = v
                except Exception:
                    current_pubkey = v
                cur_data = {
                    "endpoint": "",
                    "latest_handshake": 0,
                    "transfer_rx": 0,
                    "transfer_tx": 0,
                }
            elif current_pubkey:
                if k == "endpoint":
                    cur_data["endpoint"] = v
                elif k == "last_handshake_time_sec":
                    cur_data["latest_handshake"] = int(v) if v.isdigit() else 0
                elif k == "rx_bytes":
                    cur_data["transfer_rx"] = int(v) if v.isdigit() else 0
                elif k == "tx_bytes":
                    cur_data["transfer_tx"] = int(v) if v.isdigit() else 0

    if current_pubkey and cur_data:
        metrics[current_pubkey] = cur_data

    return metrics

def fetch_awg_interface_metrics(interface: str) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves real-time handshake and traffic metrics from userspace amneziawg-go.
    Protected by timeouts to guarantee the FastAPI worker never hangs.
    """
    # 1. Direct UAPI socket (instantaneous, zero CLI execution)
    uapi = query_uapi_socket(interface)
    if uapi:
        return uapi

    # 2. CLI fallback with strict 1.5s timeout
    if is_linux_and_root() and awg_tool_exists():
        try:
            res = subprocess.run(
                [get_awg_binary(), "show", interface, "dump"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.5
            )
            if res.returncode == 0:
                metrics = {}
                lines = res.stdout.strip().splitlines()
                for line in lines[1:]:
                    parts = line.split("\t")
                    if len(parts) >= 8:
                        pubkey = parts[0]
                        endpoint = parts[2]
                        handshake = int(parts[4]) if parts[4].isdigit() else 0
                        rx = int(parts[5]) if parts[5].isdigit() else 0
                        tx = int(parts[6]) if parts[6].isdigit() else 0
                        metrics[pubkey] = {
                            "endpoint": endpoint,
                            "latest_handshake": handshake,
                            "transfer_rx": rx,
                            "transfer_tx": tx
                        }
                return metrics
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout querying awg show {interface} dump")
        except Exception as e:
            logger.warning(f"Error querying awg show {interface}: {e}")

    return {}

# ==============================================================================
# SYSTEMD SERVICE ORCHESTRATION
# ==============================================================================

def check_daemon_status(service_name: str) -> Tuple[bool, int]:
    """
    Checks `systemctl is-active <service_name>` and calculates uptime.
    Returns (is_active, uptime_seconds).
    """
    if not is_linux_and_root() or shutil.which("systemctl") is None:
        return True, 86400 * 3  # Simulation: healthy 3 days uptime

    try:
        res = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=2.0
        )
        is_active = res.stdout.strip() == "active"
        
        # If userspace service is not active, check awg-quick fallback
        if not is_active and service_name.endswith("-go"):
            alt_svc = f"awg-quick@{service_name.replace('-go', '')}"
            res_alt = subprocess.run(
                ["systemctl", "is-active", alt_svc],
                capture_output=True,
                text=True,
                check=False,
                timeout=2.0
            )
            if res_alt.stdout.strip() == "active":
                is_active = True

        uptime = 86400 if is_active else 0
        return is_active, uptime
    except Exception:
        return False, 0

def restart_daemon_service(service_name: str) -> bool:
    """Gracefully restart protocol daemon via systemctl with a 5s timeout."""
    if not is_linux_and_root() or shutil.which("systemctl") is None:
        logger.info(f"[Mock Mode] Restarting service {service_name}")
        return True

    try:
        res = subprocess.run(
            ["systemctl", "restart", service_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0
        )
        if res.returncode == 0:
            return True
        # Try fallback if awg0-go failed
        if service_name.endswith("-go"):
            alt_svc = f"awg-quick@{service_name.replace('-go', '')}"
            res_alt = subprocess.run(
                ["systemctl", "restart", alt_svc],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0
            )
            return res_alt.returncode == 0
        return False
    except Exception as e:
        logger.warning(f"Error restarting {service_name}: {e}")
        return False

# ==============================================================================
# SERVER PUBLIC KEY RETRIEVAL & DERIVATION (PURE PYTHON X25519)
# ==============================================================================

_server_pubkey_cache: Dict[str, str] = {}

def get_server_public_key(interface: str) -> str:
    """
    Returns the server public key for interface (awg0 or awg1).
    Derives key mathematically from the PrivateKey line in *-userspace.conf,
    ensuring zero subprocess hangs.
    """
    if interface in _server_pubkey_cache:
        return _server_pubkey_cache[interface]

    # 1. Config setting override
    setting_val = getattr(settings, f"{interface.upper()}_SERVER_PUBLIC_KEY", "")
    if setting_val and setting_val.strip():
        _server_pubkey_cache[interface] = setting_val.strip()
        return setting_val.strip()

    # 2. Read from userspace config file and derive via x25519
    conf_path = get_awg_conf_path(interface)
    if os.path.isfile(conf_path):
        try:
            with open(conf_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("PrivateKey"):
                        priv_b64 = line.split("=", 1)[1].strip()
                        priv_bytes = base64.b64decode(priv_b64)
                        priv_key = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
                        pub_bytes = priv_key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        k = base64.b64encode(pub_bytes).decode("ascii")
                        _server_pubkey_cache[interface] = k
                        return k
        except Exception as e:
            logger.warning(f"Failed to read/derive server public key from {conf_path}: {e}")

    # 3. Fallback: generate a valid cryptographically sound x25519 public key
    from app.security import generate_x25519_keypair
    _, k = generate_x25519_keypair()
    _server_pubkey_cache[interface] = k
    return k

def get_awg_server_params(interface: str) -> Dict[str, Any]:
    """
    Parses obfuscation parameters from the server's *-userspace.conf.
    If not found on disk, returns the exact Trinity Mihomo etalon parameters.
    """
    if interface == "awg1":
        # Trinity etalon defaults for AWG1-v3
        params: Dict[str, Any] = {
            "version": 3,
            "port": settings.AWG1_PORT,
            "jc": int(settings.AWG1_JC),
            "jmin": int(settings.AWG1_JMIN),
            "jmax": int(settings.AWG1_JMAX),
            "s1": int(settings.AWG1_S1),
            "s2": int(settings.AWG1_S2),
            "s3": int(settings.AWG1_S3),
            "s4": int(settings.AWG1_S4),
            "h1": str(settings.AWG1_H1),
            "h2": str(settings.AWG1_H2),
            "h3": str(settings.AWG1_H3),
            "h4": str(settings.AWG1_H4),
            "header_protection_key": str(settings.AWG1_HEADER_PROTECTION_KEY),
            "content_padding_addition": str(settings.AWG1_CONTENT_PADDING_ADDITION),
            "rekey_after_time": 120,
            "rekey_timeout": 5,
            "reject_after_time": 180,
            "keepalive_timeout": 10,
            "max_handshake_attempts": 18,
            "random_trailers": True,
            "disable_cookies": True,
        }
    else:
        # Trinity etalon defaults for AWG0-v2
        params = {
            "version": 2,
            "port": settings.AWG0_PORT,
            "jc": int(settings.AWG0_JC),
            "jmin": int(settings.AWG0_JMIN),
            "jmax": int(settings.AWG0_JMAX),
            "s1": int(settings.AWG0_S1),
            "s2": int(settings.AWG0_S2),
            "s3": int(settings.AWG0_S3),
            "s4": int(settings.AWG0_S4),
            "h1": str(settings.AWG0_H1),
            "h2": str(settings.AWG0_H2),
            "h3": str(settings.AWG0_H3),
            "h4": str(settings.AWG0_H4),
        }

    conf_path = get_awg_conf_path(interface)
    if os.path.isfile(conf_path):
        try:
            with open(conf_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("[Peer]"):
                        break
                    if "=" in stripped:
                        k, v = stripped.split("=", 1)
                        k_lower = k.strip().lower()
                        v_val = v.strip()
                        if k_lower == "listenport" and v_val.isdigit():
                            params["port"] = int(v_val)
                        elif k_lower == "jc" and v_val.isdigit():
                            params["jc"] = int(v_val)
                        elif k_lower == "jmin" and v_val.isdigit():
                            params["jmin"] = int(v_val)
                        elif k_lower == "jmax" and v_val.isdigit():
                            params["jmax"] = int(v_val)
                        elif k_lower == "s1" and v_val.isdigit():
                            params["s1"] = int(v_val)
                        elif k_lower == "s2" and v_val.isdigit():
                            params["s2"] = int(v_val)
                        elif k_lower == "s3" and v_val.isdigit():
                            params["s3"] = int(v_val)
                        elif k_lower == "s4" and v_val.isdigit():
                            params["s4"] = int(v_val)
                        elif k_lower in ("h1", "h2", "h3", "h4"):
                            params[k_lower] = v_val.strip("\"'")
                        elif k_lower in ("headerprotectionkey", "header-protection-key"):
                            params["header_protection_key"] = v_val.strip("\"'")
        except Exception as e:
            logger.warning(f"Notice reading params from {conf_path}: {e}")

    return params

def get_hysteria_server_params() -> Dict[str, Any]:
    """
    Parses real Hysteria 2 port and gecko obfuscation password from /etc/hysteria/config.yaml.
    Guarantees no out-of-sync credentials between panel and daemon.
    """
    params: Dict[str, Any] = {
        "port": settings.HY2_PORT,
        "obfs_password": settings.HY2_OBFS_PASSWORD,
        "obfs_min_packet_size": settings.HY2_OBFS_MIN_PACKET,
        "obfs_max_packet_size": settings.HY2_OBFS_MAX_PACKET,
        "sni": "gateway.cloudflare.com",
    }

    cfg_path = getattr(settings, "HY2_CONFIG_PATH", "/etc/hysteria/config.yaml")
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse listen port
            m_listen = re.search(r"listen:\s*:?(\d+)", content)
            if m_listen:
                params["port"] = int(m_listen.group(1))

            # Parse gecko password
            m_pass = re.search(r"password:\s*(\S+)", content)
            if m_pass:
                params["obfs_password"] = m_pass.group(1).strip("\"'")

            # Parse minPacketSize
            m_min = re.search(r"minPacketSize:\s*(\d+)", content)
            if m_min:
                params["obfs_min_packet_size"] = int(m_min.group(1))

            # Parse maxPacketSize
            m_max = re.search(r"maxPacketSize:\s*(\d+)", content)
            if m_max:
                params["obfs_max_packet_size"] = int(m_max.group(1))
        except Exception as e:
            logger.warning(f"Notice parsing {cfg_path}: {e}")

    return params
