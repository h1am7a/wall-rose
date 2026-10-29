import os
import re
import tempfile
import pytest
from pathlib import Path

from app.config import Settings, settings
from app.routers.system import ALLOWED_SERVICES

INSTALL_SH_PATH = Path(__file__).resolve().parent.parent.parent / "install.sh"

def test_install_sh_exists():
    assert INSTALL_SH_PATH.exists(), f"install.sh not found at {INSTALL_SH_PATH}"

def test_bug_a_self_copy_guard_in_install_sh():
    """BUG-A: Verify that install.sh prevents self-copy when clone dir == INSTALL_DIR."""
    content = INSTALL_SH_PATH.read_text(encoding="utf-8")
    
    # 1. Check canonical path normalization
    assert "REAL_SOURCE_DIR=" in content
    assert "REAL_INSTALL_DIR=" in content
    assert '[[ "$REAL_SOURCE_DIR" != "$REAL_INSTALL_DIR" ]]' in content
    
    # 2. Check that self-copy is guarded with an informative log message
    assert "skipping self-copy" in content

def test_bug_b_configurable_bind_host_in_install_sh_and_unit():
    """BUG-B: Verify that panel bind host is configurable via HOST / PANEL_HOST."""
    content = INSTALL_SH_PATH.read_text(encoding="utf-8")
    
    # 1. Configurable PANEL_HOST with fallback
    assert 'PANEL_HOST="${PANEL_HOST:-${HOST:-0.0.0.0}}"' in content
    
    # 2. Written to .env
    assert "HOST=${PANEL_HOST}" in content
    
    # 3. Systemd unit reads HOST & PORT from EnvironmentFile and passes to uvicorn
    assert "Environment=\"HOST=${PANEL_HOST}\"" in content
    assert "Environment=\"PORT=${PANEL_PORT}\"" in content
    assert "EnvironmentFile=-${INSTALL_DIR}/backend/.env" in content
    assert "--host \\${HOST}" in content or "--host ${HOST}" in content
    assert "--port \\${PORT}" in content or "--port ${PORT}" in content

    # 4. Check that loopback bind skips opening WAN port in iptables
    assert 'if [[ "$PANEL_HOST" != "127.0.0.1"' in content

def test_bug_b_config_and_main_entrypoint():
    """BUG-B: Verify that app.config Settings supports HOST and main.py entrypoint respects it."""
    # Settings default is 0.0.0.0, can be overridden to 127.0.0.1
    s_default = Settings()
    assert s_default.HOST == "0.0.0.0"

    s_loopback = Settings(HOST="127.0.0.1")
    assert s_loopback.HOST == "127.0.0.1"

    # Verify main.py has __main__ entrypoint
    main_py_path = Path(__file__).resolve().parent.parent / "app" / "main.py"
    main_content = main_py_path.read_text(encoding="utf-8")
    assert 'if __name__ == "__main__":' in main_content
    assert "uvicorn.run(" in main_content
    assert "host=settings.HOST" in main_content
    assert "port=settings.PORT" in main_content

def test_bug_c_iptables_reconciliation_and_custom_chain():
    """BUG-C: Verify iptables management flushes dedicated WALLROSE-INPUT chain and purges stale ports."""
    content = INSTALL_SH_PATH.read_text(encoding="utf-8")
    
    # 1. Dedicated chain definition and flush
    assert "iptables -N WALLROSE-INPUT" in content
    assert "iptables -F WALLROSE-INPUT" in content
    assert "iptables -C INPUT -j WALLROSE-INPUT" in content

    # 2. Purge stale rules from previous installs
    assert "STALE_AWG0=" in content
    assert "STALE_AWG1=" in content
    assert "iptables -D INPUT -p udp --dport \"$STALE_AWG0\"" in content

def test_bug_c_public_ip_resolution_logic():
    """BUG-C: Verify Public IP resolution respects manual overrides and detects /32 aliases."""
    content = INSTALL_SH_PATH.read_text(encoding="utf-8")
    
    # 1. Respects user-specified SERVER_PUBLIC_IP or PUBLIC_IP
    assert 'if [[ -n "${SERVER_PUBLIC_IP:-}" ]]' in content
    assert 'elif [[ -n "${PUBLIC_IP:-}" ]]' in content
    
    # 2. Checks for /32 alias on interface
    assert 'mask == "32"' in content
    assert "Detected working public IP alias (/32)" in content

def test_bug_c_alias_ip_awk_parser_simulation():
    """BUG-C: Simulate awk parser on multiple IP configurations with /32 alias."""
    import subprocess
    awk_script = r"""
    $1 == "inet" {
      split($2, a, "/");
      ip = a[1];
      mask = a[2];
      if (ip ~ /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)/) {
        next;
      }
      if (mask == "32") {
        print ip;
        exit;
      }
    }
    """
    sample_ip_output = """
    inet 127.0.0.1/8 scope host lo
    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0
    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0
    inet 198.51.100.42/32 scope global eth0:1
    """
    # Test regex in python matching awk logic
    lines = sample_ip_output.strip().splitlines()
    found_alias = None
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "inet":
            ip, mask = parts[1].split("/")
            if re.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)", ip):
                continue
            if mask == "32":
                found_alias = ip
                break
    assert found_alias == "198.51.100.42"

def test_bug_d_unbound_anchor_and_root_key_validator():
    """BUG-D: Verify unbound-anchor and dns-root-data packages and root.key generation."""
    content = INSTALL_SH_PATH.read_text(encoding="utf-8")
    
    # 1. Packages installed
    assert "unbound-anchor" in content
    assert "dns-root-data" in content

    # 2. Key initialization
    assert "unbound-anchor -a /var/lib/unbound/root.key" in content
    assert "cp /usr/share/dns/root.key /var/lib/unbound/root.key" in content
    assert "chown -R unbound:unbound /var/lib/unbound" in content
    assert 'auto-trust-anchor-file: "/var/lib/unbound/root.key"' in content

    # 3. Enabled and started
    assert "systemctl enable --now unbound" in content

def test_bug_d_allowed_services_includes_unbound():
    """BUG-D: Verify ALLOWED_SERVICES in system router allows unbound logs."""
    assert "unbound" in ALLOWED_SERVICES
    assert ALLOWED_SERVICES["unbound"] == "unbound"
