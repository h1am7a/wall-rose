import ipaddress
from typing import Set, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Peer

def allocate_next_ip(subnet_cidr: str, used_ips: Set[str], gateway_ip: str) -> str:
    """
    Find the lowest available IP address in the specified subnet, excluding gateway and used IPs.
    """
    network = ipaddress.ip_network(subnet_cidr, strict=False)
    for host in network.hosts():
        host_str = str(host)
        if host_str == gateway_ip:
            continue
        if host_str not in used_ips:
            return host_str
    raise ValueError(f"Subnet pool exhausted for {subnet_cidr}")

async def allocate_peer_ips(session: AsyncSession) -> Tuple[str, str]:
    """
    Allocates next collision-free IPv4 for both awg0 (10.8.0.x) and awg1 (10.9.0.x).
    Returns (awg0_ip, awg1_ip).
    """
    stmt = select(Peer.awg0_ip, Peer.awg1_ip)
    rows = (await session.execute(stmt)).all()
    
    used_awg0 = {r[0] for r in rows if r[0]}
    used_awg1 = {r[1] for r in rows if r[1]}

    ip_awg0 = allocate_next_ip("10.8.0.0/24", used_awg0, gateway_ip="10.8.0.1")
    ip_awg1 = allocate_next_ip("10.9.0.0/24", used_awg1, gateway_ip="10.9.0.1")

    return ip_awg0, ip_awg1
