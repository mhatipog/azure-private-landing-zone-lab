"""Explicit, opt-in in-network DNS/TLS probe. No arbitrary discovery/scanning."""
from __future__ import annotations

import ipaddress
import socket
import ssl


def probe(host: str, expected_ips: list[str], port: int = 443, timeout: float = 3.0) -> dict:
    """Connect only to an explicitly approved expected IP; always send SNI for host.

    Run from inside the peered Azure VNet. A green result proves this vantage point
    resolved and established authenticated TLS; it does not prove global isolation.
    """
    if not host or "/" in host or ":" in host or not (0 < port <= 65535) or not (0 < timeout <= 15):
        raise ValueError("Provide a DNS hostname, valid port, and timeout <=15s")
    expected = {str(ipaddress.ip_address(ip)) for ip in expected_ips}
    approved_ranges = [ipaddress.ip_network(prefix) for prefix in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"
    )]
    if not expected or any(not any(ipaddress.ip_address(ip) in block for block in approved_ranges)
                           for ip in expected):
        raise ValueError("Provide approved RFC1918 or ULA private endpoint IPs only")
    try:
        answers = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except OSError as e:
        return {"host": host, "status": "FAIL", "stage": "dns", "error": str(e)}
    matching = sorted(expected.intersection(answers))
    if not matching:
        return {"host": host, "status": "FAIL", "stage": "dns", "resolved": answers,
                "expected": sorted(expected), "error": "No approved endpoint IP returned"}
    ip = matching[0]
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                return {"host": host, "status": "PASS", "stage": "tls", "ip": ip,
                        "tls": tls.version(), "certificate_verified": True}
    except (OSError, ssl.SSLError) as e:
        return {"host": host, "status": "FAIL", "stage": "tls", "ip": ip, "error": str(e)}
