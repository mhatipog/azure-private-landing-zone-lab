"""Analyze actual NIC effective-route output (Azure CLI, offline after capture)."""
from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

from .checks import Finding, emit


def _prefixes(route: dict) -> list[str]:
    raw = route.get("addressPrefix")
    return raw if isinstance(raw, list) else [raw] if isinstance(raw, str) else []


def evaluate_routes(payload: Any, *, resource_id: str = "nic", expected_firewall: str | None = None,
                    destination: str = "8.8.8.8") -> list[Finding]:
    """Check the best matching *active* route to an explicit destination IPv4.

    This is still a recorded snapshot of a NIC, not a live Network Watcher next-hop test.
    Handles the list returned by 'az network nic show-effective-route-table'.
    """
    if not isinstance(payload, list):
        raise ValueError("Expected Azure CLI effective-routes JSON array")
    ip = ip_address(destination)
    if ip.version != 4:
        raise ValueError("Only IPv4 destination supported")
    if expected_firewall:
        fw = ip_address(expected_firewall)
        if fw.version != 4 or not fw.is_private:
            raise ValueError("Provide approved private firewall IPv4 address")
    candidates = []
    for route in payload:
        if not isinstance(route, dict):
            raise ValueError("Each effective route must be a JSON object")
        if str(route.get("state", "")).casefold() != "active":
            continue
        for prefix in _prefixes(route):
            try:
                net = ip_network(prefix, strict=False)
                if ip in net:
                    # User/UDR wins over BGP then system on matching prefix length.
                    rank = {"user": 2, "bgp": 1, "default": 0}.get(str(route.get("source", "")).casefold(), -1)
                    candidates.append((net.prefixlen, rank, route))
            except (ValueError, TypeError):
                continue
    if not candidates:
        return [emit("EFFECTIVE_ROUTE", resource_id, "high", None, None,
                     "Capture NIC effective routes from a running VM; confirm source NIC/destination match the incident.")]
    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    bestlen, bestrank, winner = candidates[0]
    tied = [r for plen, rank, r in candidates if (plen, rank) == (bestlen, bestrank)]
    if len(tied) != 1:
        return [emit("EFFECTIVE_ROUTE", resource_id, "high", len(tied), None,
                     "Multiple equally ranked routes present; use Azure Network Watcher next-hop to confirm.")]
    hop_type = str(winner.get("nextHopType", "")).casefold()
    addresses = winner.get("nextHopIpAddress", [])
    hops = addresses if isinstance(addresses, list) else [addresses] if addresses else []
    compliant = hop_type == "virtualappliance" and (expected_firewall is None or expected_firewall in hops)
    return [emit("EFFECTIVE_ROUTE", resource_id, "high",
                 {"destination": destination, "prefix": _prefixes(winner), "source": winner.get("source"),
                  "nextHopType": winner.get("nextHopType"), "nextHopIpAddress": hops}, compliant,
                 "Inspect effective routes and next-hop diagnostics from the correct source NIC; update UDR only after change approval.")]
