"""Deterministic CIDR planning and topology linting. No Azure access required."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from ipaddress import ip_network
from typing import Any


@dataclass(frozen=True)
class TopologyIssue:
    code: str
    severity: str
    path: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def validate_topology(spec: dict[str, Any]) -> list[TopologyIssue]:
    """Validate topology shape, subnet containment, overlap and address capacity.

    Example schema in examples/topology.json. IPv4 only by design.
    """
    problems: list[TopologyIssue] = []

    def error(code: str, path: str, msg: str, severity: str = "high") -> None:
        problems.append(TopologyIssue(code, severity, path, msg))

    if not isinstance(spec, dict) or not isinstance(spec.get("vnets"), list) or not spec["vnets"]:
        return [TopologyIssue("SCHEMA", "high", "vnets", "Expected a nonempty vnets array")]
    nets = []
    names: set[str] = set()
    for i, vnet in enumerate(spec["vnets"]):
        path = f"vnets[{i}]"
        if not isinstance(vnet, dict):
            error("SCHEMA", path, "VNet must be an object")
            continue
        name = vnet.get("name")
        if not isinstance(name, str) or not name.strip():
            error("SCHEMA", path + ".name", "VNet must have a name")
            continue
        if name.casefold() in names:
            error("DUPLICATE_VNET", path, f"Repeated VNet name {name!r}")
        names.add(name.casefold())
        try:
            net = ip_network(vnet.get("cidr", ""), strict=True)
            if net.version != 4:
                raise ValueError("IPv4 only")
        except (ValueError, TypeError):
            error("INVALID_CIDR", path + ".cidr", "Require a canonical IPv4 CIDR, e.g. 10.80.0.0/16")
            continue
        nets.append((net, path, name))
        subnets = vnet.get("subnets", [])
        if not isinstance(subnets, list):
            error("SCHEMA", path + ".subnets", "Subnets must be an array")
            continue
        local = []
        subnames = set()
        for j, subnet in enumerate(subnets):
            sp = f"{path}.subnets[{j}]"
            if not isinstance(subnet, dict) or not isinstance(subnet.get("name"), str):
                error("SCHEMA", sp, "Subnet must have a name")
                continue
            sn = subnet["name"].casefold()
            if sn in subnames:
                error("DUPLICATE_SUBNET", sp, f"Repeated subnet name {subnet['name']!r}")
            subnames.add(sn)
            try:
                subnet_net = ip_network(subnet.get("cidr", ""), strict=True)
                if subnet_net.version != 4:
                    raise ValueError("IPv4 only")
            except (ValueError, TypeError):
                error("INVALID_CIDR", sp + ".cidr", "Require a canonical IPv4 subnet CIDR")
                continue
            if not subnet_net.subnet_of(net):
                error("OUTSIDE_VNET", sp, f"{subnet_net} is outside {net}")
            for other, other_path in local:
                if subnet_net.overlaps(other):
                    error("SUBNET_OVERLAP", sp, f"{subnet_net} overlaps {other} ({other_path})")
            local.append((subnet_net, sp))
            role = str(subnet.get("role", "")).lower()
            if role == "azure-firewall" and (subnet["name"] != "AzureFirewallSubnet" or subnet_net.prefixlen > 26):
                error("FIREWALL_SUBNET", sp, "Azure Firewall requires AzureFirewallSubnet of /26 or larger")
            if role == "container-apps-workload-profiles" and subnet_net.prefixlen > 27:
                error("ACA_SUBNET_SIZE", sp, "Container Apps workload profiles require /27 or larger")
            if role == "container-apps-consumption-only" and subnet_net.prefixlen > 23:
                error("ACA_SUBNET_SIZE", sp, "Legacy consumption-only environments require /23 or larger")
            if role == "private-endpoints" and subnet_net.num_addresses - 5 < 1:
                error("NO_USABLE_IPS", sp, "Subnet lacks usable Azure IP addresses")
            if role == "workload" and not subnet.get("nsg"):
                error("WORKLOAD_NSG", sp + ".nsg", "Workload subnet needs an explicit NSG association", "medium")
            if role == "workload" and bool(spec.get("forced_tunneling")) and not subnet.get("route_table"):
                error("MISSING_EGRESS_ROUTE", sp + ".route_table", "Forced tunneling workload needs a route table")
    for i, (net, path, _) in enumerate(nets):
        for other, other_path, _ in nets[:i]:
            if net.overlaps(other):
                error("VNET_OVERLAP", path, f"{net} overlaps {other} ({other_path})")
    return sorted(problems, key=lambda p: (p.path, p.code))
