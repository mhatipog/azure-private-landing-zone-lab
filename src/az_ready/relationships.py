"""Cross-resource consistency checks; absence of child evidence remains UNKNOWN."""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from .checks import Finding, get, emit


def _id(value: Any) -> str:
    return str(value or "").rstrip("/").casefold()


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _subnets(vnet: dict) -> list[dict]:
    return _list(get(vnet, "properties.subnets"))


def assess_relationships(resources: Iterable[dict]) -> list[Finding]:
    items = list(resources)
    by_id = {_id(r.get("id")): r for r in items}
    # Index zone-group children once. A linear scan per endpoint makes estates
    # with thousands of Private Endpoints quadratic (measured in benchmarks).
    zone_group_counts: dict[str, int] = {}
    for candidate in items:
        if str(candidate.get("type", "")).casefold() != "microsoft.network/privateendpoints/privatednszonegroups":
            continue
        child_id = _id(candidate.get("id"))
        parent, sep, _ = child_id.rpartition("/privatednszonegroups/")
        if sep:
            zone_group_counts[parent] = zone_group_counts.get(parent, 0) + 1
    out: list[Finding] = []
    firewall_ips: set[str] = set()
    for r in items:
        if str(r.get("type", "")).casefold() == "microsoft.network/azurefirewalls":
            for cfg in _list(get(r, "properties.ipConfigurations")):
                ip = get(cfg, "properties.privateIPAddress")
                if ip:
                    firewall_ips.add(str(ip))
    for r in items:
        rid = _id(r["id"])
        t = str(r.get("type", "")).casefold()
        if t == "microsoft.network/virtualnetworks":
            for subnet in _subnets(r):
                sid = _id(subnet.get("id")) or f"{rid}/subnets/{subnet.get('name', '?')}"
                prop = subnet.get("properties", {})
                if not isinstance(prop, dict):
                    continue
                role = str(subnet.get("name", "")).casefold()
                # Do not require UDR on private endpoint subnets: routing may be intentionally managed differently.
                if role not in ("azurefirewallsubnet", "private-endpoints") and not get(subnet, "properties.delegations"):
                    nsg = get(subnet, "properties.networkSecurityGroup.id")
                    out.append(emit("SUBNET_NSG_ATTACHED", sid, "medium", nsg, bool(nsg) if "networkSecurityGroup" in prop else None,
                                    "Associate approved NSG to workload subnet; inspect effective NSG rules."))
                table_id = get(subnet, "properties.routeTable.id")
                if table_id:
                    table = by_id.get(_id(table_id))
                    if table is None:
                        out.append(emit("SUBNET_UDR_EVIDENCE", sid, "medium", None, None,
                                        "Include referenced route tables in export; cannot verify UDR next hop."))
                    else:
                        routes = get(table, "properties.routes")
                        if routes is None:
                            out.append(emit("SUBNET_UDR_EVIDENCE", sid, "medium", None, None,
                                            "Include route table routes in snapshot."))
                        else:
                            default = [x for x in _list(routes) if get(x, "properties.addressPrefix") == "0.0.0.0/0"]
                            if not default:
                                out.append(emit("SUBNET_UDR_EVIDENCE", sid, "medium", [], False,
                                                "Attach a route table with a default route to the approved firewall."))
                            else:
                                hops = [get(x, "properties.nextHopIpAddress") for x in default if
                                        str(get(x, "properties.nextHopType") or "").casefold() == "virtualappliance"]
                                good = None if not firewall_ips else bool(set(str(x) for x in hops) & firewall_ips)
                                out.append(emit("SUBNET_FIREWALL_MATCH", sid, "high", {"hops": hops, "firewall_private_ips": sorted(firewall_ips)}, good,
                                                "Ensure UDR next hop is the actual Azure Firewall private IP; validate effective routes."))
            # Verify only CIDR consistency among subnets present in a single VNet.
            networks = []
            for subnet in _subnets(r):
                prefix = get(subnet, "properties.addressPrefix")
                if prefix is None:
                    prefixes = get(subnet, "properties.addressPrefixes")
                    prefix = prefixes[0] if isinstance(prefixes, list) and len(prefixes) == 1 else None
                if prefix:
                    try:
                        net = ipaddress.ip_network(prefix, strict=False)
                        sid = _id(subnet.get("id")) or rid
                        overlapping = [str(n) for n, _ in networks if n.overlaps(net)]
                        out.append(emit("SUBNET_NO_OVERLAP", sid, "high", overlapping, not overlapping,
                                        "Ensure subnet CIDR blocks do not overlap."))
                        networks.append((net, sid))
                    except ValueError:
                        out.append(emit("SUBNET_NO_OVERLAP", rid, "high", prefix, False, "Fix invalid subnet CIDR."))
        elif t == "microsoft.network/privateendpoints":
            # Absence of child resource in Resource Graph is not proof of missing zone group.
            count = zone_group_counts.get(rid, 0)
            out.append(emit("PE_ZONE_GROUP_PRESENT", rid, "medium", count if count else None,
                            True if count else None,
                            "Export child DNS zone group or verify private DNS integration in portal."))
            targets = _list(get(r, "properties.privateLinkServiceConnections")) + _list(get(r, "properties.manualPrivateLinkServiceConnections"))
            for target in targets:
                target_id = get(target, "properties.privateLinkServiceId")
                if target_id:
                    target_resource = by_id.get(_id(target_id))
                    out.append(emit("PE_TARGET_EVIDENCE", rid, "medium", target_id,
                                    None if target_resource is None else True,
                                    "Include private endpoint target resource in snapshot to verify its public access settings."))
    return sorted(out, key=lambda x: (x.resource_id, x.rule))
