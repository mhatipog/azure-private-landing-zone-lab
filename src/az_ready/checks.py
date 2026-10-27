"""Offline, deterministic checks over Azure Resource Graph-style resource snapshots.

A missing property is UNKNOWN, not an assumed safe/unsafe value. Never infer
reachability from control-plane data; use the separate in-VNet probe for that.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Finding:
    rule: str
    status: str  # PASS | FAIL | UNKNOWN
    severity: str  # high | medium | low
    resource_id: str
    evidence: str
    fix: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def get(obj: dict, dotted: str) -> Any:
    """Read case-insensitive ARM properties without turning absent fields into false."""
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        key = next((k for k in cur if k.lower() == part.lower()), None)
        if key is None:
            return None
        cur = cur[key]
    return cur


def emit(rule: str, rid: str, severity: str, observed: Any, good: bool | None,
         fix: str) -> Finding:
    status = "UNKNOWN" if good is None else ("PASS" if good else "FAIL")
    return Finding(rule, status, severity, rid,
                   f"observed={observed!r}" if observed is not None else "property not present in snapshot",
                   fix)


def expected(value: Any, desired: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, str) and isinstance(desired, str):
        return value.lower() == desired.lower()
    return value == desired


def check_property(resource: dict, rule: str, prop: str, desired: Any,
                   severity: str, fix: str) -> Finding:
    observed = get(resource, prop)
    return emit(rule, resource["id"], severity, observed, expected(observed, desired), fix)


def has_sensitive_port(rule: dict) -> bool:
    """Conservative NSG exposure detection including port ranges and wildcard ports.

    Reports *potential* exposure; this is not an effective-rules analysis (priority,
    shadowing, NIC rules and upstream firewall are not resolved here).
    """
    if str(get(rule, "properties.direction") or "").lower() != "inbound":
        return False
    if str(get(rule, "properties.access") or "").lower() != "allow":
        return False
    src = get(rule, "properties.sourceAddressPrefix")
    multi = get(rule, "properties.sourceAddressPrefixes")
    sources = multi if isinstance(multi, list) else [src]
    if not any(str(p).strip().lower() in ("*", "internet", "0.0.0.0/0", "::/0") for p in sources):
        return False
    multi_ports = get(rule, "properties.destinationPortRanges")
    ports = multi_ports if isinstance(multi_ports, list) else [get(rule, "properties.destinationPortRange")]
    for value in ports:
        port = str(value or "").strip()
        if port == "*":
            return True
        try:
            parts = port.split("-")
            if len(parts) == 1 and int(parts[0]) in (22, 3389):
                return True
            if len(parts) == 2 and 0 <= int(parts[0]) <= int(parts[1]) <= 65535 and any(
                    int(parts[0]) <= x <= int(parts[1]) for x in (22, 3389)):
                return True
        except ValueError:
            continue
    return False


def assess(resources: Iterable[dict]) -> list[Finding]:
    """Analyze resources without network access or external credentials."""
    out: list[Finding] = []
    items = list(resources)
    for r in items:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not r["id"].strip():
            raise ValueError("Each resource must be an object with a nonempty string 'id'")
    items.sort(key=lambda r: r["id"].casefold())
    for r in items:
        t = str(r.get("type", "")).lower()
        if t == "microsoft.network/virtualnetworks/virtualnetworkpeerings":
            for rule, prop, wanted in (
                ("PEERING_CONNECTED", "properties.peeringState", "Connected"),
                ("PEERING_FORWARDED", "properties.allowForwardedTraffic", True),
            ):
                out.append(check_property(r, rule, prop, wanted, "high", "Check both sides of VNet peering and routing."))
        elif t == "microsoft.network/routetables":
            routes = get(r, "properties.routes")
            if routes is not None and not isinstance(routes, list):
                raise ValueError("Route table routes must be a list if present")
            if routes is None:
                out.append(emit("DEFAULT_ROUTE", r["id"], "high", None, None, "Export routeTable.properties.routes."))
            else:
                defaults = [x for x in routes if get(x, "properties.addressPrefix") == "0.0.0.0/0"]
                good = any(str(get(x, "properties.nextHopType") or "").lower() == "virtualappliance" and
                           bool(get(x, "properties.nextHopIpAddress")) for x in defaults)
                out.append(emit("DEFAULT_ROUTE", r["id"], "high",
                                [get(x, "properties") for x in defaults], good,
                                "Set 0.0.0.0/0 -> VirtualAppliance with the approved firewall private IP. Confirm the table is associated with relevant subnets."))
        elif t == "microsoft.network/networksecuritygroups":
            rules = get(r, "properties.securityRules")
            if rules is not None and not isinstance(rules, list):
                raise ValueError("NSG securityRules must be a list if present")
            out.append(emit("NSG_PUBLIC_ADMIN", r["id"], "high",
                            None if rules is None else [get(x, "name") for x in rules if has_sensitive_port(x)],
                            None if rules is None else not any(has_sensitive_port(x) for x in rules),
                            "Remove Internet-wide inbound SSH/RDP/all-port allow rules. Evaluate effective NSG rules separately."))
        elif t == "microsoft.network/firewallpolicies":
            out.extend([
                check_property(r, "FW_PREMIUM", "properties.sku.tier", "Premium", "medium", "Use Premium only if TLS inspection/IDPS is required; verify SKU cost."),
                check_property(r, "FW_DNS_PROXY", "properties.dnsSettings.enableProxy", True, "high", "Enable DNS proxy and point spoke DNS to the firewall or managed resolver."),
                check_property(r, "FW_IDPS", "properties.intrusionDetection.mode", "Deny", "medium", "Review IDPS policy and exclusions before enforcing Deny."),
            ])
        elif t == "microsoft.network/privateendpoints":
            connections = get(r, "properties.privateLinkServiceConnections")
            manual = get(r, "properties.manualPrivateLinkServiceConnections")
            all_connections = (connections or []) + (manual or []) if (connections is not None or manual is not None) else None
            states = None if all_connections is None else [get(c, "properties.privateLinkServiceConnectionState.status") for c in all_connections]
            out.append(emit("PE_APPROVED", r["id"], "high", states,
                            None if states is None or not states else all(str(s).lower() == "approved" for s in states),
                            "Approve endpoint connection at target resource; check its private NIC, DNS zone group and routes."))
        elif t == "microsoft.network/privateendpoints/privatednszonegroups":
            configs = get(r, "properties.privateDnsZoneConfigs")
            out.append(emit("PE_DNS_GROUP", r["id"], "medium",
                            None if configs is None else len(configs),
                            None if configs is None else len(configs) > 0,
                            "Attach the correct privatelink zone to the endpoint; verify A records and VNet links."))
        elif t == "microsoft.network/privatednszones/virtualnetworklinks":
            out.append(check_property(r, "DNS_LINK", "properties.virtualNetworkLinkState", "Completed", "medium", "Confirm private DNS VNet link is completed."))
        elif t == "microsoft.storage/storageaccounts":
            out.extend([
                check_property(r, "STORAGE_PUBLIC", "properties.publicNetworkAccess", "Disabled", "high", "Disable public network access after private endpoints/DNS are in place."),
                check_property(r, "STORAGE_KEY", "properties.allowSharedKeyAccess", False, "high", "Disable shared-key authorization; use Entra ID and scoped RBAC."),
                check_property(r, "STORAGE_TLS", "properties.minimumTlsVersion", "TLS1_2", "medium", "Enforce TLS 1.2 or newer."),
            ])
        elif t == "microsoft.keyvault/vaults":
            out.extend([
                check_property(r, "KV_PUBLIC", "properties.publicNetworkAccess", "Disabled", "high", "Use approved private endpoint and private DNS."),
                check_property(r, "KV_RBAC", "properties.enableRbacAuthorization", True, "high", "Use Azure RBAC rather than legacy access policies."),
                check_property(r, "KV_DENY", "properties.networkAcls.defaultAction", "Deny", "high", "Set default network ACL action Deny."),
            ])
        elif t == "microsoft.sql/servers":
            out.append(check_property(r, "SQL_PUBLIC", "properties.publicNetworkAccess", "Disabled", "high", "Use Private Link and private DNS; check separate Entra-only authentication configuration."))
        elif t == "microsoft.sql/servers/azureadonlyauthentications":
            out.append(check_property(r, "SQL_ENTRA_ONLY", "properties.azureADOnlyAuthentication", True, "high", "Configure Microsoft Entra-only authentication."))
        elif t == "microsoft.servicebus/namespaces":
            out.extend([
                check_property(r, "BUS_PUBLIC", "properties.publicNetworkAccess", "Disabled", "high", "Use Private Link; requires a compatible Service Bus tier."),
                check_property(r, "BUS_LOCAL_AUTH", "properties.disableLocalAuth", True, "high", "Use managed identity and Azure RBAC."),
            ])
        elif t == "microsoft.app/managedenvironments":
            out.extend([
                check_property(r, "ACA_INTERNAL", "properties.vnetConfiguration.internal", True, "high", "Use an internal VNet-integrated Container Apps environment."),
                check_property(r, "ACA_PUBLIC", "properties.publicNetworkAccess", "Disabled", "high", "Disable public network access after testing internal DNS and ingress."),
            ])
        elif t == "microsoft.apimanagement/service":
            out.append(check_property(r, "APIM_PUBLIC", "properties.publicNetworkAccess", "Disabled", "high", "Use supported APIM tier and inbound private endpoint; disabling public access may require a two-step deployment."))
    return sorted(out, key=lambda f: (f.resource_id.lower(), f.rule))
