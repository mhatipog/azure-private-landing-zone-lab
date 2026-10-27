"""Deterministic, synthetic Azure Resource Graph estates for OFFLINE testing only.

No credentials, deployment or network access. Every resource ID, resource property
and connection below is generated for a fictitious subscription. This is not a
representation of an actual deployed Azure control plane.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

SUBSCRIPTION = "/subscriptions/00000000-0000-4000-8000-000000000000"
BASE = SUBSCRIPTION + "/resourceGroups/simulated/providers/"
FIREWALL_IP = "10.80.0.4"


def item(kind: str, name: str, **properties: Any) -> dict:
    return {"id": BASE + kind + "/" + name, "type": kind, "properties": properties}


def _spoke_cidr_prefix(index: int) -> str:
    """Private /24 address prefix for spoke index, skipping the hub's /16."""
    if not 0 <= index < 60_000:
        raise ValueError("Spoke index must be in [0, 60000)")
    second_octet = index // 256
    if second_octet >= 80:
        second_octet += 1
    return f"10.{second_octet}.{index % 256}"


def simulate_estate(spokes: int = 1) -> list[dict]:
    """Generate internally consistent hub/spoke resources for stress/e2e testing.

    A spoke includes UDR, NSG, VNet, peering, private endpoints/zone groups,
    private targets and a DNS VNet link. CIDRs do not overlap for <=60,000 spokes.
    """
    if not 1 <= spokes <= 60_000:
        raise ValueError("spokes must be 1..60000")
    hub = item("microsoft.network/virtualnetworks", "sim-hub", subnets=[
        {"name": "AzureFirewallSubnet", "properties": {"addressPrefix": "10.80.0.0/26"}}
    ])
    firewall = item("microsoft.network/azurefirewalls", "sim-fw", ipConfigurations=[
        {"properties": {"privateIPAddress": FIREWALL_IP}}
    ])
    policy = item("microsoft.network/firewallpolicies", "sim-fw-policy", sku={"tier": "Premium"},
                  dnsSettings={"enableProxy": True}, intrusionDetection={"mode": "Deny"})
    resources = [hub, firewall, policy]
    for n in range(spokes):
        c = _spoke_cidr_prefix(n)
        prefix = f"spoke-{n:05d}"
        route = item("microsoft.network/routetables", prefix + "-egress", routes=[
            {"name": "default-firewall", "properties": {"addressPrefix": "0.0.0.0/0",
             "nextHopType": "VirtualAppliance", "nextHopIpAddress": FIREWALL_IP}}
        ])
        nsg = item("microsoft.network/networksecuritygroups", prefix + "-nsg", securityRules=[])
        vnet = item("microsoft.network/virtualnetworks", prefix, subnets=[
            {"name": "workload", "properties": {"addressPrefix": c + ".0/25",
                "routeTable": {"id": route["id"]}, "networkSecurityGroup": {"id": nsg["id"]}}},
            {"name": "private-endpoints", "properties": {"addressPrefix": c + ".128/25",
                "networkSecurityGroup": {"id": nsg["id"]}}}
        ])
        peer_id = vnet["id"] + "/virtualNetworkPeerings/hub"
        peer = {"id": peer_id, "type": "microsoft.network/virtualnetworks/virtualnetworkpeerings",
                "properties": {"peeringState": "Connected", "allowForwardedTraffic": True}}
        store = item("microsoft.storage/storageaccounts", "storage-" + prefix,
                     publicNetworkAccess="Disabled", allowSharedKeyAccess=False,
                     minimumTlsVersion="TLS1_2")
        vault = item("microsoft.keyvault/vaults", "vault-" + prefix,
                     publicNetworkAccess="Disabled", enableRbacAuthorization=True,
                     networkAcls={"defaultAction": "Deny"})
        endpoint = item("microsoft.network/privateendpoints", prefix + "-storage-pe",
            privateLinkServiceConnections=[{"properties": {"privateLinkServiceId": store["id"],
                "privateLinkServiceConnectionState": {"status": "Approved"}}}])
        group = {"id": endpoint["id"] + "/privateDnsZoneGroups/default",
                 "type": "microsoft.network/privateendpoints/privatednszonegroups",
                 "properties": {"privateDnsZoneConfigs": [{"properties": {
                     "privateDnsZoneId": BASE + "microsoft.network/privateDnsZones/privatelink.blob.core.windows.net"}}]}}
        link = {"id": BASE + "microsoft.network/privateDnsZones/privatelink.blob.core.windows.net/virtualNetworkLinks/" + prefix,
                "type": "microsoft.network/privatednszones/virtualnetworklinks",
                "properties": {"virtualNetworkLinkState": "Completed"}}
        resources.extend([route, nsg, vnet, peer, store, vault, endpoint, group, link])
    return resources


def inject_faults(resources: list[dict], spoke_index: int = 0) -> tuple[list[dict], set[str]]:
    """Inject independently named, deterministic faults; return expected *rule* IDs.

    Original records stay unchanged so they can be compared for drift.
    """
    altered = deepcopy(resources)
    prefix = f"spoke-{spoke_index:05d}"
    changes = {
        ("microsoft.network/routetables", prefix + "-egress"): ("routes", 0, "nextHopIpAddress", "10.80.0.99"),
        ("microsoft.storage/storageaccounts", "storage-" + prefix): ("publicNetworkAccess", "Enabled"),
        ("microsoft.keyvault/vaults", "vault-" + prefix): ("enableRbacAuthorization", False),
        ("microsoft.network/privateendpoints", prefix + "-storage-pe"): ("privateLinkServiceConnectionState", "Rejected"),
    }
    for record in altered:
        kind, name = record["type"], record["id"].rsplit("/", 1)[-1]
        target = changes.get((kind, name))
        if not target:
            continue
        if kind == "microsoft.network/routetables":
            record["properties"]["routes"][0]["properties"]["nextHopIpAddress"] = target[-1]
        elif kind == "microsoft.network/privateendpoints":
            record["properties"]["privateLinkServiceConnections"][0]["properties"][target[0]]["status"] = target[1]
        else:
            record["properties"][target[0]] = target[1]
    return altered, {"SUBNET_FIREWALL_MATCH", "STORAGE_PUBLIC", "KV_RBAC", "PE_APPROVED"}
