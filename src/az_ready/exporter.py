"""Least-exposure Azure Resource Graph inventory export using an existing Azure CLI login.

Read-only queries, finite pagination, no shell interpolation, allowlisted resource types
and properties, and no raw data-plane secrets written to disk.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Callable

from .checks import get

# Resource types included in snapshot; Resource Graph may not index all children.
RESOURCE_TYPES = (
    "microsoft.network/virtualnetworks",
    "microsoft.network/virtualnetworks/virtualnetworkpeerings",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/routetables",
    "microsoft.network/azurefirewalls",
    "microsoft.network/firewallpolicies",
    "microsoft.network/privateendpoints",
    "microsoft.network/privateendpoints/privatednszonegroups",
    "microsoft.network/privatednszones/virtualnetworklinks",
    "microsoft.storage/storageaccounts",
    "microsoft.keyvault/vaults",
    "microsoft.sql/servers",
    "microsoft.sql/servers/azureadonlyauthentications",
    "microsoft.servicebus/namespaces",
    "microsoft.app/managedenvironments",
    "microsoft.apimanagement/service",
)

# Keep only fields the checker needs. Do not persist full ARM properties, tags,
# auth values, configuration strings, subscription metadata or credential fields.
FIELDS = {
    "microsoft.network/virtualnetworks": ("subnets",),
    "microsoft.network/virtualnetworks/virtualnetworkpeerings": ("peeringState", "allowForwardedTraffic"),
    "microsoft.network/networksecuritygroups": ("securityRules",),
    "microsoft.network/routetables": ("routes",),
    "microsoft.network/azurefirewalls": ("ipConfigurations",),
    "microsoft.network/firewallpolicies": ("sku", "dnsSettings", "intrusionDetection"),
    "microsoft.network/privateendpoints": ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections"),
    "microsoft.network/privateendpoints/privatednszonegroups": ("privateDnsZoneConfigs",),
    "microsoft.network/privatednszones/virtualnetworklinks": ("virtualNetworkLinkState",),
    "microsoft.storage/storageaccounts": ("publicNetworkAccess", "allowSharedKeyAccess", "minimumTlsVersion"),
    "microsoft.keyvault/vaults": ("publicNetworkAccess", "enableRbacAuthorization", "networkAcls"),
    "microsoft.sql/servers": ("publicNetworkAccess",),
    "microsoft.sql/servers/azureadonlyauthentications": ("azureADOnlyAuthentication",),
    "microsoft.servicebus/namespaces": ("publicNetworkAccess", "disableLocalAuth"),
    "microsoft.app/managedenvironments": ("vnetConfiguration", "publicNetworkAccess"),
    "microsoft.apimanagement/service": ("publicNetworkAccess",),
}

# Nested fields are reduced too. Sensitive strings cannot be extracted by default.
NESTED = {
    "microsoft.network/virtualnetworks": {"subnets": [{"id": None, "name": None, "properties": {"addressPrefix": None, "addressPrefixes": None, "networkSecurityGroup": {"id": None}, "routeTable": {"id": None}, "delegations": [{"name": None}]}}]},
    "microsoft.network/networksecuritygroups": {"securityRules": [{"name": None, "properties": {"direction": None, "access": None, "priority": None, "sourceAddressPrefix": None, "sourceAddressPrefixes": None, "destinationPortRange": None, "destinationPortRanges": None}}]},
    "microsoft.network/routetables": {"routes": [{"name": None, "properties": {"addressPrefix": None, "nextHopType": None, "nextHopIpAddress": None}}]},
    "microsoft.network/azurefirewalls": {"ipConfigurations": [{"properties": {"privateIPAddress": None}}]},
    "microsoft.network/firewallpolicies": {"sku": {"tier": None}, "dnsSettings": {"enableProxy": None}, "intrusionDetection": {"mode": None}},
    "microsoft.network/privateendpoints": {"privateLinkServiceConnections": [{"properties": {"privateLinkServiceId": None, "privateLinkServiceConnectionState": {"status": None}}}], "manualPrivateLinkServiceConnections": [{"properties": {"privateLinkServiceId": None, "privateLinkServiceConnectionState": {"status": None}}}]},
    "microsoft.network/privateendpoints/privatednszonegroups": {"privateDnsZoneConfigs": [{"properties": {"privateDnsZoneId": None}}]},
    "microsoft.keyvault/vaults": {"networkAcls": {"defaultAction": None}},
    "microsoft.app/managedenvironments": {"vnetConfiguration": {"internal": None}},
}


def _prune(value, shape):
    if shape is None:
        return value if isinstance(value, (str, bool, int, float)) or value is None else None
    if isinstance(shape, list):
        return [_prune(x, shape[0]) for x in value] if isinstance(value, list) else None
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            return None
        return {key: _prune(get(value, key), subshape) for key, subshape in shape.items() if get(value, key) is not None}
    return None


def sanitize(resource: dict) -> dict:
    typ = str(resource.get("type", "")).lower()
    if typ not in FIELDS or not isinstance(resource.get("id"), str):
        raise ValueError("Unsupported or malformed Resource Graph record")
    props = get(resource, "properties")
    safe = {}
    for name in FIELDS[typ]:
        val = get(props, name) if isinstance(props, dict) else None
        if val is not None:
            shape = NESTED.get(typ, {}).get(name)
            # Never pass complex objects with no explicit nested allowlist.
            safe[name] = _prune(val, shape)
    return {"id": resource["id"], "type": typ, "properties": safe}


def export(subscriptions: list[str], page_size: int = 500, max_pages: int = 200,
           invoke: Callable[[list[str]], subprocess.CompletedProcess] | None = None) -> dict:
    if not subscriptions or any(not s or not isinstance(s, str) for s in subscriptions):
        raise ValueError("Pass one or more explicit Azure subscription IDs")
    if not 1 <= page_size <= 1000 or max_pages < 1:
        raise ValueError("page_size must be 1..1000 and max_pages positive")
    if invoke is None and not shutil.which("az"):
        raise RuntimeError("Azure CLI not found; install 'az' and 'az extension add --name resource-graph'")
    runner = invoke or (lambda argv: subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120))
    types = ", ".join(f"'{t}'" for t in RESOURCE_TYPES)
    query = f"Resources | where type in~ ({types}) | project id, type, properties | order by id asc"
    seen: dict[str, dict] = {}
    for page in range(max_pages):
        args = ["az", "graph", "query", "-q", query, "--first", str(page_size), "--skip", str(page * page_size), "--subscriptions", *subscriptions, "-o", "json"]
        run = runner(args)
        if run.returncode:
            raise RuntimeError("Azure Resource Graph query failed; verify 'az login', extension and Reader permissions: " + str(run.stderr).strip()[:400])
        try:
            data = json.loads(run.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError("Azure CLI returned invalid JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise RuntimeError("Unexpected Azure Resource Graph result envelope")
        records = data["data"]
        for record in records:
            safe = sanitize(record)
            key = safe["id"].lower()
            if key in seen:
                raise RuntimeError("Duplicate resource during pagination; collection may have changed. Rerun the export.")
            seen[key] = safe
        if len(records) < page_size:
            break
    else:
        raise RuntimeError("Export page cap exceeded; no partial inventory was written")
    return {"schemaVersion": 1, "source": "azure-resource-graph", "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
            "note": "Allowlisted control-plane metadata only. Resource Graph indexing can omit child resources; absence is not proof of failure.",
            "resources": [seen[key] for key in sorted(seen)]}
