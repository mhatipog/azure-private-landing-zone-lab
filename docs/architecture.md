# Architecture and trust boundaries

```text
                         Azure subscription (per environment)
   ┌────────────── hub VNet 10.84/16 ──────────────────┐
   │ AzureFirewallSubnet /26 -> Firewall Premium *      │
   │  DNS proxy / IDPS / policy (no TLS CA distributed)  │
   └──────────────────────┬─────────────────────────────┘
                          │ bidirectional peering
   ┌──────────────────────▼─────────────────────────────┐
   │ spoke VNet 10.85/16                                │
   │  private-endpoints /24                             │
   │    Storage blob PE -> privatelink.blob.core...      │
   │    Key Vault PE   -> privatelink.vaultcore...       │
   │  ACA infrastructure /23                            │
   │    optional internal environment (manual internal DNS)     │
   │  optional UDR default -> Firewall private IP       │
   └────────────────────────────────────────────────────┘
   * Disabled by default; expensive. Use WHAT-IF first.
```

## Security boundaries

- **Default** is a private foundation with Key Vault RBAC, Storage Entra-only authorization, private DNS zones and no public workload ingress. Nothing is deployed unless operator chooses to apply and provides cost acknowledgement.
- **Optional Firewall Premium** starts with IDPS **Alert**, not Deny; there is no sample allow-all collection and no claim that TLS inspection is active. You must add policy, validate essential Azure control-plane FQDNs, DNS paths and permitted egress before attaching forced-tunnel routes in a production environment.
- **Optional ACA** internal managed environment DNS is mapped to its internal static IP. This is **not** the distinct Private Link endpoint mode for ACA; the two should not be confused. Application/container identity, probes, revision strategy and ingress are workload-owned and not provisioned here.
- **No network probe from public CI**: `probe` only runs when explicitly invoked from a trusted peered network with a known endpoint IP. Public CI only runs deterministic snapshot tests.
- **Hub-spoke CIDRs are fixed lab examples.** Use an assigned address plan and verify VNet overlap before deployment.
- RBAC assignments, private Azure SQL/Service Bus/APIM, production policy, listener TLS binding, bastion, WAF and diagnostics are **extensions**, not deployed as completed features. See the expansion guide.

## Validation levels

1. `bicep build` is static syntax/type checking (requires Azure CLI+Bicep).
2. `az deployment sub validate` checks Azure-side requirements subject to subscription permissions.
3. `az deployment sub what-if` previews changes but is not infallible.
4. `az-private-ready assess snapshot.json` finds misconfiguration evidence in an exported resource set; missing values are `UNKNOWN`.
5. `az-private-ready probe <host> --expected-ip <ip>` tests DNS+verified TLS from one approved VNet vantage point.
6. Effective route tables, IP flows, firewall application rules, traffic inspection, certificate chains, private FQDN requirements and actual access controls require live Azure testing.

## Source of truth

Official Microsoft documentation:

- [Azure Private Endpoints for Container Apps](https://learn.microsoft.com/azure/container-apps/private-endpoints-with-dns)
- [Azure APIM inbound private endpoint limits](https://learn.microsoft.com/azure/api-management/private-endpoint)
- [Firewall Policy ARM/Bicep resources](https://learn.microsoft.com/azure/templates/microsoft.network/firewallpolicies)
- [Subscription-scoped deployment what-if](https://learn.microsoft.com/cli/azure/deployment/sub)
