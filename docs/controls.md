# Control catalog and evidence levels

| Group | Rule(s) | What evidence means | What it does **not** prove |
|---|---|---|---|
| Perimeter | NSG_PUBLIC_ADMIN | A potential broad inbound administrative rule is present | Effective traffic; NSG priority/shadowing is not modeled |
| Egress | DEFAULT_ROUTE, SUBNET_FIREWALL_MATCH | Declared 0/0 virtual appliance and optionally known firewall IP match | Effective NIC route or actual packets reaching firewall |
| Subnets | SUBNET_NO_OVERLAP, SUBNET_NSG_ATTACHED | CIDR conflicts or NSG object association | Firewall policy or host access permissions |
| Private Link | PE_APPROVED, PE_ZONE_GROUP_PRESENT, PE_DNS_GROUP | Declared endpoint approval / DNS group in supplied evidence | DNS response at application host |
| DNS | DNS_LINK, FW_DNS_PROXY | Private zone link completion and proxy flag | Conditional forwarding is correctly wired end to end |
| Storage | STORAGE_PUBLIC, STORAGE_KEY, STORAGE_TLS | Selected security flags | Correct data-plane RBAC or filesystem isolation |
| Key Vault | KV_PUBLIC, KV_RBAC, KV_DENY | Selected public-access, RBAC and network ACL flags | Secret/certificate rotation or private FQDN resolution |
| SQL | SQL_PUBLIC, SQL_ENTRA_ONLY | Public access and optional Entra-only child property | Admin authority, restore health or data-plane connectivity |
| Service Bus | BUS_PUBLIC, BUS_LOCAL_AUTH | Network and shared-key/local-auth flags | Service tier suitability or managed identity authorization |
| Container Apps | ACA_INTERNAL, ACA_PUBLIC | Environment declaration | Ingress reachability, backend probe success, image pull and isolation |
| APIM | APIM_PUBLIC | Public network toggle | Private inbound and outbound tier-specific design |
| Firewall | FW_PREMIUM, FW_DNS_PROXY, FW_IDPS | SKU, DNS proxy and enforcement flags | TLS inspection active, zero false positives or right rules |

**Interpretation:** `PASS` means the specified field met the check, not that the system is secure. `FAIL` means the specified field did not meet the check. `UNKNOWN` means insufficient snapshot evidence. `WAIVED` means an explicit non-expired exception for a failing/unknown rule, retaining its prior status.

The scanner is deliberately not a certification tool and does not use GDPR, NIS2 or ISO 27001 labels as assertions. Those require contextual risk assessment and independent evidence.
