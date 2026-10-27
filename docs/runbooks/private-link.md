# Runbook: failed Azure Private Endpoint access

**Symptoms:** `PE_APPROVED`, `PE_ZONE_GROUP_PRESENT`, `PE_TARGET_EVIDENCE`, DNS/TLS `probe` errors; application cannot reach Storage, SQL, Key Vault or Service Bus.

## Check without making changes

1. Record the failing FQDN, expected Azure service subresource (`blob` vs `dfs` matters), source subnet, timestamp, correlation ID and service region.
2. Confirm target service public network access policy, private endpoint provisioning state and private link service connection **Approved** state. These are different concepts.
3. Confirm an appropriate private DNS zone group is attached; check the corresponding `privatelink.*` zone and A record; check VNet links or your central resolver/forwarding architecture. Avoid duplicate private DNS zones with conflicting answers across spokes.
4. From an approved jump host or agent inside the *source* VNet: `nslookup <hostname>` and `az-private-ready probe <hostname> --expected-ip <approved RFC1918 IP>`.
5. Compare the resolved private endpoint IP to the endpoint NIC and effective routing. If forced tunneling is enabled, verify effective routes and any required endpoint network policies; don't blindly add /32 routes.
6. Use Azure Firewall DNS Proxy and flow logs where applicable. A `PASS` TLS probe proves only this path and certificate validation; it cannot prove Entra RBAC authorization or that the service is nonpublic.

## Rollback

- Restore the last approved DNS record/forwarding configuration or endpoint-zone-group binding using a change ticket, retaining earlier exports and audit logs.
- Do not enable public network access as a troubleshooting shortcut. If temporary exception is unavoidable, require explicit risk acceptance, monitoring, narrow source restriction and expiry.
- Post-change: capture split-horizon DNS, TLS, application-level Entra authorization and application telemetry, then close the ticket.

**Pitfall:** Some Resource Graph exports omit child private DNS zone groups. The scanner reports `UNKNOWN`, not FAIL, when evidence is missing.
