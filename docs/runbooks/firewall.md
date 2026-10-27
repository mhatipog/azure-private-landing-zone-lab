# Runbook: firewall routing, DNS proxy, TLS and IDPS

1. Correlate a blocked request with its source/destination IP/FQDN, policy collection/rule, firewall instance, timestamp and application correlation ID.
2. Check the spoke's associated UDR and effective route to the destination, not just a declarative 0/0 rule. Resolve the actual firewall private IP and compare with the route target. Beware asymmetric paths and service endpoints/private endpoints.
3. For FQDN rules, determine which resolver the source uses, whether Azure Firewall DNS Proxy is enabled, and whether custom DNS/Private Resolver forwarding reaches the right private zones.
4. In Log Analytics, begin with `AZFWNetworkRule`, `AZFWApplicationRule`, `AZFWIdpsSignature`; table availability depends on your diagnostic settings. See `queries/firewall.kql`.
5. For TLS inspection, distinguish certificate trust failure, app pinning and policy denial. Use managed CA and scoped exceptions after approval; do not disable TLS verification or globally bypass inspection.
6. For IDPS Alert -> Deny changes, assess false positives from sampled logs, baseline traffic and app health. Record policy diff and rollback version.

## Safe release / rollback pattern

- Save current firewall policy ID, rule group versions and diagnostics; apply a candidate policy to a nonproduction firewall or canary where feasible.
- Re-run Network Watcher and application smoke tests from a workload VNet.
- Only swap production association after explicit approval and a reversible change record.
- Roll back **policy association** to the known-good policy when required; capture post-rollback evidence. Do not auto-flip production firewall policies based on snapshot check failures.

**Cost:** Firewall Premium incurs significant hourly charges. This repository defaults to `deployFirewall=false` and `intrusionDetection.mode=Alert` when enabled; it never enables TLS decryption by default.
