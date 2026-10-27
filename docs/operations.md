# Operational runbook (for a controlled non-production subscription)

## Before the first deployment

1. Confirm address plan, DNS ownership, service quotas, Azure policy, permissions, budget alert and the target subscription (`az account show`).
2. Estimate charges, especially Firewall Premium, managed Container Apps, Log Analytics and Private Link. The default deployment still incurs storage/private endpoint charges.
3. Start in a fresh sandbox RG. Do not use these fixed lab prefixes in an existing corporate network.
4. Configure a workload identity federation service connection in Azure DevOps. Pipelines must not carry client secrets or subscription credentials.
5. Register the `plz-dev`, `plz-test`, `plz-acc`, `plz-preprod`, and `plz-prod` Azure DevOps Environments; set reviewer approvals and branch checks in the portal.
6. The sample pipeline points at a named self-hosted pool. Replace only with an approved agent pool; the agent needs network reachability and must not expose elevated tokens to untrusted PRs.

## CLI

```bash
az login
az account set --subscription <YOUR_SANDBOX_SUBSCRIPTION_ID>
az bicep build --file infra/main.bicep
az deployment sub what-if --location westeurope --template-file infra/main.bicep \
  --parameters environment=dev costAcknowledgement=I_ACCEPT_AZURE_CHARGES
# Deploy only after review:
az deployment sub create --location westeurope --template-file infra/main.bicep \
  --parameters environment=dev costAcknowledgement=I_ACCEPT_AZURE_CHARGES
```

`az-private-ready assess` accepts a scrubbed Resource Graph export `{"data": [...]}` or `{"resources": [...]}` or just a resource array. Avoid publishing resource IDs from a real tenant, which may reveal infrastructure names.

## Private DNS incident

- Confirm the target endpoint connection is Approved, and private DNS zone group references the correct zone.
- Confirm a VNet link exists for the network where clients resolve names, including linked hub/resolver where appropriate.
- From an agent inside the VNet run `nslookup <service-fqdn>` and compare with the private endpoint NIC IP.
- Only then run `az-private-ready probe <service-fqdn> --expected-ip <approved-ip>`.
- If DNS is proxied through Azure Firewall, verify upstream forwarding, custom DNS settings, and `168.63.129.16` conditional resolution. Do not assume a private A record alone proves reachability.

## Forced tunneling change / rollback

- Record effective routes and firewall policy identifiers before change; establish break-glass network path.
- Deploy a scoped non-production route-table change, run Azure Network Watcher checks and service-specific smoke tests.
- If connectivity fails, roll back **the specific route-table association** or the route in the approved change, not the whole hub VNet. Do not use unreviewed generic `az group delete` scripts.
- TLS inspection requires certificate trust distribution and app compatibility validation; neither is automatically enabled here.

## Secrets, audit and privacy

Never commit tenant exports, TLS private keys, .pfx files, service connection tokens, actual CA cert bundles or logs with request payloads. Normalize/strip identifiers before issue reports. Do not treat this checker as an ISO 27001/NIS2/GDPR audit or a security scan of deployed workloads.
