# Azure Private Landing Zone Lab

**Hub–spoke Azure infrastructure as code + a testable private-network readiness checker.** Built for engineers responsible for Azure Firewall Premium, Private Endpoints/DNS, Azure Container Apps and controlled DevSecOps deployments.

> Early-stage reference implementation, not a Microsoft product or a certified secure landing zone. Offline tests pass; deployment still requires validation against an Azure subscription. No Azure resources are provisioned by cloning this repo.

## What you can run today

- **`az-private-ready`** is a pip-installable, stdlib-only Python CLI. It evaluates Resource Graph-style JSON and emits an actionable Markdown or JSON report. A missing fact is reported **UNKNOWN**, never silently treated as compliant.
- **Private DNS/TLS probe** accepts only explicitly approved private endpoint IP addresses, uses the original hostname for SNI, and fails safely if DNS points elsewhere. Run it from a VNet-connected agent, *not* from GitHub-hosted public CI.
- **Subscription-scope Bicep** provisions a new sandbox RG with hub/spoke VNets, peering, subnet separation, private endpoints + DNS for Storage and Key Vault, secure data-plane defaults; optional high-cost Azure Firewall Premium, forced routing and an internal Container Apps environment (its DNS zone must be configured after deployment).
- **Azure DevOps five-stage pipeline** (dev → test → acc → preprod → prod) with compile/validate/what-if and explicit opt-in for apply. Set deployment approvals in Azure DevOps Environments.
- Regression snapshots cover compliant, broken, and missing evidence. Public GitHub CI never needs Azure credentials.

### 60-second offline demo

```bash
python -m pip install -e .
az-private-ready assess tests/fixtures/compliant.json --format json
az-private-ready assess tests/fixtures/broken.json --output report.md
# Exit 2 = rule failures at selected threshold; exit 3 = invalid input.
```

Expected: compliant fixture reports **23 PASS**; broken fixture reports high-severity failures (routing, Key Vault, Storage, firewall DNS proxy, NSG, private endpoint approval). These are **synthetic fixtures**, not evidence from any live tenant.

### Check a known private endpoint, from a connected VNet only

```bash
az-private-ready probe mystorage.blob.core.windows.net --expected-ip 10.85.0.7
```

`PASS` means the DNS reply included the approved IP and a CA-verified TLS handshake to that IP worked with SNI `mystorage.blob.core.windows.net` from this host. It does **not** prove that public access is disabled, or that all clients can reach the service.

## Rules and evidence

| Category | What is checked |
|---|---|
| VNet | Peering connected and forwarded traffic permitted |
| Egress | Route table has a 0/0 route to a named virtual appliance |
| NSG | No explicit Internet-wide inbound SSH/RDP or all-port allow rules |
| Azure Firewall | Premium tier, DNS proxy enabled, IDPS mode (Deny vs Alert) |
| Private Link | Approved endpoint connections and nonempty private DNS zone groups |
| Private DNS | VNet links report completed |
| Storage | Public disabled, shared key disabled, TLS 1.2 |
| Key Vault | Public disabled, RBAC enabled, default deny |
| Azure SQL | Public disabled; Entra-only child resource checked if included |
| Service Bus | Public disabled and local authentication disabled |
| Container Apps | Internal environment, public network access disabled |
| API Management | Public network access disabled (tier-dependent two-step configuration) |

**Read this carefully:** resource checks are deliberately *local* and *evidence-based*. They cannot prove actual subnet association, DNS forwarding, effective firewall egress, APIM outbound isolation, end-to-end private accessibility or deployment success. An `UNKNOWN` is never a green tick. See [architecture / trust boundaries](docs/architecture.md).

## Design and rollout

1. Review [the architecture](docs/architecture.md) and [operations runbook](docs/operations.md). Confirm non-overlapping CIDRs and estimated Azure spend.
2. `az bicep build --file infra/main.bicep` to compile with the installed Azure CLI.
3. `az deployment sub what-if` with explicit cost acknowledgement before any apply.
4. Start with **`deployFirewall=false`, `deployContainerApps=false`**. Even the default provisioned resources cost money.
5. For enterprise networking, use approved shared hub and DNS architecture rather than deploying a duplicate firewall in every environment. Extend with policy tests and monitored rollback.

**Important production details:** API Management private gateway and outbound VNet integration have different tier/networking prerequisites; an internal Container Apps environment is not the same as a Container Apps private endpoint. Firewall Premium TLS inspection requires managed CA certificates and app-specific exemptions; this repo does **not** enable inspection by default. Docs: [APIM](https://learn.microsoft.com/azure/api-management/private-endpoint), [Container Apps](https://learn.microsoft.com/azure/container-apps/private-endpoints-with-dns), [Firewall](https://learn.microsoft.com/azure/templates/microsoft.network/firewallpolicies).

## Roadmap / good first contributions

- Live Resource Graph exporter with least-privilege Azure Workload Identity; normalized snapshots, tenant-safe redaction.
- Cross-resource graph checks: subnet route associations, endpoint-to-zone mapping, effective route/TLS/SNI telemetry; integrate Azure Network Watcher.
- Optional modules for APIM v2 private inbound/outbound, SQL Entra-only, Service Bus Premium and managed identity role assignments.
- Defender for Cloud recommendations, Azure Monitor KQL dashboards, CodeQL/SARIF for infrastructure checks, firewall policy blue/green and recovery tests.
- Cost estimation and policy-as-code gates for hub/spoke architecture.

## Development

Python 3.10+, no runtime dependencies. `python -m unittest discover -s tests -v`. The Bicep deployment path additionally requires Azure CLI, Bicep extension and sufficient Azure permissions. The CI pipeline deliberately doesn't deploy or authenticate.

MIT licensed. Contributions and corrections welcome; open an issue with a sanitized fixture and expected/actual finding. **Never paste a live tenant export with identifiers, secrets or connection strings into a public issue.**
