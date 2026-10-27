# Azure Private Landing Zone Lab

**Private Azure networking diagnostics, deployment readiness and drift detection — with reproducible Bicep infrastructure and an offline Python CLI.**

A useful engineering toolkit for Azure platform teams operating hub-spoke landing zones, Azure Firewall, Private Link, managed identities, Container Apps and Azure DevOps. Not affiliated with Microsoft.

> **Safety boundary:** Reference implementation, not a certified secure landing zone or an automatic production remediation engine. No resources are created until an engineer explicitly opts into an Azure deployment. Offline fixtures are synthetic; a `PASS` covers only an observed property, not effective connectivity or ISO/NIS2 compliance.

## Why build this?

A cloud configuration can look private in ARM/Bicep while traffic still fails because DNS has the wrong forwarding path, a route table is unassociated, or a subnet points to an old firewall IP. This project makes those gaps **visible, testable and actionable**, and keeps missing evidence separate from failures.

## Use it in five minutes (no Azure subscription required)

```bash
python -m pip install -e .
az-private-ready topology examples/topology.json
az-private-ready assess tests/fixtures/compliant.json --format json
az-private-ready assess tests/fixtures/broken.json --format markdown --output report.md
az-private-ready assess tests/fixtures/broken.json --relationships --format sarif --output report.sarif
python -m unittest discover -s tests -v
```

The broken fixture intentionally exits `2`; an input error exits `3`, while a successful assessment exits `0`. Use `--fail-on none` for evidence-only reports.

## Offline end-to-end validation (no Azure subscription required)

The toolkit includes a deterministic Azure-style estate simulator and a full CLI
verification harness. It checks mock-paginated Resource Graph export, subnet
field-preservation, 4 injected failures, drift/SARIF, waivers, missing-evidence
semantics, effective routes, topology and performance at scale.

```bash
python -m pip install -e .
python scripts/offline_validation.py --spokes 6 --benchmarks 10,100,1000,2000 --repeat 5 --output offline-results.json
az-private-ready simulate --spokes 5 --inject-faults --output synthetic-failures.json
az-private-ready assess synthetic-failures.json --relationships --format sarif --output findings.sarif
```

Every generated snapshot explicitly declares `SYNTHETIC_OFFLINE_FIXTURE`:
passing simulated checks is **not evidence from a live Azure tenant**.
See [E2E methodology, performance metrics, and offline/live validation limits](docs/offline-validation.md).

## Features

| Component | Practical value |
|---|---|
| **Snapshot rule engine** | Evaluates selected hub-spoke, firewall, NSG, private DNS/endpoint, Storage, Key Vault, SQL, Service Bus, APIM and Container Apps controls. Missing fields become `UNKNOWN`. |
| **Cross-resource graph checks** | Optional `--relationships` verifies subnet/NSG and subnet/UDR attachment, route next-hop against the *actual firewall IP*, subnet CIDR overlap and endpoint-to-target evidence. Missing child objects remain `UNKNOWN`. |
| **Topology preflight** | Pure-Python IPv4 planner catches CIDR overlaps, out-of-VNet subnets, Azure Firewall `/26`, Container Apps `/27` or legacy `/23`, missing workload NSG/forced-egress routes. |
| **Live read-only exporter** | Via Azure CLI Resource Graph; explicit subscription scope, stable pagination, strict nested field allowlists, no secret/credential fields, no incomplete output after errors. |
| **Effective NIC route validation** | Analyze a captured `az network nic show-effective-route-table` JSON for the actual longest-prefix route, UDR priority and optional expected firewall IP. |
| **Drift comparison** | Stable rule/resource fingerprints highlight new failures and distinguish resources that stopped appearing from those that were fixed. |
| **Security exceptions** | Exact resource+rule waivers, mandatory rationale, approver and expiry, original failing evidence retained. No wildcard skips. |
| **CI-friendly reports** | Markdown, JSON or SARIF 2.1.0; configurable failure threshold. No cloud credentials in unit tests. |
| **Private TLS/DNS probe** | Opt-in hostname + approved RFC1918 IPs; verifies private DNS match and CA-validated TLS with the real SNI hostname, from an in-VNet agent. |
| **Bicep sandbox** | Subscription-scope resource group and reusable hub/spoke foundation. Defaults keep Firewall Premium and Container Apps off to avoid surprise high-cost services. |
| **Azure DevOps deployment** | Five named environments with explicit deployment opt-in, validate/what-if and environment approvals. Use Workload Identity Federation and appropriate self-hosted agent. |
| **Incident runbooks** | Practical Private Link, firewall/IDPS and TLS certificate investigation/rollback; sample KQL queries. |

### Read-only Azure assessment

Install Azure CLI and its Resource Graph extension; authenticate with Reader permissions for explicitly chosen subscriptions. The exporter does not query arbitrary subscriptions.

```bash
az login
az extension add --name resource-graph
az-private-ready export --subscription <subscription-guid> --output tenant.json
az-private-ready assess tenant.json --relationships --format markdown --output readiness.md
az-private-ready diff approved.json tenant.json --relationships --fail-on-regression
```

Keep `tenant.json` **private**: although credentials and unrelated ARM fields are not exported, subscription IDs, resource names, CIDRs and topology metadata still reveal internal infrastructure. See [live assessment guide](docs/live-assessment.md).

### Validate an effective NIC route, not just a route table

```bash
az network nic show-effective-route-table -g <resource-group> -n <nic-name> -o json > routes.json
az-private-ready effective-routes routes.json --destination 8.8.8.8 --firewall-ip 10.80.0.4
```

The sample is reproducible with `examples/effective-routes.json`. A NIC must be attached to a running VM for meaningful Azure effective-route data; use Azure Network Watcher **next hop** to confirm an actual path. Never treat a declarative UDR alone as proof.

### Network planning before deployment

Edit `examples/topology.json`, then:

```bash
az-private-ready topology examples/topology.json --format markdown
```

This validates the *proposed IP plan*, not an already deployed Azure tenant. In the Bicep foundation, network CIDRs are example defaults; change them for your existing address plan and inspect any connections to shared hubs before deployment.

### Probe a private endpoint from within your network

```bash
az-private-ready probe mystorage.blob.core.windows.net --expected-ip 10.85.0.7
```

Only explicitly approved private addresses are contacted. A passing probe confirms local DNS resolution and authenticated TLS for this hostname/path; **not** that public access is disabled or application RBAC is correct. Never run this against a third party or from public CI expecting a meaningful private-network result.

## Deployment (opt-in and billable)

1. Review [the architecture](docs/architecture.md), [operation notes](docs/operations.md) and Azure costs. The current Bicep provisions a **new sandbox**, not an existing shared corporate landing zone.
2. `az bicep build --file infra/main.bicep` on a machine with the Azure CLI/Bicep extension.
3. `az deployment sub validate` and `az deployment sub what-if` with `environment`, location and `costAcknowledgement=I_ACCEPT_AZURE_CHARGES`.
4. Start with `deployFirewall=false`, `deployContainerApps=false`. Even the baseline resources incur charges; confirm budgets and ownership.
5. Proceed only after a security-reviewed change request, then run in-network verification and log any rollback/incident steps.

`infra/main.bicep` is a reference starting point, **not** a production-ready Azure Landing Zones implementation. Don't deploy it directly into an existing organization hub. The APIM/SQL/Service Bus control-plane analyzer covers inventory even though those deployment modules are **not** included in this Bicep foundation.

## Engineering references

- [Rule catalog and evidence levels](docs/controls.md)
- [Live assessment / drift workflow](docs/live-assessment.md)
- [Private Link troubleshooting](docs/runbooks/private-link.md)
- [Azure Firewall, DNS proxy, TLS & IDPS runbook](docs/runbooks/firewall.md)
- [TLS certificate renewals](docs/runbooks/certificates.md)
- [Architecture and threat boundaries](docs/architecture.md)
- [Azure operations & cost controls](docs/operations.md)
- [Log Analytics KQL samples](queries/)

## Limitations and contributions

Resource Graph inventory is eventually consistent and may omit certain child resources. NSG inspection is conservative: it flags **potential** exposure, not priority-resolved effective rules. The exporter only knows the resource types listed in `src/az_ready/exporter.py`, and topology planning supports IPv4. No TLS interception or automated firewall changes occur. Azure infrastructure builds/deployments still need independent subscription validation; tests here run offline by design.

**PRs welcome:** share a *sanitized* failing snapshot, describe expected and observed behavior and add a regression test. Do not paste tenant exports, addresses, subscription IDs, credentials or production incident logs into public GitHub issues.

Search terms: **Azure landing zone**, **hub spoke network**, **Azure private endpoint diagnostics**, **Azure Firewall DNS Proxy**, **Bicep**, **Azure DevOps**, **Private DNS**, **Resource Graph**, **DevSecOps**, **Azure Container Apps**, **drift detection**, **Azure security validation**.

MIT license.
