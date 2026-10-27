# Deployment assurance: prove the behaviour, not just the template

The goal is not to certify an entire tenant. It is to build a reproducible **change →
expected behaviours → actual observations → gate** chain. AI-generated Terraform,
Bicep or pipeline code can compile while breaking effective networking or service
behaviour. These checks are intended to make that failure visible before a release
is declared successful.

## Evidence ladder

| Gate | Evidence | What it cannot prove |
|---|---|---|
| `az bicep build` | Template compiles | Provider acceptance or service operation |
| `az deployment sub validate` | Provider validates template and permissions | Successful provisioning |
| `az deployment sub what-if` + `gate-whatif` | Predicted ARM changes and risk classification | Actual runtime behaviour; provider-side side effects |
| `coverage-gate` | Every changed resource has declared runtime & monitoring coverage | That a nominated probe proves the whole dependency |
| Manual Azure DevOps Environment approval | Named approver can review risk before an actual apply | A tool cannot infer human approval from an unsigned JSON file |
| `verify` from **inside each relevant VNet** | Actual DNS answers, fixed private destination IP, verified TLS certificate/SNI and HTTP status/latency | Traffic from every application/node; service RBAC; egress *denial*; IDPS effectiveness |
| `monitor-gate` from current Azure Connection Monitor logs | Observed recent tests, failure rate and explicit no-data detection | Monitoring paths not declared; complete coverage of all requests |
| `receipt` | SHA-256 link between risk and probe reports | Digital signature, immutable storage, attested source identity |

**Verdicts matter.** ARM `Create`, `Modify` and `Deploy` are REVIEW; Delete,
Unsupported, incomplete results and known high-severity predicted misconfiguration
are BLOCK. `REVIEW` must be reviewed; never turn it into automatic approval with
`|| true`. Human authorization should be protected as a separately configured Azure
DevOps Environment check. No command in this repository silently deploys, fixes
firewalls, trusts unapproved addresses, or rolls anything back.

## Azure DevOps operational examples

The separate, manually triggered [preflight pipeline](../pipelines/assurance-preflight.yml)
performs ARM what-if, identifies BLOCK/REVIEW, enforces impact coverage and
publishes evidence **without deploying**. The [postdeploy verification
pipeline](../pipelines/assurance-postdeploy.yml) executes authenticated Azure
CLI collection and in-VNet runtime probes after deployment, then publishes
observations. Both require an explicitly configured Azure service connection,
reviewed contract files and a trusted agent pool. These YAML templates have
not been run against an Azure DevOps organization here; review/test in a
non-production project first. Azure DevOps Environment manual approval rules
must be configured independently on the actual deployment stage—neither of
these diagnostic pipelines grants deployment approval.

## 1. Offline reproducibility before changing Azure

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/assurance_demo.py --output assurance-demo.json --rounds 40
```

This starts a **real local TLS server**, issues real encrypted HTTP requests and
checks four failure categories. It also exercises plan review and staleness checks.
It generates a disposable self-signed certificate at runtime, destroys it at exit,
uses loopback only, and records `notAzureEvidence=true`. The measured socket
latency is purely a local baseline, never an Azure performance claim.

## 2. Capture the actual deployment plan

From a trusted authenticated agent, in a private evidence directory:

```sh
az deployment sub what-if \
  --location westeurope \
  --template-file infra/main.bicep \
  --parameters environment=dev costAcknowledgement=I_ACCEPT_AZURE_CHARGES \
  --result-format FullResourcePayloads --no-pretty-print -o json > whatif.json
az-private-ready gate-whatif whatif.json --output plan-verdict.json
```

Exit codes are `0` (no risky changes), `2` (BLOCK or REVIEW), `3` (bad input /
missing evidence). `Review` is not equivalent to a failed deployment; it calls for
human inspection of resources, property deltas, cost, dependencies, and rollback.
`Azure what-if` can show false-positive changes when expressions cannot be
resolved; use that as a reason to investigate, **not** ignore the entire delta.
Public examples are intentionally fictitious. ARM plan JSON may contain resource
identifiers or metadata and should be retained in a restricted artifact store.

To test a dangerous change offline:

```sh
az-private-ready gate-whatif examples/assurance/whatif.demo.json
# BLOCK: predicted Storage public exposure
```

## 3. Ensure changed resources have tests

Edit reviewed, source-controlled files derived from the real architecture:
`examples/assurance/contract.sample.json`, `monitor.sample.json` and
`coverage.sample.json`. A coverage mapping binds **each changed ARM ID prefix**
to named post-deployment probes and Connection Monitor tests.

```sh
az-private-ready coverage-gate whatif.json \
  contracts/dev-services.json contracts/dev-monitor.json \
  contracts/dev-coverage.json --output coverage-verdict.json
```

Exit `2` means something changed without declared coverage. Exit `0` says only
**DECLARED_NOT_PROVEN**—not that the tests themselves are sufficient. Keep the
contracts and coverage map separate from generated IaC changes and require human
review of modifications to them. Otherwise an AI agent can remove a test as easily
as it removes a broken resource.

## 4. After approval and deployment, test real service behaviour

Run the following from a **VNet-injected self-hosted agent** in the same intended
network path as the consuming application. `verify` deliberately rejects public
and loopback addresses by default. DNS cannot return extra, unapproved answers.
Connection is pinned to an approved destination to prevent an additional DNS
lookup, with the original hostname retained for authenticated SNI/TLS.

```sh
az-private-ready verify contracts/dev-services.json \
  --samples 5 --interval 3 --output evidence/dev-network-contract.json
```

A sample contract tests an actual HTTPS health endpoint, fixed expected private
IP addresses, trusted CA and certificate hostname, expected HTTP code and a
latency budget. Put no authentication secrets in the JSON. For authenticated
business operations, add your own application-level integration tests; an HTTP
403 is evidence of *reachability* and an auth response, not proof of successful
business authorization. A failed check does not automatically attribute fault to
DNS, Firewall, NSG or the service—use Network Watcher next-hop/connection tests
and application traces to isolate the cause.

For sensitive flows, test independent vantages: application subnet, on-prem,
and any DR or private resolver network. Only listed targets are covered.

## 5. Monitor after release; do not confuse silence with health

Network Watcher Connection Monitor has real connectivity observations stored in
`NWConnectionMonitorTestResult`, including `TestResult`, `ChecksFailed`,
`ChecksTotal` and `TimeGenerated`. Enable/configure the monitors and diagnostic
workspace first. No infrastructure is provisioned by the analyzer.

```sh
export LOG_ANALYTICS_WORKSPACE_ID='WORKSPACE_GUID'
export MONITOR_SPEC=contracts/dev-monitor.json
bash scripts/live_monitor_gate.sh
```

The script queries recent Azure Monitor records and passes the *raw result* to
`monitor-gate`. The spec defines source/destination/configuration triples,
minimum recent samples, maximum failure rate and freshness. It **fails closed**
for missing rows, stale data, indeterminate/failed tests and invalid counts.
Remember ingestion can lag: do not treat immediately missing rows after first
monitor deployment as proof of outage; treat them as *insufficient evidence* and
wait for a legitimate monitoring window. For ongoing monitoring, schedule this
read-only gate on your internal runner and alert on nonzero exit codes.

Never rely on GitHub-hosted public runners to prove private connectivity.

## 6. Collect and retain independent evidence

```sh
az-private-ready receipt evidence/plan-verdict.json \
  evidence/dev-network-contract.json --release-id change-12345 \
  --output evidence/release-receipt.json
```

For a full evidence bundle, pass both `--monitor evidence/connection-monitor-verdict.json`
and `--coverage evidence/coverage-verdict.json` with `--require-complete`.
Without both, `receipt` deliberately reports `PARTIAL_EVIDENCE` and strict mode
exits 2. A REVIEW what-if is never silently approved. A complete green receipt
means only `EVIDENCE_CHECKS_PASSED_NOT_ATTESTED`, never production certification.

The receipt includes SHA-256 digests, not signatures. Keep the original JSON
reports as artifacts with restricted access, along with who approved the change,
Azure deployment-operation ID, rollout timestamps, and production logs. The
vantage point is **operator-declared and not authenticated by the CLI**. Do not
present a receipt as a signed attestation or guarantee of deployment correctness.

## 7. Recovery and continuous monitoring

- Treat an unexpected `BLOCK` as a **stop** before apply. Treat degraded runtime
  or monitoring checks as a release incident after apply; investigate first.
- Use the [firewall](runbooks/firewall.md), [Private Link](runbooks/private-link.md)
  and [certificate](runbooks/certificates.md) runbooks, app health and Azure
  Network Watcher diagnostics to isolate the fault.
- Maintain an operator-approved rollback for each change (e.g. previous image
  revision, last known-good DNS entry, known-good firewall policy). Avoid blindly
  restoring the entire ARM template or automatically undoing data migrations.
- Keep independent Azure Monitor alerts and actionable on-call ownership. This
  CLI is a bounded probe/gate, **not** an always-running monitor or alerting SaaS.

## Known blind spots

- No access to actual Azure or authenticated production evidence in offline CI.
- Certificate checks respect the local trusted CA; inspection/interception
  policy and IDPS effectiveness require additional live tests.
- A private IP DNS answer plus TLS does not prove no other route/public endpoint
  exists. Combine with policy checks, effective routes, network flow and security
  telemetry, and carefully designed negative tests.
- Resource Graph and ARM What-if may be stale/incomplete; `UNKNOWN`/`REVIEW`
  must not be silently converted to green.
- A healthy `/health` endpoint is not an application transaction. Add business
  transaction, identity, queue/database persistence, failover, restore/RTO-RPO,
  load and soak tests appropriate to each workload.
- Generated tests, contracts, source code and their success reports can all be
  fabricated. Protect them under human review, least privilege, immutable CI
  artifacts and external approval. Cryptographic signatures and trusted runner
  attestation remain future extensions.

Further independent Azure services: [ARM what-if](https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-what-if), [Network Watcher Connection Monitor](https://learn.microsoft.com/azure/network-watcher/connection-monitor-overview), [test-result schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/nwconnectionmonitortestresult).
