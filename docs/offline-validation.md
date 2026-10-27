# Offline end-to-end validation and performance benchmarks

The goal is to catch correctness, integration and scaling regressions **before** using
an Azure subscription. All inputs are fictitious, no `az login` or Azure SDK is
needed, no network access is made, and nothing is deployed. A successful run is
**not** a certified Azure landing zone, a live network connectivity test or a
substitute for deployment validation.

## Repeat the exact E2E checks

Python 3.10+ from repository root:

```bash
python -m pip install -e .
python -m unittest discover -s tests -q
python scripts/offline_validation.py --spokes 6 --benchmarks 10,100,1000,2000 --repeat 5 --output offline-results.json
```

What is validated against an independently specified expected outcome:

1. `az-private-ready simulate` generates the same synthetic inventory in separate CLI processes.
2. Every generated, fully evidenced resource passes all checks (without UNKNOWN).
3. Four fault injections independently violate Key Vault RBAC, Storage public access, Private Endpoint approval, and firewall UDR linkage; all four are detected.
4. `diff --fail-on-regression` finds exactly those four regressions, and each SARIF issue has a stable unique fingerprint.
5. A resource-scoped exception waives just one failure; the remaining three still fail the pipeline.
6. Removing DNS zone-group evidence yields UNKNOWN, not a false PASS or false FAIL.
7. A **mocked Azure CLI subprocess boundary** returns real Azure Resource Graph-shaped pages to the real exporter and sanitizer. After pagination and sanitization, findings must exactly match the original inventory. This catches broken field projections (e.g. subnet arrays).
8. CLI network topology flags overlapping subnet CIDRs.
9. Effective route selection catches a more-specific Internet route bypassing a firewall default route.
10. Malformed JSON inventories fail with documented exit status 3.
11. Reordering resource records does not change findings.

The E2E runner checks expected exit statuses **0** for success, **2** for an
actionable policy failure, and **3** for invalid input. It has no access to any
Azure subscription and uses only Python standard-library modules.

## Generate smaller, inspectable scenarios

```bash
az-private-ready simulate --spokes 5 --output example.json
az-private-ready simulate --spokes 5 --inject-faults --output failures.json
az-private-ready assess example.json --relationships --format json --output pass.json
az-private-ready assess failures.json --relationships --format sarif --output findings.sarif
az-private-ready diff example.json failures.json --relationships --fail-on-regression
```

`simulate` always writes `"notLiveAzureEvidence": true` and
`"source": "SYNTHETIC_OFFLINE_FIXTURE"`. Do not upload generated snapshots as
actual security assessments.

## Benchmark methodology

- Sizes are **spokes**, not records: each spoke adds nine Azure-style resources and around nineteen checks.
- Fixed deterministic inputs; no randomness, internet, credentials or network calls.
- Each size runs in its own fresh process to reduce interference and isolate peak RSS.
- One unmeasured warm-up followed by the requested number of timed iterations.
- Wall-clock `perf_counter` medians and ranges; all times are reported in milliseconds.
- Separately measure resource checks, cross-resource relationships, full analysis, JSON report serialization, **mocked paginated export → assess → report** and an **actual CLI subprocess** loading JSON and writing a report.
- Resource throughput is `resource_count / median_full_assessment_seconds`, **not** real tenant discovery throughput.
- Peak resident memory is measured on POSIX, reported as MiB. Windows reports `null`.
- Performance results depend on CPU contention, Python version, IO/cache state and host. No fixed timing assertion is used in CI; CI verifies correctness at smaller sizes, while full benchmarks are informational.
- `export_assess_report_ms` includes in-process fake transport JSON encode/decode, not network RTT, API throttling or Azure Resource Graph indexing time.

Example extended run:

```bash
python scripts/offline_validation.py --spokes 8 \
  --benchmarks 10,100,1000,2000,5000 --repeat 7 \
  --output offline-results.json
```

Compare two benchmark reports using the same machine and Python version. Core
analysis is optimized using pre-indexed private DNS zone-group children (linear
rather than repeated full-estate scans). Normalization is tested against the
same control oracles to prevent benchmark-only optimizations that change results.

## What cannot be proven offline

| Capability | Status |
|---|---|
| Resource Graph export command / pagination / sanitizer | **Simulated transport, real parsing** |
| Control checks and link consistency | **Validated with synthetic evidence** |
| Routing decisions from captured NIC effective routes | **Validated offline against known cases** |
| SARIF, drift and CLI exit codes | **Validated end-to-end** |
| Bicep syntax/type compilation | CI Bicep job; not included unless Azure CLI/Bicep installed |
| Resource Graph real permissions, shape quirks and indexing latency | **Requires real tenant** |
| Effective packet forwarding, DNS resolver behaviour, SNI/certificate checks | **Requires VNet-connected probe** |
| Firewall Premium IDPS/TLS inspection under actual policy | **Requires live sandbox** |
| Approval workflows, rollback and service health | **Requires Azure DevOps / Azure** |
| Cloud running cost, quotas and throttling | **Requires Azure** |

No claim that an offline emulation fully validates Azure itself. The purpose is
to make an eventual *small* live sandbox pilot more predictable and cheaper.

## CI integration

`.github/workflows/tests.yml` runs the unit tests and a small E2E/benchmark job
without cloud credentials. The separate Bicep job compiles IaC (no deployment).
The E2E JSON evidence is retained as a workflow artifact where supported.

## A bug found by this method

The initial exporter mistakenly treated `virtualNetworks.properties.subnets`
as a dictionary instead of an array. A direct fixture against the raw snapshot
passed, but the same fixture round-tripped through the real sanitizer lost
subnet evidence. An export round-trip test now prevents that regression.
