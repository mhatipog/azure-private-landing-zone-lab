#!/usr/bin/env python3
"""End-to-end offline test, chaos test and reproducible performance benchmark.

Exercises the real CLI in subprocesses, mocks *only* the Azure CLI Resource Graph
transport, and checks explicit fault-injection oracles. No Azure credentials,
network calls or resources. Benchmark workers run in isolated subprocesses to
obtain comparable peak memory. Fixed data / no pseudorandom input.

Run: python scripts/offline_validation.py --benchmarks 10,100,1000,2000
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
try:
    import resource
except ImportError:  # The CLI/tests run on Windows; RSS instrumentation is POSIX-only.
    resource = None
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from az_ready.checks import assess
from az_ready.effective_routes import evaluate_routes
from az_ready.exporter import export
from az_ready.relationships import assess_relationships
from az_ready.reports import diff, json_report, stats, to_sarif
from az_ready.simulator import FIREWALL_IP, inject_faults, simulate_estate


def assert_check(ok: bool, description: str, checks: list[str]) -> None:
    if not ok:
        raise AssertionError(description)
    checks.append(description)


def cli(*argv: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
    result = subprocess.run([sys.executable, "-m", "az_ready", *map(str, argv)],
                            cwd=ROOT, env=env, capture_output=True, text=True,
                            timeout=45, check=False)
    if result.returncode != expected:
        raise AssertionError(f"CLI exit expected={expected} actual={result.returncode}: {argv}, stderr={result.stderr[:400]}")
    return result


def verify(spokes: int) -> dict[str, Any]:
    if not 1 <= spokes <= 100:
        raise ValueError("Use 1..100 spokes for the full CLI E2E test; use --benchmarks for scale")
    checks: list[str] = []
    with tempfile.TemporaryDirectory(prefix="az-ready-offline-") as tmp:
        work = Path(tmp)
        good, bad = work / "synthetic.json", work / "mutated.json"
        cli("simulate", "--spokes", str(spokes), "--output", str(good))
        cli("simulate", "--spokes", str(spokes), "--inject-faults", "--output", str(bad))
        original = json.loads(good.read_text())
        altered = json.loads(bad.read_text())
        assert_check(original["notLiveAzureEvidence"] and original["source"] == "SYNTHETIC_OFFLINE_FIXTURE",
                     "All simulated inventory clearly labeled synthetic", checks)
        assert_check(len(original["resources"]) == 9 * spokes + 3,
                     "Generator estate size matches expected resource count", checks)
        assert_check(original["resources"] != altered["resources"], "Faults alter inventory", checks)
        cli("simulate", "--spokes", str(spokes), "--output", str(work / "repeat.json"))
        assert_check(good.read_bytes() == (work / "repeat.json").read_bytes(),
                     "Exact reproducibility across separate CLI processes", checks)

        good_report, bad_report = work / "good-report.json", work / "bad-report.json"
        cli("assess", str(good), "--relationships", "--format", "json", "--output", str(good_report))
        cli("assess", str(bad), "--relationships", "--format", "json", "--output", str(bad_report), expected=2)
        before, after = json.loads(good_report.read_text()), json.loads(bad_report.read_text())
        assert_check(before["summary"]["total"] == 19 * spokes + 4 and
                     before["summary"]["pass"] == before["summary"]["total"] and
                     before["summary"]["unknown"] == before["summary"]["fail"] == 0,
                     "All generated baseline controls PASS with complete evidence", checks)
        failing_rules = {f["rule"] for f in after["findings"] if f["status"] == "FAIL"}
        _, injected_rules = inject_faults(original["resources"])
        assert_check(failing_rules == injected_rules and after["summary"]["fail"] == 4,
                     "Exactly four independent injected faults detected, no spurious failures", checks)

        dr = work / "drift.json"
        cli("diff", str(good), str(bad), "--relationships", "--fail-on-regression", "--output", str(dr), expected=2)
        assert_check(json.loads(dr.read_text())["regressions"] == 4,
                     "Drift analysis independently detects all four regressions", checks)
        sarif_path = work / "alerts.sarif"
        cli("assess", str(bad), "--relationships", "--format", "sarif", "--output", str(sarif_path), expected=2)
        sarif = json.loads(sarif_path.read_text())
        results = sarif["runs"][0]["results"]
        assert_check(sarif["version"] == "2.1.0" and len(results) == 4 and
                     len({r["fingerprints"]["az-private-ready/v1"] for r in results}) == 4,
                     "SARIF 2.1.0 emits four unique stable security alerts", checks)

        waivers_path, waived_path = work / "waivers.json", work / "waived.json"
        fault = next(f for f in after["findings"] if f["rule"] == "STORAGE_PUBLIC")
        waivers_path.write_text(json.dumps({"waivers": [{"rule": "STORAGE_PUBLIC",
            "resource_id": fault["resource_id"], "reason": "offline scenario test",
            "approved_by": "simulation", "expires": "2099-12-31"}]}))
        cli("assess", str(bad), "--relationships", "--waivers", str(waivers_path),
            "--format", "json", "--output", str(waived_path), expected=2)
        waived = json.loads(waived_path.read_text())["summary"]
        assert_check(waived["waived"] == 1 and waived["fail"] == 3,
                     "Exact resource waiver retained, remaining failures still block", checks)

        missing = copy.deepcopy(original)
        missing["resources"] = [r for r in original["resources"] if
            r["type"].casefold() != "microsoft.network/privateendpoints/privatednszonegroups"]
        missing_file = work / "missing.json"
        missing_file.write_text(json.dumps(missing))
        unknown_result = work / "unknown.json"
        cli("assess", str(missing_file), "--relationships", "--strict-unknown",
            "--format", "json", "--output", str(unknown_result), expected=2)
        unknown = json.loads(unknown_result.read_text())["summary"]
        assert_check(unknown["unknown"] == spokes and unknown["fail"] == 0,
                     "Missing DNS evidence becomes UNKNOWN, never PASS or fabricated FAIL", checks)

        # Real serializer/validator round trip with simulated `az graph query` pages.
        # subprocess.CompletedProcess deliberately substitutes only the network transport.
        normalized = sorted(original["resources"], key=lambda r: r["id"].casefold())
        requests = []
        def fake_az(args: list[str]) -> subprocess.CompletedProcess[str]:
            assert args[:3] == ["az", "graph", "query"]
            offset = int(args[args.index("--skip") + 1])
            size = int(args[args.index("--first") + 1])
            requests.append(offset)
            return subprocess.CompletedProcess(args, 0,
                json.dumps({"data": normalized[offset: offset + size]}), "")
        exported = export(["00000000-0000-4000-8000-000000000000"], page_size=7,
                          max_pages=spokes * 2 + 10, invoke=fake_az)
        export_findings = assess(exported["resources"]) + assess_relationships(exported["resources"])
        assert_check(len(exported["resources"]) == len(normalized) and
                     stats(export_findings) == before["summary"] and len(requests) >= 2,
                     "Mocked paginated Azure Graph export preserves assessment results", checks)
        assert_check(all(r["type"] == r["type"].casefold() for r in exported["resources"]),
                     "Resource Graph export normalizes allowed resource types", checks)

        topology = ROOT / "examples" / "topology.json"
        cli("topology", str(topology), "--output", str(work / "topology-pass.json"))
        bad_topology = json.loads(topology.read_text())
        bad_topology["vnets"][1]["subnets"][1]["cidr"] = "10.85.0.0/25"
        (work / "topology-fail.json").write_text(json.dumps(bad_topology))
        cli("topology", str(work / "topology-fail.json"), expected=2)
        assert_check(True, "Network CIDR topology detects overlapping subnets", checks)

        routes = ROOT / "examples" / "effective-routes.json"
        cli("effective-routes", str(routes), "--firewall-ip", FIREWALL_IP,
            "--output", str(work / "route-pass.json"))
        bad_routes = json.loads(routes.read_text())
        bad_routes.append({"source": "User", "state": "Active", "addressPrefix": ["8.8.8.0/24"],
                           "nextHopType": "Internet", "nextHopIpAddress": []})
        (work / "route-fail.json").write_text(json.dumps(bad_routes))
        cli("effective-routes", str(work / "route-fail.json"), "--firewall-ip", FIREWALL_IP, expected=2)
        assert_check(True, "NIC effective route longest-prefix bypass is detected", checks)

        invalid = work / "invalid.json"
        invalid.write_text('{"resources": [ { "properties": {} } ]}')
        cli("assess", str(invalid), expected=3)
        assert_check(True, "Malformed resource inventory fails closed with documented exit code", checks)

        # Metamorphic property: order of Resource Graph rows cannot affect findings.
        resources = original["resources"]
        expected_findings = assess(resources) + assess_relationships(resources)
        reversed_findings = assess(list(reversed(resources))) + assess_relationships(list(reversed(resources)))
        assert_check(sorted((f.rule, f.resource_id, f.status) for f in expected_findings) ==
                     sorted((f.rule, f.resource_id, f.status) for f in reversed_findings),
                     "Assessment independent of Resource Graph record order", checks)

    return {"status": "PASS", "checks": len(checks), "check_names": checks,
            "spokes": spokes, "resources": len(original["resources"]),
            "findings": before["summary"]["total"], "injected_regressions": 4,
            "export_pages": len(requests), "network_requests": 0,
            "azure_deployments": 0, "mode": "synthetic-only"}


def _timed(fn, repeats: int) -> dict:
    samples = []
    value = None
    for n in range(repeats + 1):  # first one is warm-up
        start = time.perf_counter()
        value = fn()
        elapsed = time.perf_counter() - start
        if n:
            samples.append(elapsed)
    return {"median_ms": round(statistics.median(samples) * 1000, 3),
            "min_ms": round(min(samples) * 1000, 3),
            "max_ms": round(max(samples) * 1000, 3), "value": value}


def benchmark_worker(spokes: int, repeats: int) -> dict:
    estate = simulate_estate(spokes)
    core = _timed(lambda: assess(estate), repeats)
    relations = _timed(lambda: assess_relationships(estate), repeats)
    full = _timed(lambda: assess(estate) + assess_relationships(estate), repeats)
    serialize = _timed(lambda: json_report(full["value"]), repeats)
    raw_size = len(json.dumps({"resources": estate}, separators=(",", ":")).encode())
    ordered = sorted(estate, key=lambda r: r["id"].casefold())
    def mock_az(args):
        skip = int(args[args.index("--skip") + 1])
        length = int(args[args.index("--first") + 1])
        return subprocess.CompletedProcess(args, 0,
            json.dumps({"data": ordered[skip:skip + length]}), "")
    def end_to_end():
        exported = export(["synthetic-subscription"], page_size=500,
                          max_pages=spokes // 20 + 50, invoke=mock_az)
        analyzed = assess(exported["resources"]) + assess_relationships(exported["resources"])
        return json_report(analyzed)
    pipeline = _timed(end_to_end, repeats)
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "inventory.json"
        snapshot.write_text(json.dumps({"resources": estate}))
        output = Path(tmp) / "assessment.json"
        def cli_once():
            result = cli("assess", str(snapshot), "--relationships", "--format", "json",
                         "--output", str(output))
            return output.stat().st_size
        cli_latency = _timed(cli_once, repeats)
    findings = full["value"]
    if stats(findings)["fail"] or stats(findings)["unknown"]:
        raise AssertionError("Cannot benchmark a broken reference estate")
    info = {"spokes": spokes, "resources": len(estate), "findings": len(findings),
            "snapshot_bytes": raw_size, "core_ms": core["median_ms"],
            "relationships_ms": relations["median_ms"], "assess_ms": full["median_ms"],
            "report_ms": serialize["median_ms"], "export_assess_report_ms": pipeline["median_ms"],
            "cli_json_assess_ms": cli_latency["median_ms"],
            "assess_min_ms": full["min_ms"],
            "assess_max_ms": full["max_ms"],
            "throughput_resources_per_s": round(len(estate) / max(full["median_ms"] / 1000, .000001)),
            "peak_rss_mib": (round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)
                             if resource and sys.platform != "darwin" else
                             round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024), 2)
                             if resource else None),
            "repeat": repeats}
    return info


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--spokes", type=int, default=6, help="Number of spokes in real CLI E2E tests")
    p.add_argument("--benchmarks", default="10,100,1000,2000", help="Comma-separated spoke sizes")
    p.add_argument("--repeat", type=int, default=5, help="Measurements per benchmark, plus one warmup")
    p.add_argument("--output", type=Path, help="Write complete machine-readable evidence JSON")
    p.add_argument("--worker-spokes", type=int, help=argparse.SUPPRESS)
    args = p.parse_args()
    if not 1 <= args.repeat <= 30:
        p.error("repeat must be between 1 and 30")
    if args.worker_spokes is not None:
        print(json.dumps(benchmark_worker(args.worker_spokes, args.repeat)))
        return 0
    try:
        e2e = verify(args.spokes)
        sizes = [int(part.strip()) for part in args.benchmarks.split(",") if part.strip()]
        if not sizes or len(sizes) != len(set(sizes)) or any(n < 1 or n > 60000 for n in sizes):
            raise ValueError("benchmarks must be unique comma-separated integers 1..60000")
        benchmarks = []
        for size in sizes:
            run = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                  "--worker-spokes", str(size), "--repeat", str(args.repeat)],
                                 capture_output=True, text=True, timeout=180, check=True)
            benchmarks.append(json.loads(run.stdout))
        summary = {"schemaVersion": 1, "validation": e2e, "benchmark": benchmarks,
                   "environment": {"python": platform.python_version(),
                                   "platform": platform.platform(),
                                   "architecture": platform.machine()},
                   "limits": "Synthetic input and mocked Resource Graph transport. No proof of live Azure RBAC, Azure API contract, DNS, packet routing, TLS inspection, billing, Bicep deployment or production security."}
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
        return 0
    except (AssertionError, ValueError, subprocess.SubprocessError) as exc:
        print("OFFLINE VALIDATION FAILED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
