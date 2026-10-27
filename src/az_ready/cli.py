"""CLI with offline validation and strictly opt-in read-only Azure Resource Graph export."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import Finding, assess
from .exporter import export
from .effective_routes import evaluate_routes
from .probe import probe
from .relationships import assess_relationships
from .reports import apply_waivers, diff, json_report, stats, to_sarif
from .simulator import inject_faults, simulate_estate
from .topology import validate_topology


def summary(findings: list[Finding]) -> dict:
    return stats(findings)


def markdown(findings: list[Finding]) -> str:
    info = stats(findings)
    out = ["# Azure private readiness report", "",
           f"PASS {info['pass']} · FAIL {info['fail']} · UNKNOWN {info['unknown']} · WAIVED {info['waived']}", "",
           "| Status | Severity | Rule | Resource | Evidence |", "|---|---|---|---|---|"]
    for f in findings:
        clean = lambda s: str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")[:220]
        out.append(f"| {f.status} | {f.severity} | {f.rule} | `{clean(f.resource_id)}` | {clean(f.evidence)} |")
    out.extend(["", "## Recommended actions", ""])
    for f in findings:
        if f.status in ("FAIL", "UNKNOWN"):
            out.append(f"- **{f.rule}** ({f.status}, `{f.resource_id}`): {f.fix}")
    out.extend(["", "> Control-plane snapshot evidence only; not proof of effective routing, reachability, TLS inspection or compliance certification."])
    return "\n".join(out) + "\n"


def _load_snapshot(path: Path) -> list[dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    resources = raw if isinstance(raw, list) else raw.get("resources", raw.get("data")) if isinstance(raw, dict) else None
    if not isinstance(resources, list):
        raise ValueError("Expected JSON list or object containing 'resources' list")
    return resources


def _findings(path: Path, relationships: bool) -> list[Finding]:
    resources = _load_snapshot(path)
    findings = assess(resources)
    if relationships:
        findings += assess_relationships(resources)
    return sorted(findings, key=lambda f: (f.resource_id.casefold(), f.rule))


def _write(content: str, path: Path | None) -> None:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    else:
        print(content, end="")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="az-private-ready", description="Evidence-based Azure private landing zone checks")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("assess", help="Assess offline JSON resource snapshot")
    a.add_argument("snapshot", type=Path)
    a.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    a.add_argument("--output", type=Path)
    a.add_argument("--fail-on", choices=["high", "any", "none"], default="high")
    a.add_argument("--strict-unknown", action="store_true")
    a.add_argument("--relationships", action="store_true", help="Check subnet, route and endpoint relationships")
    a.add_argument("--waivers", type=Path, help="JSON exact-resource temporary waivers")
    d = sub.add_parser("probe", help="Verify expected private DNS addresses and authenticated TLS inside VNet")
    d.add_argument("hostname")
    d.add_argument("--expected-ip", required=True, action="append")
    d.add_argument("--port", type=int, default=443)
    d.add_argument("--timeout", type=float, default=3)
    e = sub.add_parser("export", help="Read-only, redacted Resource Graph inventory using az login")
    e.add_argument("--subscription", action="append", required=True)
    e.add_argument("--output", required=True, type=Path)
    e.add_argument("--page-size", type=int, default=500)
    e.add_argument("--max-pages", type=int, default=200)
    t = sub.add_parser("topology", help="Validate a proposed network CIDR plan offline")
    t.add_argument("spec", type=Path)
    t.add_argument("--output", type=Path)
    t.add_argument("--format", choices=["json", "markdown"], default="json")
    c = sub.add_parser("diff", help="Compare assessment fingerprints between two snapshots")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    c.add_argument("--relationships", action="store_true")
    c.add_argument("--fail-on-regression", action="store_true")
    c.add_argument("--output", type=Path)
    er = sub.add_parser("effective-routes", help="Analyze a NIC's captured Azure effective route table")
    er.add_argument("routes", type=Path)
    er.add_argument("--destination", default="8.8.8.8", help="IPv4 destination to evaluate (default: test route to 8.8.8.8)")
    er.add_argument("--firewall-ip", help="Expected Azure Firewall private IPv4 address")
    er.add_argument("--nic-id", default="nic")
    er.add_argument("--output", type=Path)
    sim = sub.add_parser("simulate", help="Generate explicitly synthetic, deterministic Azure-style JSON inventory (offline)")
    sim.add_argument("--spokes", type=int, default=1, help="Synthetic spoke count 1..60000")
    sim.add_argument("--inject-faults", action="store_true", help="Mutate four security controls in spoke 0")
    sim.add_argument("--output", required=True, type=Path, help="Required output path to avoid accidental stdout flooding")
    ns = p.parse_args(argv)
    try:
        if ns.command == "simulate":
            resources = simulate_estate(ns.spokes)
            if ns.inject_faults:
                resources, _ = inject_faults(resources)
            _write(json.dumps({"schemaVersion": 1, "source": "SYNTHETIC_OFFLINE_FIXTURE",
                               "notLiveAzureEvidence": True, "resources": resources},
                              indent=2) + "\n", ns.output)
            return 0
        if ns.command == "probe":
            result = probe(ns.hostname, ns.expected_ip, ns.port, ns.timeout)
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "PASS" else 2
        if ns.command == "export":
            result = export(ns.subscription, page_size=ns.page_size, max_pages=ns.max_pages)
            _write(json.dumps(result, indent=2) + "\n", ns.output)
            print(f"Exported {len(result['resources'])} sanitized metadata records to {ns.output}", file=sys.stderr)
            return 0
        if ns.command == "effective-routes":
            raw = json.loads(ns.routes.read_text(encoding="utf-8"))
            findings = evaluate_routes(raw, resource_id=ns.nic_id,
                                       expected_firewall=ns.firewall_ip, destination=ns.destination)
            _write(json_report(findings), ns.output)
            return 2 if any(f.status == "FAIL" for f in findings) else 0 if all(f.status == "PASS" for f in findings) else 3
        if ns.command == "topology":
            raw = json.loads(ns.spec.read_text(encoding="utf-8"))
            issues = validate_topology(raw)
            if ns.format == "json":
                content = json.dumps({"total": len(issues), "issues": [i.to_dict() for i in issues]}, indent=2) + "\n"
            else:
                content = "# CIDR topology preflight\n\n" + ("\n".join(f"- **{i.severity} {i.code}** `{i.path}`: {i.message}" for i in issues) or "No issues detected") + "\n"
            _write(content, ns.output)
            return 2 if issues else 0
        if ns.command == "diff":
            result = diff(_findings(ns.before, ns.relationships), _findings(ns.after, ns.relationships))
            _write(json.dumps(result, indent=2) + "\n", ns.output)
            return 2 if ns.fail_on_regression and result["regressions"] else 0
        findings = _findings(ns.snapshot, ns.relationships)
        if ns.waivers:
            findings = apply_waivers(findings, json.loads(ns.waivers.read_text(encoding="utf-8")))
        content = (json_report(findings) if ns.format == "json" else
                   json.dumps(to_sarif(findings, ns.snapshot.name), indent=2) + "\n" if ns.format == "sarif" else
                   markdown(findings))
        _write(content, ns.output)
        counts = stats(findings)
        return 2 if ((ns.fail_on == "high" and counts["high_fail"]) or
                     (ns.fail_on == "any" and counts["fail"]) or
                     (ns.strict_unknown and counts["unknown"])) else 0
    except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
