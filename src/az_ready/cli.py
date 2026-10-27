"""Command line interface: no Azure credentials needed for assess/report."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .checks import Finding, assess
from .probe import probe


def summary(findings: list[Finding]) -> dict:
    counts = Counter(f.status for f in findings)
    return {"total": len(findings), "pass": counts["PASS"], "fail": counts["FAIL"],
            "unknown": counts["UNKNOWN"],
            "high_fail": sum(f.status == "FAIL" and f.severity == "high" for f in findings)}


def markdown(findings: list[Finding]) -> str:
    info = summary(findings)
    out = ["# Azure private readiness report", "",
           f"PASS {info['pass']} · FAIL {info['fail']} · UNKNOWN {info['unknown']}", "",
           "| Status | Severity | Rule | Resource | Evidence |", "|---|---|---|---|---|"]
    for f in findings:
        clean = lambda s: str(s).replace("|", "\\|").replace("\n", " ")[:240]
        out.append(f"| {f.status} | {f.severity} | {f.rule} | `{clean(f.resource_id)}` | {clean(f.evidence)} |")
    out.extend(["", "## Recommended actions", ""])
    for f in findings:
        if f.status != "PASS":
            out.append(f"- **{f.rule}** ({f.status}, `{f.resource_id}`): {f.fix}")
    out.extend(["", "> Snapshot evidence only; does not demonstrate effective routing, end-to-end reachability, TLS inspection or compliance certification."])
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="az-private-ready", description="Azure private landing-zone readiness checks")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("assess", help="Evaluate a JSON resource snapshot offline")
    a.add_argument("snapshot", type=Path)
    a.add_argument("--format", choices=["markdown", "json"], default="markdown")
    a.add_argument("--output", type=Path)
    a.add_argument("--fail-on", choices=["high", "any", "none"], default="high")
    a.add_argument("--strict-unknown", action="store_true")
    d = sub.add_parser("probe", help="Verify approved private DNS IP and authenticated TLS from inside a VNet")
    d.add_argument("hostname")
    d.add_argument("--expected-ip", required=True, action="append", help="Allowed private endpoint IP (repeatable)")
    d.add_argument("--port", type=int, default=443)
    d.add_argument("--timeout", type=float, default=3)
    ns = p.parse_args(argv)
    if ns.command == "probe":
        result = probe(ns.hostname, ns.expected_ip, ns.port, ns.timeout)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "PASS" else 2
    try:
        raw = json.loads(ns.snapshot.read_text(encoding="utf-8"))
        resources = raw if isinstance(raw, list) else raw.get("resources", raw.get("data"))
        if not isinstance(resources, list):
            raise ValueError("Expected JSON list or object containing 'resources' list")
        findings = assess(resources)
        result = (json.dumps({"summary": summary(findings), "findings": [f.to_dict() for f in findings]}, indent=2) + "\n"
                  if ns.format == "json" else markdown(findings))
        if ns.output:
            ns.output.parent.mkdir(parents=True, exist_ok=True)
            ns.output.write_text(result, encoding="utf-8")
        else:
            print(result, end="")
        return 2 if ((ns.fail_on == "high" and summary(findings)["high_fail"]) or
                     (ns.fail_on == "any" and summary(findings)["fail"]) or
                     (ns.strict_unknown and summary(findings)["unknown"])) else 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
