"""Machine-readable reports, policy waivers, safe diff and SARIF output."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import replace
from datetime import date
from pathlib import Path

from .checks import Finding


def identity(f: Finding) -> str:
    return hashlib.sha256((f.rule + "\0" + f.resource_id.casefold()).encode()).hexdigest()[:24]


def apply_waivers(findings: list[Finding], waivers: dict, *, today: date | None = None) -> list[Finding]:
    """Explicit exact-ID waivers; retain original status in evidence and no wildcard exceptions.

    A waiver must have a human rationale, approver, and an expiry date.
    """
    today = today or date.today()
    if not isinstance(waivers, dict) or not isinstance(waivers.get("waivers"), list):
        raise ValueError("Waiver file needs a 'waivers' array")
    approved = {}
    for item in waivers["waivers"]:
        if not isinstance(item, dict):
            raise ValueError("Each waiver must be an object")
        required = ("rule", "resource_id", "reason", "approved_by", "expires")
        if any(not isinstance(item.get(field), str) or not item[field].strip() for field in required):
            raise ValueError("Waivers require rule, resource_id, reason, approved_by, expires")
        if any("*" in item[f] or "?" in item[f] for f in ("rule", "resource_id")):
            raise ValueError("Wildcards are not allowed in waivers")
        expires = date.fromisoformat(item["expires"])
        key = (item["rule"].casefold(), item["resource_id"].casefold())
        if key in approved:
            raise ValueError(f"Duplicate waiver for {key}")
        if expires >= today:
            approved[key] = item
    return [replace(f, status="WAIVED", evidence=f.evidence +
                    f" [waived: original={f.status}, until={approved[(f.rule.casefold(), f.resource_id.casefold())]['expires']}, reason={approved[(f.rule.casefold(), f.resource_id.casefold())]['reason']}]"
                    ) if f.status != "PASS" and (f.rule.casefold(), f.resource_id.casefold()) in approved else f for f in findings]


def stats(findings: list[Finding]) -> dict:
    cnt = Counter(f.status for f in findings)
    return {"total": len(findings), "pass": cnt["PASS"], "fail": cnt["FAIL"],
            "unknown": cnt["UNKNOWN"], "waived": cnt["WAIVED"],
            "high_fail": sum(f.status == "FAIL" and f.severity == "high" for f in findings)}


def diff(before: list[Finding], after: list[Finding]) -> dict:
    previous = {identity(f): f for f in before}
    current = {identity(f): f for f in after}
    events = []
    for key in sorted(set(previous) | set(current)):
        old, new = previous.get(key), current.get(key)
        if old is None:
            change = "new_resource_or_rule"
        elif new is None:
            change = "not_observed"  # Not equivalent to remediation.
        elif old.status != new.status:
            change = "changed"
        else:
            continue
        item = new or old
        events.append({"fingerprint": key, "rule": item.rule, "resource_id": item.resource_id,
                       "before": old.status if old else None, "after": new.status if new else None,
                       "change": change})
    regressions = [e for e in events if e["after"] == "FAIL" and e["before"] != "FAIL"]
    return {"regressions": len(regressions), "changes": events}


def to_sarif(findings: list[Finding], file_name: str = "snapshot.json") -> dict:
    """SARIF 2.1.0: scanner findings linked to snapshot input, not invented source line locations."""
    levels = {"high": "error", "medium": "warning", "low": "note"}
    active = [f for f in findings if f.status in ("FAIL", "UNKNOWN")]
    rules = sorted({f.rule for f in active})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "az-private-ready", "informationUri":
                                               "https://github.com/mhatipog/azure-private-landing-zone-lab",
                                               "rules": [{"id": r, "name": r, "shortDescription": {"text": r.replace('_', ' ').title()}} for r in rules]}},
                      "results": [{"ruleId": f.rule, "level": "note" if f.status == "UNKNOWN" else levels[f.severity],
                                   "message": {"text": f"{f.status}: {f.resource_id}: {f.fix}"},
                                   "fingerprints": {"az-private-ready/v1": identity(f)},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": Path(file_name).name},
                                                                       "region": {"startLine": 1}}}]} for f in active]}]}


def json_report(findings: list[Finding]) -> str:
    return json.dumps({"summary": stats(findings), "findings": [f.to_dict() for f in findings]}, indent=2) + "\n"
