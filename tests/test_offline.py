"""Regression tests for the offline estate emulator and real export normalization."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from az_ready.checks import assess
from az_ready.cli import main
from az_ready.exporter import export, sanitize
from az_ready.relationships import assess_relationships
from az_ready.reports import diff, stats
from az_ready.simulator import _spoke_cidr_prefix, inject_faults, simulate_estate


class OfflineSimulationTests(unittest.TestCase):
    def test_consistent_estate(self):
        r = simulate_estate(20)
        results = assess(r) + assess_relationships(r)
        self.assertEqual(len(r), 183)
        self.assertEqual(stats(results), {
            "total": 384, "pass": 384, "fail": 0, "unknown": 0,
            "waived": 0, "high_fail": 0})

    def test_fault_oracles(self):
        before = simulate_estate(3)
        after, expected_rules = inject_faults(before)
        previous = assess(before) + assess_relationships(before)
        current = assess(after) + assess_relationships(after)
        self.assertEqual({f.rule for f in current if f.status == "FAIL"}, expected_rules)
        self.assertEqual(diff(previous, current)["regressions"], len(expected_rules))
        self.assertEqual(stats(previous)["fail"], 0)

    def test_deterministic(self):
        self.assertEqual(simulate_estate(3), simulate_estate(3))

    def test_private_cidrs_even_after_skipping_hub_range(self):
        self.assertEqual(_spoke_cidr_prefix(0), "10.0.0")
        self.assertEqual(_spoke_cidr_prefix(20479), "10.79.255")
        self.assertEqual(_spoke_cidr_prefix(20480), "10.81.0")
        self.assertTrue(_spoke_cidr_prefix(59999).startswith("10."))

    def test_export_retains_vnet_subnets_not_null(self):
        r = next(r for r in simulate_estate(1) if r["type"] == "microsoft.network/virtualnetworks")
        sanitized = sanitize(r)
        self.assertIsInstance(sanitized["properties"]["subnets"], list)
        self.assertEqual(sanitized["properties"]["subnets"][0]["properties"]["addressPrefix"], "10.80.0.0/26")

    def test_paginated_export_preserves_relationships(self):
        resources = simulate_estate(3)
        ordered = sorted(resources, key=lambda x: x["id"].casefold())
        calls = []
        def mock_command(args):
            start = int(args[args.index("--skip") + 1])
            page_size = int(args[args.index("--first") + 1])
            calls.append(start)
            return subprocess.CompletedProcess(args, 0, json.dumps({"data": ordered[start:start + page_size]}), "")
        actual = export(["synthetic-subscription"], page_size=7, invoke=mock_command)
        self.assertGreater(len(calls), 1)
        self.assertEqual(stats(assess(actual["resources"]) + assess_relationships(actual["resources"])),
                         stats(assess(resources) + assess_relationships(resources)))

    def test_missing_child_evidence_remains_unknown(self):
        r = [x for x in simulate_estate(1) if x["type"] != "microsoft.network/privateendpoints/privatednszonegroups"]
        self.assertEqual(next(f for f in assess_relationships(r) if f.rule == "PE_ZONE_GROUP_PRESENT").status,
                         "UNKNOWN")

    def test_cli_simulation_full_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "simulated.json"
            self.assertEqual(main(["simulate", "--spokes", "2", "--output", str(p)]), 0)
            payload = json.loads(p.read_text())
            self.assertTrue(payload["notLiveAzureEvidence"])
            self.assertEqual(main(["assess", str(p), "--relationships", "--output", str(p.parent / "report.md")]), 0)
            self.assertEqual(main(["simulate", "--spokes", "2", "--inject-faults", "--output", str(p)]), 0)
            self.assertEqual(main(["assess", str(p), "--relationships", "--output", str(p.parent / "bad.md")]), 2)

    def test_invalid_inventory_fails_closed(self):
        for invalid in (None, ["bad"], [{"type": "microsoft.sql/servers"}], [{"id": ""}]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                assess(invalid if isinstance(invalid, list) else [invalid])

    def test_invalid_field_shape_fails_closed(self):
        with self.assertRaises(ValueError):
            assess([{"id": "a", "type": "microsoft.network/routetables", "properties": {"routes": "not-a-list"}}])
        with self.assertRaises(ValueError):
            assess([{"id": "a", "type": "microsoft.network/networksecuritygroups", "properties": {"securityRules": "not-a-list"}}])


if __name__ == "__main__":
    unittest.main()
