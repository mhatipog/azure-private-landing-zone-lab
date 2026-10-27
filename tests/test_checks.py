import json
import unittest
from pathlib import Path
from unittest.mock import patch

from az_ready.checks import assess
from az_ready.cli import main, summary, markdown
from az_ready.probe import probe

ROOT = Path(__file__).parent / "fixtures"


def by_rule(findings, rule):
    return next(f for f in findings if f.rule == rule)


class AssessmentTests(unittest.TestCase):
    def test_good_snapshot(self):
        findings = assess(json.loads((ROOT / "compliant.json").read_text())["resources"])
        self.assertTrue(findings)
        self.assertEqual(summary(findings)["fail"], 0)
        self.assertEqual(summary(findings)["unknown"], 0)

    def test_problematic_snapshot(self):
        findings = assess(json.loads((ROOT / "broken.json").read_text())["resources"])
        self.assertEqual(by_rule(findings, "DEFAULT_ROUTE").status, "FAIL")
        self.assertEqual(by_rule(findings, "KV_RBAC").status, "FAIL")
        self.assertEqual(by_rule(findings, "PE_APPROVED").status, "FAIL")
        self.assertEqual(by_rule(findings, "STORAGE_KEY").status, "FAIL")
        self.assertEqual(by_rule(findings, "NSG_PUBLIC_ADMIN").status, "FAIL")
        self.assertEqual(by_rule(findings, "FW_DNS_PROXY").status, "FAIL")
        self.assertGreater(summary(findings)["high_fail"], 0)

    def test_missing_is_unknown_not_pass(self):
        f = assess([{"id": "r1", "type": "Microsoft.Storage/storageAccounts", "properties": {}}])
        self.assertEqual({x.status for x in f}, {"UNKNOWN"})

    def test_order_independent_and_case_insensitive(self):
        resources = [{"id":"z", "type":"MICROSOFT.SQL/SERVERS", "Properties":{"PublicNetworkAccess":"Disabled"}},
                     {"id":"a", "type":"microsoft.sql/servers", "properties":{"publicNetworkAccess":"Enabled"}}]
        self.assertEqual(assess(resources), assess(reversed(resources)))
        self.assertEqual(assess(resources)[1].status, "PASS")

    def test_cli_output_and_exit_status(self):
        self.assertEqual(main(["assess", str(ROOT / "compliant.json"), "--format", "json", "--output", "/tmp/az-readiness-test.json"]), 0)
        self.assertEqual(main(["assess", str(ROOT / "broken.json"), "--output", "/tmp/az-readiness-bad.md"]), 2)
        self.assertEqual(main(["assess", str(ROOT / "empty-fields.json"), "--strict-unknown"]), 3)  # missing file
        self.assertIn("Recommended actions", markdown(assess(json.loads((ROOT / "broken.json").read_text())["resources"])))

    def test_reject_invalid_resource(self):
        with self.assertRaises(ValueError):
            assess([{"type": "microsoft.sql/servers"}])


class ProbeTests(unittest.TestCase):
    def test_reject_public_and_invalid_target(self):
        for candidate in (["8.8.8.8"], ["bad"], []):
            with self.assertRaises(ValueError):
                probe("example.org", candidate)
        with self.assertRaises(ValueError):
            probe("https://example.org", ["10.0.0.4"])

    @patch("az_ready.probe.socket.getaddrinfo")
    @patch("az_ready.probe.socket.create_connection")
    def test_dns_mismatch_prevents_connection(self, connect, resolver):
        resolver.return_value = [(None, None, None, None, ("10.0.0.55", 443))]
        outcome = probe("example.org", ["10.0.0.4"])
        self.assertEqual(outcome["stage"], "dns")
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
