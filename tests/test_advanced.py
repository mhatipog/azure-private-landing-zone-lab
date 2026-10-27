import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from az_ready.checks import Finding, assess, has_sensitive_port
from az_ready.cli import main
from az_ready.exporter import export, sanitize, RESOURCE_TYPES
from az_ready.relationships import assess_relationships
from az_ready.reports import apply_waivers, diff, identity, stats, to_sarif
from az_ready.topology import validate_topology

ROOT = Path(__file__).parent.parent


def a(rule, status="FAIL", rid="/subscriptions/x/resourceGroups/y/providers/Microsoft.Foo/test"):
    return Finding(rule, status, "high", rid, "sample", "fix")


def topology():
    return json.loads((ROOT / "examples/topology.json").read_text())


class TopologyTests(unittest.TestCase):
    def test_valid_plan(self):
        self.assertEqual(validate_topology(topology()), [])

    def test_fails_with_missing_vnets(self):
        self.assertEqual(validate_topology({})[0].code, "SCHEMA")

    def test_invalid_vnet_ip(self):
        p = topology()
        p["vnets"][0]["cidr"] = "garbage"
        self.assertIn("INVALID_CIDR", {x.code for x in validate_topology(p)})

    def test_noncanonical_cidr(self):
        p = topology()
        p["vnets"][0]["cidr"] = "10.80.1.1/16"
        self.assertIn("INVALID_CIDR", {x.code for x in validate_topology(p)})

    def test_vnet_overlap(self):
        p = topology()
        p["vnets"][1]["cidr"] = "10.80.0.0/16"
        self.assertIn("VNET_OVERLAP", {x.code for x in validate_topology(p)})

    def test_subnet_overlap(self):
        p = topology()
        p["vnets"][1]["subnets"][1]["cidr"] = "10.85.0.0/25"
        self.assertIn("SUBNET_OVERLAP", {x.code for x in validate_topology(p)})

    def test_outside_vnet(self):
        p = topology()
        p["vnets"][1]["subnets"][1]["cidr"] = "10.86.0.0/27"
        self.assertIn("OUTSIDE_VNET", {x.code for x in validate_topology(p)})

    def test_misnamed_or_small_firewall_subnet(self):
        p = topology()
        p["vnets"][0]["subnets"][0]["name"] = "wrong"
        p["vnets"][0]["subnets"][0]["cidr"] = "10.80.0.0/27"
        self.assertIn("FIREWALL_SUBNET", {x.code for x in validate_topology(p)})

    def test_aca_size(self):
        p = topology()
        p["vnets"][1]["subnets"][2]["cidr"] = "10.85.2.0/28"
        self.assertIn("ACA_SUBNET_SIZE", {x.code for x in validate_topology(p)})

    def test_legacy_aca_size(self):
        p = topology()
        p["vnets"][1]["subnets"][2]["role"] = "container-apps-consumption-only"
        self.assertIn("ACA_SUBNET_SIZE", {x.code for x in validate_topology(p)})

    def test_nsg_required(self):
        p = topology()
        del p["vnets"][1]["subnets"][0]["nsg"]
        self.assertIn("WORKLOAD_NSG", {x.code for x in validate_topology(p)})

    def test_forced_tunnel_route_required(self):
        p = topology()
        del p["vnets"][1]["subnets"][0]["route_table"]
        self.assertIn("MISSING_EGRESS_ROUTE", {x.code for x in validate_topology(p)})

    def test_cli_preflight_status(self):
        self.assertEqual(main(["topology", str(ROOT / "examples/topology.json")]), 0)


class ExporterTests(unittest.TestCase):
    def test_allowlist_redacts_nested_sensitive_fields(self):
        r = {"id":"/subscriptions/x/f", "type":"Microsoft.Network/firewallPolicies", "properties": {
             "sku": {"tier":"Premium", "secret":"oops"}, "dnsSettings": {"enableProxy":True, "servers":["secret-dns"]},
             "transportSecurity": {"certificateAuthority":{"keyVaultSecretId":"https://example.invalid/secret"}}}}
        s = json.dumps(sanitize(r))
        self.assertNotIn("oops", s)
        self.assertNotIn("secret-dns", s)
        self.assertNotIn("keyVaultSecretId", s)
        self.assertIn('"enableProxy": true', s)

    def test_reject_unknown_resource(self):
        with self.assertRaises(ValueError):
            sanitize({"id":"a", "type":"Microsoft.Compute/virtualMachines", "properties":{"password":"test"}})

    def test_nsg_nested_projection(self):
        r = {"id":"id", "type":"Microsoft.Network/networkSecurityGroups", "properties":{"securityRules":[
            {"name":"rule", "properties":{"access":"Allow", "sourceAddressPrefix":"*", "privateData":"sensitive"}}]}}
        safe = json.dumps(sanitize(r))
        self.assertNotIn("sensitive", safe)
        self.assertIn('"access": "Allow"', safe)

    def test_exports_two_pages_and_sorts(self):
        records = [{"id":f"/a/{i}", "type":"microsoft.storage/storageaccounts", "properties":{"publicNetworkAccess":"Disabled"}} for i in range(3)]
        seen = []
        def invoke(argv):
            skip = int(argv[argv.index("--skip") + 1])
            seen.append(skip)
            return CompletedProcess(argv, 0, json.dumps({"data":records[skip:skip + 2]}), "")
        result = export(["sub-id"], page_size=2, invoke=invoke)
        self.assertEqual(seen, [0, 2])
        self.assertEqual(len(result["resources"]), 3)
        self.assertEqual(result["source"], "azure-resource-graph")

    def test_duplicate_page_is_rejected(self):
        r = {"id":"/a", "type":"microsoft.storage/storageaccounts", "properties":{}}
        def invoke(argv):
            return CompletedProcess(argv, 0, json.dumps({"data":[r]}), "")
        with self.assertRaisesRegex(RuntimeError, "Duplicate"):
            export(["sub"], page_size=1, invoke=invoke)

    def test_no_partial_export_if_page_cap_reached(self):
        def invoke(argv):
            idx = argv[argv.index("--skip") + 1]
            return CompletedProcess(argv, 0, json.dumps({"data":[{"id":f"/{idx}", "type":RESOURCE_TYPES[0], "properties":{}}]}), "")
        with self.assertRaisesRegex(RuntimeError, "cap"):
            export(["sub"], page_size=1, max_pages=2, invoke=invoke)

    def test_nonzero_exit(self):
        def invoke(argv): return CompletedProcess(argv, 1, "", "auth fail")
        with self.assertRaisesRegex(RuntimeError, "auth fail"):
            export(["sub"], invoke=invoke)

    def test_requires_subscriptions(self):
        with self.assertRaises(ValueError):
            export([], invoke=lambda a: None)


class RelationshipTests(unittest.TestCase):
    def test_missing_zone_group_is_unknown(self):
        pe = {"id":"/r/privateEndpoints/foo", "type":"microsoft.network/privateendpoints", "properties":{}}
        finding = next(f for f in assess_relationships([pe]) if f.rule == "PE_ZONE_GROUP_PRESENT")
        self.assertEqual(finding.status, "UNKNOWN")

    def test_present_zone_group(self):
        pe = {"id":"/r/privateEndpoints/foo", "type":"microsoft.network/privateendpoints", "properties":{}}
        child = {"id":pe["id"] + "/privateDnsZoneGroups/default", "type":"microsoft.network/privateendpoints/privateDnsZoneGroups", "properties":{}}
        finding = next(f for f in assess_relationships([pe,child]) if f.rule == "PE_ZONE_GROUP_PRESENT")
        self.assertEqual(finding.status, "PASS")

    def _subnet_evidence(self, hop):
        rt = "/sub/resourceGroups/rg/providers/Microsoft.Network/routeTables/main"
        vn = {"id":"/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/spoke", "type":"microsoft.network/virtualnetworks", "properties":{
              "subnets":[{"name":"workload", "id":"/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/spoke/subnets/workload",
                          "properties":{"networkSecurityGroup":{"id":"nsg"}, "routeTable":{"id":rt}, "addressPrefix":"10.85.0.0/24"}}]}}
        route = {"id":rt, "type":"microsoft.network/routetables", "properties":{"routes":[{"properties":{"addressPrefix":"0.0.0.0/0", "nextHopType":"VirtualAppliance", "nextHopIpAddress":hop}}]}}
        fw = {"id":"/sub/firewall", "type":"microsoft.network/azurefirewalls", "properties":{"ipConfigurations":[{"properties":{"privateIPAddress":"10.80.0.4"}}]}}
        return [vn,route,fw]

    def test_route_matches_actual_firewall(self):
        results = assess_relationships(self._subnet_evidence("10.80.0.4"))
        self.assertEqual(next(f for f in results if f.rule == "SUBNET_FIREWALL_MATCH").status,"PASS")

    def test_route_does_not_match_actual_firewall(self):
        results = assess_relationships(self._subnet_evidence("10.80.0.7"))
        self.assertEqual(next(f for f in results if f.rule == "SUBNET_FIREWALL_MATCH").status,"FAIL")

    def test_missing_firewall_ip_is_unknown(self):
        resources = self._subnet_evidence("10.80.0.7")[:-1]
        self.assertEqual(next(f for f in assess_relationships(resources) if f.rule == "SUBNET_FIREWALL_MATCH").status,"UNKNOWN")

    def test_subnet_overlap(self):
        resources = self._subnet_evidence("10.80.0.4")
        subnet = copy.deepcopy(resources[0]["properties"]["subnets"][0])
        subnet["id"] += "2"
        subnet["properties"]["addressPrefix"] = "10.85.0.128/25"
        resources[0]["properties"]["subnets"].append(subnet)
        self.assertEqual([f.status for f in assess_relationships(resources) if f.rule == "SUBNET_NO_OVERLAP"], ["PASS", "FAIL"])


class WaiverTests(unittest.TestCase):
    def sample(self, expiry="2099-12-31"):
        return {"waivers":[{"rule":"A", "resource_id":"/A", "reason":"accepted for migration",
                            "approved_by":"engineer", "expires":expiry}]}

    def test_waiver_does_not_remove_finding(self):
        f = apply_waivers([a("A", rid="/A")], self.sample(), today=date(2026,10,27))
        self.assertEqual(f[0].status,"WAIVED")
        self.assertIn("original=FAIL",f[0].evidence)
        self.assertEqual(stats(f)["waived"],1)

    def test_expired_waiver_does_not_work(self):
        f = apply_waivers([a("A", rid="/A")],self.sample("2000-01-01"))
        self.assertEqual(f[0].status,"FAIL")

    def test_cannot_waive_all_with_wildcards(self):
        spec = self.sample()
        spec["waivers"][0]["resource_id"] = "*"
        with self.assertRaisesRegex(ValueError, "Wildcards"):
            apply_waivers([a("A")],spec)

    def test_waiver_rejects_missing_approval(self):
        spec = self.sample()
        del spec["waivers"][0]["approved_by"]
        with self.assertRaises(ValueError):
            apply_waivers([a("A")],spec)

    def test_pass_not_waived(self):
        self.assertEqual(apply_waivers([a("A", "PASS", rid="/A")],self.sample())[0].status,"PASS")


class ReportingTests(unittest.TestCase):
    def test_deterministic_fingerprint(self):
        self.assertEqual(identity(a("test",rid="/A")),identity(a("test",rid="/a")))

    def test_diff_reports_new_failure(self):
        result = diff([a("A","PASS")],[a("A","FAIL")])
        self.assertEqual(result["regressions"],1)
        self.assertEqual(result["changes"][0]["change"],"changed")

    def test_diff_missing_resource_not_false_fix(self):
        result = diff([a("A","FAIL")],[])
        self.assertEqual(result["regressions"],0)
        self.assertEqual(result["changes"][0]["change"],"not_observed")

    def test_sarif_standard(self):
        result = to_sarif([a("A"),a("B","UNKNOWN"),a("C","PASS")],"/tmp/tenant-export.json")
        self.assertEqual(result["version"],"2.1.0")
        found = result["runs"][0]["results"]
        self.assertEqual(len(found),2)
        self.assertEqual(found[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],"tenant-export.json")

    def test_cli_assess_sarif_and_relationships(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/"sarif.json"
            rc = main(["assess",str(ROOT/"tests/fixtures/broken.json"),"--relationships","--format","sarif","--output",str(output)])
            self.assertEqual(rc,2)
            self.assertEqual(json.loads(output.read_text())["version"],"2.1.0")

    def test_cli_diff_regressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            old,new = Path(tmp)/"old.json",Path(tmp)/"new.json"
            old.write_text(json.dumps({"resources":[{"id":"a","type":"microsoft.sql/servers","properties":{"publicNetworkAccess":"Disabled"}}]}))
            new.write_text(json.dumps({"resources":[{"id":"a","type":"microsoft.sql/servers","properties":{"publicNetworkAccess":"Enabled"}}]}))
            self.assertEqual(main(["diff",str(old),str(new),"--fail-on-regression"]),2)


class NSGTests(unittest.TestCase):
    @staticmethod
    def rule(src,port):
        return {"properties":{"direction":"Inbound", "access":"Allow", "sourceAddressPrefix":src, "destinationPortRange":port}}

    def test_sensitive_port_range(self):
        self.assertTrue(has_sensitive_port(self.rule("Internet","20-23")))
        self.assertTrue(has_sensitive_port(self.rule("*","3300-3400")))

    def test_safe_ports(self):
        self.assertFalse(has_sensitive_port(self.rule("Internet","443")))
        self.assertFalse(has_sensitive_port(self.rule("10.0.0.0/8","22")))


if __name__ == '__main__':
    unittest.main()

from az_ready.effective_routes import evaluate_routes

class EffectiveRoutesTests(unittest.TestCase):
    def routes(self):
        return json.loads((ROOT / "examples/effective-routes.json").read_text())

    def test_user_route_beats_system_default(self):
        f = evaluate_routes(self.routes(), expected_firewall="10.80.0.4")
        self.assertEqual(f[0].status, "PASS")

    def test_wrong_firewall_detected(self):
        f = evaluate_routes(self.routes(), expected_firewall="10.80.0.5")
        self.assertEqual(f[0].status, "FAIL")

    def test_more_specific_route_wins(self):
        items = self.routes()
        items.append({"source":"User","state":"Active", "addressPrefix":["8.8.8.0/24"],
                      "nextHopType":"Internet", "nextHopIpAddress":[]})
        self.assertEqual(evaluate_routes(items)[0].status,"FAIL")

    def test_missing_route_unknown(self):
        self.assertEqual(evaluate_routes([], destination="8.8.8.8")[0].status,"UNKNOWN")

    def test_ignores_invalid_prefix(self):
        items = self.routes()
        items.append({"source":"User","state":"Active", "addressPrefix":["malformed"],
                      "nextHopType":"Internet"})
        self.assertEqual(evaluate_routes(items)[0].status,"PASS")

    def test_rejects_public_firewall_ip(self):
        with self.assertRaises(ValueError):
            evaluate_routes([], expected_firewall="8.8.8.8")

    def test_cli_effective_routes(self):
        self.assertEqual(main(["effective-routes",str(ROOT/"examples/effective-routes.json"),"--firewall-ip","10.80.0.4"]),0)
