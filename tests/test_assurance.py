"""Risk gates + real local TLS/HTTP integration; no Azure credentials needed."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from az_ready.assurance import gate_what_if, validate_contract, verify_contract
from az_ready.release import release_receipt

REPO = Path(__file__).resolve().parents[1]


def whatif(*changes):
    return {'status': 'Succeeded', 'properties': {'changes': list(changes), 'diagnostics': []}}


def change(t, rid='/subscriptions/demo/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct', delta=None):
    c = {'changeType': t, 'resourceId': rid}
    if delta is not None:
        c['delta'] = delta
    return c


class PlanGateTests(unittest.TestCase):
    def test_nochange(self):
        self.assertEqual(gate_what_if(whatif(change('NoChange')))['decision'], 'PASS')

    def test_empty_needs_review(self):
        self.assertEqual(gate_what_if(whatif())['decision'], 'REVIEW')

    def test_create_review(self):
        self.assertEqual(gate_what_if(whatif(change('Create')))['decision'], 'REVIEW')

    def test_modify_review(self):
        result = gate_what_if(whatif(change('Modify', delta=[{'path': 'properties.tags', 'before': {}, 'after': {}}])))
        self.assertEqual(result['decision'], 'REVIEW')

    def test_modify_sensitive(self):
        d = [{'path': 'properties', 'children': [{'path': 'properties.publicNetworkAccess', 'before': 'Disabled', 'after': 'Enabled'}]}]
        checks = gate_what_if(whatif(change('Modify', delta=d)))['checks']
        self.assertIn('WHATIF_SENSITIVE_MODIFY', {c['check'] for c in checks})

    def test_public_storage_in_predicted_after_blocked(self):
        c = change('Create')
        c['after'] = {'type': 'Microsoft.Storage/storageAccounts', 'properties': {
            'publicNetworkAccess': 'Enabled', 'allowSharedKeyAccess': False,
            'allowBlobPublicAccess': False, 'minimumTlsVersion': 'TLS1_2'}}
        result = gate_what_if(whatif(c))
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertIn('WHATIF_PREDICTED_UNSAFE', [x['check'] for x in result['checks']])

    def test_unsafe_delta_without_full_after_blocked(self):
        d = [{'path': 'properties.publicNetworkAccess', 'after': 'Enabled'}]
        result = gate_what_if(whatif(change('Modify', delta=d)))
        self.assertEqual(result['decision'], 'BLOCK')
        self.assertIn('WHATIF_PREDICTED_UNSAFE_DELTA', [c['check'] for c in result['checks']])

    def test_disabling_keyvault_rbac_blocked(self):
        d = [{'path': 'properties.enableRbacAuthorization', 'after': False}]
        result = gate_what_if(whatif(change('Modify', delta=d)))
        self.assertEqual(result['decision'], 'BLOCK')

    def test_safe_delta_remains_review_not_pass(self):
        d = [{'path': 'properties.publicNetworkAccess', 'after': 'Disabled'}]
        result = gate_what_if(whatif(change('Modify', delta=d)))
        self.assertEqual(result['decision'], 'REVIEW')

    def test_missing_delta_fails_closed(self):
        self.assertEqual(gate_what_if(whatif(change('Modify')))['decision'], 'BLOCK')

    def test_delete_blocked(self):
        self.assertEqual(gate_what_if(whatif(change('Delete')))['decision'], 'BLOCK')

    def test_unsupported_blocked(self):
        self.assertEqual(gate_what_if(whatif(change('Unsupported')))['decision'], 'BLOCK')

    def test_provisional_blocked(self):
        data = {'status': 'Succeeded', 'properties': {'potentialChanges': [change('NoChange')]}}
        self.assertEqual(gate_what_if(data)['decision'], 'BLOCK')

    def test_partial_fails_closed(self):
        data = whatif(change('NoChange'))
        data['status'] = 'Running'
        self.assertEqual(gate_what_if(data)['decision'], 'BLOCK')

    def test_protected_prefix(self):
        result = gate_what_if(whatif(change('Create')), protected=['/subscriptions/demo/'])
        self.assertEqual(result['decision'], 'BLOCK')

    def test_duplicate_ids(self):
        result = gate_what_if(whatif(change('NoChange'), change('NoChange')))
        self.assertEqual(result['decision'], 'BLOCK')

    def test_missing_changes_not_silent_pass(self):
        with self.assertRaises(ValueError):
            gate_what_if({'status': 'Succeeded', 'properties': {'diagnostics': []}})

    def test_truncated_result_guard(self):
        with self.assertRaises(ValueError):
            gate_what_if(whatif(change('NoChange'), change('NoChange', '/two')), max_changes=1)

    def test_malformed_nested_delta(self):
        with self.assertRaises(ValueError):
            gate_what_if(whatif(change('Modify', delta=[{'path': 'foo', 'children': {'x': 'y'}}])))

    def test_unknown_change_type(self):
        self.assertEqual(gate_what_if(whatif(change('NobodyKnows')))['decision'], 'BLOCK')

    def test_diagnostic_no_silent_pass(self):
        d = whatif(change('NoChange'))
        d['properties']['diagnostics'] = [{'code': 'Incomplete'}]
        self.assertEqual(gate_what_if(d)['decision'], 'REVIEW')


class ContractValidationTests(unittest.TestCase):
    @staticmethod
    def contract(ips=None, **changes):
        t = {'name': 'private-api', 'host': 'localhost', 'expectedIPs': ips or ['127.0.0.1'],
             'port': 443, 'path': '/health', 'expectedStatus': [200]}
        t.update(changes)
        return {'schemaVersion': 1, 'vantagePoint': 'unit-test', 'targets': [t]}

    def test_default_rejects_loopback(self):
        with self.assertRaises(ValueError):
            validate_contract(self.contract())

    def test_local_explicit(self):
        self.assertEqual(len(validate_contract(self.contract(), allow_loopback=True)), 1)

    def test_public_ip_rejected_even_local(self):
        with self.assertRaises(ValueError):
            validate_contract(self.contract(['8.8.8.8']), allow_loopback=True)

    def test_private_ip_accepted(self):
        doc = self.contract(['10.8.1.24'])
        self.assertEqual(len(validate_contract(doc)), 1)

    def test_ipv4_mapped_ipv6_not_approved(self):
        with self.assertRaises(ValueError):
            validate_contract(self.contract(['::ffff:10.0.0.1']), allow_loopback=True)

    def test_path_injection_rejected(self):
        for path in ['/health\r\nHost: example.com', 'https://evil.com', '/?token=abc']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_contract(self.contract(path=path), allow_loopback=True)

    def test_duplicate_targets(self):
        doc = self.contract()
        doc['targets'].append(copy.deepcopy(doc['targets'][0]))
        with self.assertRaises(ValueError):
            validate_contract(doc, allow_loopback=True)

    def test_noninteger_port(self):
        with self.assertRaises(ValueError):
            validate_contract(self.contract(port=True), allow_loopback=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 403 if self.path == '/restricted' else 500 if self.path == '/fail' else 200
        payload = b'{"contains":"sample-not-a-secret"}'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class LiveLocalTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subprocess.run(['which', 'openssl'], capture_output=True).returncode == 0:
            raise unittest.SkipTest('OpenSSL binary needed for ephemeral certificate integration')
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = str(Path(cls.temp.name) / 'cert.pem')
        cls.key = str(Path(cls.temp.name) / 'key.pem')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', cls.key, '-out', cls.cert, '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, cls.key)
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.thread.join(timeout=3)
        cls.temp.cleanup()

    def contract(self, **changes):
        t = {'name': 'internal-api', 'host': 'localhost', 'expectedIPs': ['127.0.0.1', '::1'],
             'port': self.srv.server_port, 'path': '/health', 'expectedStatus': [200],
             'caBundle': self.cert, 'maxLatencyMs': 10000}
        t.update(changes)
        return {'schemaVersion': 1, 'vantagePoint': 'local TLS socket', 'targets': [t]}

    def test_actual_private_dns_tls_http(self):
        result = verify_contract(self.contract(), allow_loopback=True)
        self.assertEqual(result['decision'], 'PASS', result)
        self.assertEqual(result['checks'][0]['httpStatus'], 200)
        self.assertEqual(result['source'], 'LOCAL_LOOPBACK_INTEGRATION_TEST')

    def test_real_403_can_be_contract(self):
        result = verify_contract(self.contract(path='/restricted', expectedStatus=[403]), allow_loopback=True)
        self.assertEqual(result['decision'], 'PASS', result)

    def test_real_wrong_status(self):
        result = verify_contract(self.contract(path='/fail'), allow_loopback=True)
        self.assertEqual(result['decision'], 'FAIL')

    def test_real_trust_rejection(self):
        doc = self.contract()
        doc['targets'][0].pop('caBundle')
        result = verify_contract(doc, allow_loopback=True)
        self.assertEqual(result['decision'], 'FAIL')
        self.assertIn('TLS', result['checks'][0]['reason'])

    def test_dns_leak_rejected_without_connection(self):
        def dns(host, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]
        result = verify_contract(self.contract(), allow_loopback=True, resolver=dns)
        self.assertEqual(result['decision'], 'FAIL')
        self.assertIn('unapproved', result['checks'][0]['reason'])

    def test_hostname_mismatch_rejected(self):
        result = verify_contract(self.contract(host='different.localhost'), allow_loopback=True,
            resolver=lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))])
        self.assertEqual(result['decision'], 'FAIL')

    def test_multiple_samples(self):
        result = verify_contract(self.contract(), allow_loopback=True, samples=3)
        self.assertEqual(result['decision'], 'PASS')
        self.assertEqual(len(result['checks']), 3)
        self.assertEqual(result['successRate'], 1)
        self.assertGreater(result['p95LatencyMs'], 0)

    def test_body_content_never_reported(self):
        result = verify_contract(self.contract(), allow_loopback=True)
        self.assertNotIn('sample-not-a-secret', json.dumps(result))

    def test_receipt_not_falsely_approved(self):
        runtime = verify_contract(self.contract(), allow_loopback=True)
        created = release_receipt(gate_what_if(whatif(change('Create'))), runtime, release_id='ci-test')
        self.assertEqual(created['verdict'], 'REQUIRES_HUMAN_APPROVAL')
        self.assertEqual(len(created['planReportSha256']), 64)
        failed = release_receipt(gate_what_if(whatif(change('Delete'))), runtime, release_id='ci-test')
        self.assertEqual(failed['verdict'], 'BLOCK')

    def test_subprocess_cli_entire_path(self):
        with tempfile.TemporaryDirectory() as wd:
            folder = Path(wd)
            contract = folder / 'contract.json'
            what = folder / 'what-if.json'
            plan = folder / 'plan.json'
            runtime = folder / 'runtime.json'
            receipt = folder / 'receipt.json'
            contract.write_text(json.dumps(self.contract()), encoding='utf-8')
            what.write_text(json.dumps(whatif(change('NoChange'))), encoding='utf-8')
            def run(*args):
                return subprocess.run([sys.executable, '-m', 'az_ready', *map(str,args)],
                                      cwd=REPO, capture_output=True, text=True)
            a = run('gate-whatif', what, '--output', plan)
            self.assertEqual(a.returncode, 0, a.stderr)
            b = run('verify', contract, '--local-test-only', '--output', runtime)
            self.assertEqual(b.returncode, 0, b.stderr)
            c = run('receipt', plan, runtime, '--release-id', 'test-v1', '--output', receipt)
            self.assertEqual(c.returncode, 0, c.stderr)
            self.assertEqual(json.loads(receipt.read_text())['verdict'], 'PARTIAL_EVIDENCE')
            self.assertEqual(run('receipt', plan, runtime, '--release-id', 'test-v1', '--require-complete').returncode, 2)
            self.assertEqual(run('verify', contract, '--output', runtime).returncode, 3)


if __name__ == '__main__':
    unittest.main()
