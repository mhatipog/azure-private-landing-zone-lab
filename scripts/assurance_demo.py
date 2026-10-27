#!/usr/bin/env python3
"""One-command end-to-end *local* exercise with actual HTTPS sockets.

No Azure credentials, deployments, private keys in repository, external hosts,
or external network traffic. OpenSSL generates an ephemeral self-signed cert.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import statistics

from az_ready.assurance import gate_what_if, verify_contract
from az_ready.monitor import gate_monitor
from az_ready.release import release_receipt


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200 if self.path == '/health' else 503
        body = b'local-ephemeral-server'
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description='Run real loopback TLS, what-if and monitor fault tests offline')
    parser.add_argument('--output', default='assurance-demo.json', type=Path)
    parser.add_argument('--rounds', default=30, type=int)
    options = parser.parse_args()
    if not 1 <= options.rounds <= 200:
        parser.error('--rounds must be between 1 and 200')
    rid = '/subscriptions/demo/resourceGroups/rg-sandbox/providers/Microsoft.Storage/storageAccounts/example'
    with tempfile.TemporaryDirectory(prefix='azure-assurance-test-') as d:
        cert, key = str(Path(d)/'cert.pem'), str(Path(d)/'key.pem')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                        '-keyout',key,'-out',cert], check=True, capture_output=True)
        server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert,key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            raw = {'schemaVersion':1, 'vantagePoint':'ephemeral loopback (NOT Azure)',
                   'targets':[{'name':'internal-api','host':'localhost',
                               'expectedIPs':['127.0.0.1','::1'], 'port':server.server_port,
                               'path':'/health','expectedStatus':[200], 'caBundle':cert,
                               'maxLatencyMs':2000}]}
            safe_plan = {'status':'Succeeded','properties':{'changes':[{'resourceId':rid,'changeType':'NoChange'}]}}
            changed_plan = {'status':'Succeeded','properties':{'changes':[{'resourceId':rid,'changeType':'Create'}]}}
            unsafe_plan = {'status':'Succeeded','properties':{'changes':[{'resourceId':rid,'changeType':'Delete'}]}}
            baseline = gate_what_if(safe_plan)
            requires_review = gate_what_if(changed_plan)
            blocked = gate_what_if(unsafe_plan)
            passing_runtime = verify_contract(raw, allow_loopback=True)
            raw['targets'][0]['path'] = '/bad-health'
            failing_runtime = verify_contract(raw, allow_loopback=True)
            raw['targets'][0]['path'] = '/health'
            now = datetime.now(timezone.utc)
            spec = {'schemaVersion':1, 'expectedTests':[
                {'source':'spoke-checker','destination':'internal-api','configuration':'https'}],
                'maxAgeMinutes':30, 'maxFailureRate':0.02, 'minChecks':10}
            row = {'TimeGenerated':now.isoformat(),'SourceName':'spoke-checker','DestinationName':'internal-api',
                   'TestConfigurationName':'https','TestResult':'Pass','ChecksTotal':100,'ChecksFailed':0}
            green_monitor = gate_monitor([row],spec,now=now)
            row['TimeGenerated']=(now-timedelta(hours=2)).isoformat()
            stale_monitor = gate_monitor([row],spec,now=now)
            start = time.perf_counter()
            latency=[]
            for _ in range(options.rounds):
                result = verify_contract(raw,allow_loopback=True)
                if result['decision'] != 'PASS':
                    raise RuntimeError('Local TLS probe failed during benchmark')
                latency.extend(x['latencyMs'] for x in result['checks'])
            duration=time.perf_counter()-start
            results={'kind':'LOCAL_ASSURANCE_DEMO','notAzureEvidence':True,
                     'checks':{
                         'unchangedPlanPass':baseline['decision']=='PASS',
                         'changedPlanNeedsReview':requires_review['decision']=='REVIEW',
                         'deletionBlocked':blocked['decision']=='BLOCK',
                         'realHttpsPositivePass':passing_runtime['decision']=='PASS',
                         'realHttp503Detected':failing_runtime['decision']=='FAIL',
                         'freshMonitoringPass':green_monitor['decision']=='PASS',
                         'missingFreshMonitoringRejected':stale_monitor['decision']=='FAIL',
                         'humanApprovalNotInvented':release_receipt(requires_review,passing_runtime,release_id='demo')['verdict']=='REQUIRES_HUMAN_APPROVAL',
                     },
                     'localTlsBenchmark': {'rounds':options.rounds,'totalMs':round(duration*1000,2),
                                           'medianMs':round(statistics.median(latency),2),
                                           'minMs':round(min(latency),2),
                                           'maxMs':round(max(latency),2),
                                           'unit':'real loopback TCP+TLS+HTTP check; NOT Azure network latency'}}
            results['passed'] = all(results['checks'].values())
            options.output.parent.mkdir(parents=True,exist_ok=True)
            options.output.write_text(json.dumps(results,indent=2)+'\n',encoding='utf-8')
            print(json.dumps(results,indent=2))
            return 0 if results['passed'] else 2
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)


if __name__=='__main__':
    raise SystemExit(main())
