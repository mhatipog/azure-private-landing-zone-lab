"""Portable, hash-linked release evidence (not a signed attestation).

The output is designed for retention by an independent CI artifact store.
An input artifact, or a fabricated vantage-point label, is not itself proof
of deployment, operator identity or an authenticated monitoring session.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json


def canonical_hash(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode('utf-8')).hexdigest()


def release_receipt(plan: dict, runtime: dict, *, release_id: str,
                    monitor: dict | None = None, coverage: dict | None = None) -> dict:
    if not isinstance(plan, dict) or plan.get('kind') != 'arm-whatif-gate' or plan.get('decision') not in ('PASS', 'REVIEW', 'BLOCK'):
        raise ValueError('Expected genuine gate-whatif report')
    if not isinstance(runtime, dict) or runtime.get('kind') != 'in-network-service-contract' or runtime.get('decision') not in ('PASS', 'FAIL'):
        raise ValueError('Expected service verification report')
    if not isinstance(release_id, str) or not release_id.strip() or len(release_id) > 128:
        raise ValueError('Provide release identifier (maximum 128 characters)')
    if monitor is not None and (not isinstance(monitor, dict) or monitor.get('kind') != 'azure-connection-monitor-gate'
                                or monitor.get('decision') not in ('PASS', 'FAIL')):
        raise ValueError('Expected Azure Connection Monitor gate report')
    if coverage is not None and (not isinstance(coverage, dict) or coverage.get('kind') != 'change-impact-coverage'
                                 or coverage.get('decision') not in ('FAIL', 'DECLARED_NOT_PROVEN')):
        raise ValueError('Expected change impact coverage report')
    if (runtime['decision'] != 'PASS' or plan['decision'] == 'BLOCK'
        or (monitor and monitor['decision'] == 'FAIL') or (coverage and coverage['decision'] == 'FAIL')):
        verdict = 'BLOCK'
    elif plan['decision'] == 'REVIEW':
        verdict = 'REQUIRES_HUMAN_APPROVAL'
    elif monitor is None or coverage is None:
        verdict = 'PARTIAL_EVIDENCE'
    else:
        verdict = 'EVIDENCE_CHECKS_PASSED_NOT_ATTESTED'
    return {'schemaVersion': 1, 'kind': 'deployment-evidence-receipt',
            'releaseId': release_id, 'createdAtUtc': datetime.now(timezone.utc).isoformat(),
            'verdict': verdict, 'planDecision': plan['decision'],
            'runtimeDecision': runtime['decision'], 'runtimeSamples': runtime.get('samples'),
            'monitorDecision': monitor['decision'] if monitor else 'NOT_PROVIDED',
            'coverageDecision': coverage['decision'] if coverage else 'NOT_PROVIDED',
            'planReportSha256': canonical_hash(plan), 'runtimeReportSha256': canonical_hash(runtime),
            'monitorReportSha256': canonical_hash(monitor) if monitor else None,
            'coverageReportSha256': canonical_hash(coverage) if coverage else None,
            'limitations': [
                'This receipt is a checksum-linked summary, not a digitally signed attestation.',
                'A claimed vantage point is not cryptographically verified.',
                'Runtime probes validate only explicitly declared targets from this agent.',
                'Human Azure DevOps environment approval is external and cannot be inferred from a JSON file.',
                'Periodic production monitoring, rollback readiness and effective Azure Firewall/IDPS enforcement require independent evidence.']}
