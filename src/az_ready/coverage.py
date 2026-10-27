"""Scope-to-test mapping: don't call a release validated while impacted resources are untested.

This gate checks declared coverage only. It cannot establish that a named health
probe is a complete behavioral test for an Azure resource. Mapping policies
must be reviewed/protected separately from an AI-authored deployment change.
"""
from __future__ import annotations

from .assurance import _changes, validate_contract


def gate_coverage(whatif: dict, contract: dict, monitor_spec: dict, mapping: dict) -> dict:
    changes, _, provisional = _changes(whatif)
    if provisional:
        raise ValueError('Cannot declare coverage from provisional what-if changes')
    targets = validate_contract(contract, allow_loopback=False)
    target_names = {t['name'] for t in targets}
    if not isinstance(monitor_spec, dict) or not isinstance(monitor_spec.get('expectedTests'), list):
        raise ValueError('Missing monitoring specification')
    monitored = {
        (t.get('source'), t.get('destination'), t.get('configuration'))
        for t in monitor_spec['expectedTests'] if isinstance(t, dict)
    }
    if not isinstance(mapping, dict) or mapping.get('schemaVersion') != 1 or not isinstance(mapping.get('resourceCoverage'), list):
        raise ValueError('Expected schemaVersion=1 and resourceCoverage list')
    if len(mapping['resourceCoverage']) > 500:
        raise ValueError('Too many coverage declarations')
    specs = []
    for item in mapping['resourceCoverage']:
        if not isinstance(item, dict):
            raise ValueError('Malformed coverage mapping')
        prefix = item.get('resourceIdPrefix')
        probes = item.get('requiredProbes')
        monitors = item.get('requiredMonitors')
        if not isinstance(prefix, str) or not prefix.startswith('/subscriptions/') or len(prefix) < 40:
            raise ValueError('Coverage resourceIdPrefix must be a precise ARM path')
        if not isinstance(probes, list) or not probes or any(not isinstance(x, str) or not x for x in probes):
            raise ValueError('Each mapping needs explicit post-deployment probes')
        if not isinstance(monitors, list) or not monitors or any(not isinstance(m, dict) or
              any(not isinstance(m.get(k), str) for k in ('source','destination','configuration')) for m in monitors):
            raise ValueError('Each mapping needs expected Network Watcher monitor tests')
        specs.append((prefix.lower(), probes, monitors))
    checks = []
    for change in changes:
        if change.get('changeType', '').lower() in ('nochange', 'ignore'):
            continue
        rid = change.get('resourceId', '')
        if not isinstance(rid, str):
            raise ValueError('What-if change has no resource ID')
        matches = [p for p in specs if rid.lower().startswith(p[0])]
        if not matches:
            checks.append({'resource': rid, 'status': 'FAIL', 'reason': 'No impact-to-test mapping for changed resource'})
            continue
        # Most specific prefix wins: avoid broad rule masking a narrowly scoped exception.
        prefix, probes, monitors = max(matches, key=lambda p: len(p[0]))
        missing_probes = sorted(set(probes) - target_names)
        missing_monitors = [m for m in monitors if
            (m['source'], m['destination'], m['configuration']) not in monitored]
        if missing_probes or missing_monitors:
            checks.append({'resource': rid, 'status':'FAIL', 'reason':
                           f'Incomplete declared coverage: {len(missing_probes)} probes and {len(missing_monitors)} monitors missing'})
        else:
            checks.append({'resource': rid, 'status': 'DECLARED',
                           'reason': f'Declared {len(probes)} probe(s) and {len(monitors)} monitor(s) under approved mapping'})
    return {'schemaVersion': 1, 'kind': 'change-impact-coverage',
            'decision': 'FAIL' if any(x['status']=='FAIL' for x in checks) or not checks else 'DECLARED_NOT_PROVEN',
            'changesChecked': len(checks), 'checks': checks,
            'limitations': 'Checks required tests are declared, not that they accurately prove behavior. Protect mapping via CODEOWNERS/manual review.'}
