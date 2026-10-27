"""Fail-closed evaluation of Azure Network Watcher Connection Monitor evidence.

Consume trusted, read-only KQL output. Missing or stale test evidence is not a
PASS; absence of alerts does not establish availability or security.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json


def _parse_rows(data: object) -> list[dict]:
    # `az monitor log-analytics query -o json` commonly returns a list of records.
    if isinstance(data, list):
        if any(not isinstance(item, dict) for item in data):
            raise ValueError('Expected row objects in telemetry output')
        return data
    # Direct Azure Monitor Logs Query REST API returns tables/columns/rows.
    if not isinstance(data, dict) or not isinstance(data.get('tables'), list) or not data['tables']:
        raise ValueError('Expected Azure CLI JSON records or Logs Query API tables')
    table = data['tables'][0]
    if not isinstance(table, dict) or not isinstance(table.get('columns'), list) or not isinstance(table.get('rows'), list):
        raise ValueError('Malformed Log Analytics table')
    keys = [c.get('name') for c in table['columns']]
    if any(not isinstance(k, str) for k in keys) or len(set(keys)) != len(keys):
        raise ValueError('Malformed column definitions')
    out = []
    for record in table['rows']:
        if not isinstance(record, list) or len(record) != len(keys):
            raise ValueError('Malformed telemetry table row')
        out.append(dict(zip(keys, record)))
    return out


def _time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError('TimeGenerated must be ISO 8601 text')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Invalid telemetry time') from exc
    if parsed.tzinfo is None:
        raise ValueError('Telemetry time must include UTC offset')
    return parsed.astimezone(timezone.utc)


def _key(record: dict) -> tuple[str, str, str]:
    return (str(record.get('SourceName', '')).casefold(),
            str(record.get('DestinationName', '')).casefold(),
            str(record.get('TestConfigurationName', '')).casefold())


def gate_monitor(data: object, specification: dict, *, now: datetime | None = None) -> dict:
    if not isinstance(specification, dict) or specification.get('schemaVersion') != 1:
        raise ValueError('Monitoring specification requires schemaVersion=1')
    tests = specification.get('expectedTests')
    if not isinstance(tests, list) or not 1 <= len(tests) <= 100:
        raise ValueError('Specify 1..100 exact expectedTests')
    max_age = specification.get('maxAgeMinutes', 30)
    max_failure = specification.get('maxFailureRate', 0.02)
    minimum_checks = specification.get('minChecks', 1)
    if type(max_age) not in (int,float) or not 1 <= max_age <= 1440 or type(max_failure) not in (int,float) or not 0 <= max_failure <= 1 or type(minimum_checks) is not int or not 1 <= minimum_checks <= 10000:
        raise ValueError('Invalid telemetry freshness, failure-rate or minimum-check thresholds')
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError('now must be timezone aware')
    current = current.astimezone(timezone.utc)
    rows = _parse_rows(data)
    if len(rows) > 100000:
        raise ValueError('Too many telemetry rows; restrict query time window')
    indexed = defaultdict(list)
    for row in rows:
        key = _key(row)
        if all(key):
            indexed[key].append(row)
    checks = []
    seen = set()
    for t in tests:
        if not isinstance(t, dict) or any(not isinstance(t.get(f), str) or not t[f].strip() for f in ('source', 'destination', 'configuration')):
            raise ValueError('Expected test requires exact source, destination and configuration names')
        key = tuple(t[f].casefold() for f in ('source', 'destination', 'configuration'))
        if key in seen:
            raise ValueError('Duplicate monitored test')
        seen.add(key)
        name = '/'.join(t[f] for f in ('source', 'destination', 'configuration'))
        recent = []
        for row in indexed.get(key, []):
            stamp = _time(row.get('TimeGenerated'))
            if current - timedelta(minutes=max_age) <= stamp <= current + timedelta(minutes=5):
                recent.append((stamp, row))
        if not recent:
            checks.append({'test': name, 'status': 'FAIL', 'reason': 'Missing or stale telemetry'})
            continue
        recent.sort(key=lambda x: x[0])
        bad_state = any(str(row.get('TestResult', '')).lower() != 'pass' for _, row in recent)
        counts = [row.get('ChecksTotal') for _, row in recent]
        failures = [row.get('ChecksFailed') for _, row in recent]
        if any(type(a) is not int or type(b) is not int or a <= 0 or b < 0 or b > a for a,b in zip(counts,failures)):
            checks.append({'test': name, 'status': 'FAIL', 'reason': 'Incomplete or invalid sample counts'})
            continue
        total, failed = sum(counts), sum(failures)
        fraction = failed / total
        result = 'FAIL' if bad_state or total < minimum_checks or fraction > max_failure else 'PASS'
        checks.append({'test': name, 'status': result, 'sampleRows': len(recent),
                       'checksTotal': total, 'checksFailed': failed,
                       'failureRate': round(fraction, 6),
                       'ageSeconds': round((current - recent[-1][0]).total_seconds(), 1),
                       'reason': ('Recent Connection Monitor checks passed thresholds' if result == 'PASS'
                                  else 'Failure/warning/indeterminate state, inadequate checks or threshold exceeded')})
    return {'schemaVersion': 1, 'kind': 'azure-connection-monitor-gate',
            'decision': 'PASS' if all(x['status'] == 'PASS' for x in checks) else 'FAIL',
            'checks': checks, 'expectedTests': len(tests), 'observedRows': len(rows),
            'limitations': 'Requires trustworthy Azure Monitor data; tests only specified configured paths and time windows.'}
