"""Deployment assurance: ARM what-if risk gate and in-network service contracts.

No cloud writes, arbitrary discovery or automatic rollback. Runtime checks must be
executed from a deliberately selected network vantage point. JSON-only contracts
avoid implicit scripting or unsafe interpolation from untrusted deployment output.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time

PRIVATE_NETS = tuple(ipaddress.ip_network(c) for c in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))
LOOPBACK_NETS = (ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128'))
_HOST = re.compile(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
_ALLOWED_TYPES = {'create', 'delete', 'ignore', 'deploy', 'nochange', 'modify', 'unsupported'}
RISK_PATHS = ('publicnetworkaccess', 'allowsharedkeyaccess', 'enablerbacauthorization',
              'networkacls', 'securityrules', 'route', 'firewallpolicy', 'ipconfigurations',
              'privateendpoint', 'enablehttps', 'minimumtlsversion', 'allowblobpublicaccess',
              'authentication', 'identity', 'accesspolicies', 'intrusiondetection',
              'dnssettings', 'disablelocalauth')


def _record(check: str, status: str, reason: str, resource: str = '') -> dict:
    return {'check': check, 'status': status, 'reason': reason, 'resource': resource}


def _changes(data: Any) -> tuple[list, list, bool]:
    """Read actual Azure REST/CLI what-if JSON. Reject abbreviated JSON as evidence."""
    if not isinstance(data, dict):
        raise ValueError('ARM what-if must be a JSON object')
    props = data.get('properties', data)
    if not isinstance(props, dict):
        raise ValueError('Malformed ARM what-if properties')
    # An absent changes list is not a no-op. An API potentialChanges list is provisional.
    changes = props.get('changes')
    provisional = False
    if changes is None and 'potentialChanges' in props:
        changes = props['potentialChanges']
        provisional = True
    if not isinstance(changes, list):
        raise ValueError('Expected full what-if JSON with properties.changes array')
    return changes, props.get('diagnostics', []), provisional


def gate_what_if(data: dict, *, protected: list[str] | None = None,
                 max_changes: int = 10000) -> dict:
    """Never auto-approve a modification simply because ARM predicts it is safe.

    This policy rejects destructive/unsupported operations and requires human review
    of Deploy, Modify and sensitive Creates. Only unchanged/ignored resources PASS.
    The gate is a preflight risk signal, not a cloud deployment approval.
    """
    changes, diagnostics, provisional = _changes(data)
    if len(changes) > max_changes:
        raise ValueError('What-if has more changes than configured limit; refuse truncated assessment')
    if diagnostics is None or not isinstance(diagnostics, list):
        raise ValueError('Malformed what-if diagnostics')
    protected = protected or []
    if len(protected) > 100 or any(not isinstance(p, str) or not p.strip() or len(p) > 250 for p in protected):
        raise ValueError('Invalid protected resource prefixes')
    checks: list[dict] = []
    if data.get('error') or data.get('properties', {}).get('error'):
        checks.append(_record('WHATIF_ERROR', 'BLOCK', 'ARM reported an operation error'))
    if provisional:
        checks.append(_record('WHATIF_PROVISIONAL', 'BLOCK', 'Result contains potentialChanges, not finalized changes'))
    if diagnostics:
        checks.append(_record('WHATIF_DIAGNOSTICS', 'REVIEW', f'{len(diagnostics)} diagnostics require review'))
    status = str(data.get('status', data.get('properties', {}).get('provisioningState', 'Succeeded'))).lower()
    if status not in ('succeeded', 'success', 'completed'):
        checks.append(_record('WHATIF_INCOMPLETE', 'BLOCK', 'What-if operation is not complete'))
    if not changes:
        checks.append(_record('WHATIF_EMPTY', 'REVIEW', 'No resources returned: ensure correct scope and deployment input'))
    seen: set[str] = set()
    from .checks import assess  # Common proven control rules also apply to predicted *after* resources.
    for ch in changes:
        if not isinstance(ch, dict):
            raise ValueError('Malformed resource change')
        rid = ch.get('resourceId')
        ctype = ch.get('changeType')
        if not isinstance(rid, str) or not rid.strip() or not isinstance(ctype, str):
            raise ValueError('Every change needs resourceId and changeType')
        if rid.casefold() in seen:
            checks.append(_record('WHATIF_DUPLICATE', 'BLOCK', 'Duplicate resource in what-if', rid))
        seen.add(rid.casefold())
        t = ctype.casefold()
        # Explicitly dangerous predicted settings can be blocked before any deployment.
        # A partial `after` object cannot establish safety: review is still necessary.
        after = ch.get('after')
        if t in ('create', 'modify', 'deploy') and isinstance(after, dict):
            modeled = dict(after)
            modeled.setdefault('id', rid)
            if 'type' not in modeled:
                # ARM IDs use /providers/{namespace}/{type}/{name}/... ; infer only the
                # immediate resource type, not a guess about arbitrary extensions.
                fragments = rid.lower().split('/providers/')
                if len(fragments) > 1:
                    parts = fragments[-1].split('/')
                    if len(parts) >= 3:
                        modeled['type'] = parts[0] + '/' + parts[1]
            unsafe = [f.rule for f in assess([modeled]) if f.status == 'FAIL' and f.severity == 'high']
            if unsafe:
                checks.append(_record('WHATIF_PREDICTED_UNSAFE', 'BLOCK',
                                      'Predicted configuration violates high-severity controls: ' + ', '.join(sorted(set(unsafe))), rid))
        if t not in _ALLOWED_TYPES:
            checks.append(_record('WHATIF_UNKNOWN_CHANGE', 'BLOCK', 'Unrecognized ARM change type', rid))
        elif t == 'delete':
            checks.append(_record('WHATIF_DELETE', 'BLOCK', 'Resource deletion requires separate risk evaluation', rid))
        elif t == 'unsupported':
            checks.append(_record('WHATIF_UNSUPPORTED', 'BLOCK', 'ARM cannot predict this change', rid))
        elif t in ('ignore', 'nochange'):
            checks.append(_record('WHATIF_'+t.upper(), 'PASS', 'No change predicted', rid))
        elif t == 'deploy':
            checks.append(_record('WHATIF_DEPLOY', 'REVIEW', 'Redeployment may change unspecified properties', rid))
        elif t == 'modify':
            delta = ch.get('delta')
            if not isinstance(delta, list) or not delta:
                checks.append(_record('WHATIF_INCOMPLETE_DELTA', 'BLOCK', 'Modify without full property deltas', rid))
                continue
            paths = _delta_paths(delta)
            disallowed = _unsafe_delta(delta)
            if disallowed:
                checks.append(_record('WHATIF_PREDICTED_UNSAFE_DELTA', 'BLOCK',
                                      'Predicted unsafe security properties: '+', '.join(disallowed), rid))
            sensitive = any(any(term in p.lower().replace('.', '').replace('/', '') for term in RISK_PATHS)
                            for p in paths)
            checks.append(_record('WHATIF_SENSITIVE_MODIFY' if sensitive else 'WHATIF_MODIFY', 'REVIEW',
                                  'Sensitive network/security property changed' if sensitive else 'Change must be reviewed and post-tested', rid))
        elif t == 'create':
            if any(rid.casefold().startswith(p.casefold()) for p in protected):
                checks.append(_record('WHATIF_PROTECTED_CREATE', 'BLOCK', 'Changes to protected scope forbidden', rid))
            else:
                checks.append(_record('WHATIF_CREATE', 'REVIEW', 'New resource requires validation and runtime contract', rid))
        if t not in ('nochange', 'ignore', 'create') and any(rid.casefold().startswith(p.casefold()) for p in protected):
            checks.append(_record('WHATIF_PROTECTED', 'BLOCK', 'Protected resource/scope changed', rid))
    counts = {s: sum(x['status'] == s for x in checks) for s in ('PASS', 'REVIEW', 'BLOCK')}
    return {'schemaVersion': 1, 'kind': 'arm-whatif-gate', 'decision':
            'BLOCK' if counts['BLOCK'] else 'REVIEW' if counts['REVIEW'] else 'PASS',
            'counts': counts, 'changesAnalyzed': len(changes), 'checks': checks}



def _unsafe_delta(nodes: list) -> list[str]:
    """Flag unequivocally unsafe predicted property changes, even when ARM omits after."""
    unsafe = []
    stack = list(nodes)
    while stack:
        entry = stack.pop()
        if not isinstance(entry, dict):
            continue
        path = str(entry.get('path', '')).casefold().replace('/', '.').split('.')[-1]
        new = entry.get('after')
        value = str(new).casefold() if new is not None else ''
        risky = ((path == 'publicnetworkaccess' and value == 'enabled') or
                 (path in ('allowsharedkeyaccess', 'allowblobpublicaccess') and new is True) or
                 (path in ('disablelocalauth', 'enablerbacauthorization') and new is False) or
                 (path == 'minimumtlsversion' and value in ('tls1_0', 'tls1_1')))
        if risky:
            unsafe.append(path)
        children = entry.get('children', [])
        if isinstance(children, list):
            stack.extend(children)
    return sorted(set(unsafe))

def _delta_paths(nodes: list, depth: int = 0) -> list[str]:
    if depth > 15 or len(nodes) > 20000:
        raise ValueError('Invalid/excessively nested what-if delta')
    out: list[str] = []
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get('path'), str):
            raise ValueError('Malformed what-if property delta')
        out.append(node['path'])
        children = node.get('children', [])
        if not isinstance(children, list):
            raise ValueError('Malformed nested what-if delta')
        out.extend(_delta_paths(children, depth + 1))
    return out


def _safe_ip(value: str, allow_loopback: bool = False) -> str:
    ip = ipaddress.ip_address(value)
    if not any(ip in n for n in (PRIVATE_NETS + LOOPBACK_NETS if allow_loopback else PRIVATE_NETS)):
        raise ValueError('Endpoint address must be RFC1918/ULA private (loopback only in explicit local-test mode)')
    return str(ip)


def validate_contract(doc: dict, *, allow_loopback: bool = False) -> list[dict]:
    if not isinstance(doc, dict) or doc.get('schemaVersion') != 1 or not isinstance(doc.get('targets'), list):
        raise ValueError('Contract must contain schemaVersion=1 and targets array')
    targets = doc['targets']
    if not targets or len(targets) > 100:
        raise ValueError('Contract requires 1..100 explicit targets')
    names = set()
    for t in targets:
        if not isinstance(t, dict) or not isinstance(t.get('name'), str) or not t['name'].strip() or len(t['name']) > 100:
            raise ValueError('Target requires a short name')
        if t['name'] in names:
            raise ValueError('Duplicate target name')
        names.add(t['name'])
        hostname = t.get('host')
        if not isinstance(hostname, str) or not _HOST.fullmatch(hostname) or hostname.endswith('.'):
            raise ValueError('Target host must be a literal DNS hostname, not a URL/IP')
        ips = t.get('expectedIPs')
        if not isinstance(ips, list) or not 1 <= len(ips) <= 20:
            raise ValueError('Target requires 1..20 approved expectedIPs')
        for ip in ips:
            if not isinstance(ip, str):
                raise ValueError('Expected IP must be a string')
            _safe_ip(ip, allow_loopback)
        port = t.get('port', 443)
        timeout = t.get('timeoutSeconds', 3)
        path = t.get('path', '/health')
        expected = t.get('expectedStatus', [200])
        if type(port) is not int or not (1 <= port <= 65535) or isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 15:
            raise ValueError('Port or timeout out of range')
        if not isinstance(path, str) or not path.startswith('/') or len(path) > 512 or '\r' in path or '\n' in path or '#' in path or '://' in path or '?' in path:
            raise ValueError('Path must be a literal relative path without query, credentials or controls')
        if not isinstance(expected, list) or not expected or any(type(c) is not int or not 100 <= c <= 599 for c in expected):
            raise ValueError('expectedStatus must list HTTP status codes')
        latency = t.get('maxLatencyMs', 1000)
        if type(latency) not in (int, float) or not 1 <= latency <= 60000:
            raise ValueError('maxLatencyMs out of range')
        if 'caBundle' in t and (not isinstance(t['caBundle'], str) or len(t['caBundle']) > 2048):
            raise ValueError('caBundle must be a local CA certificate path')
    return targets


def verify_target(t: dict, *, allow_loopback: bool = False, resolver=None) -> dict:
    """Real DNS, TCP, authenticated TLS and HTTP GET. Never logs response bodies.

    DNS must not contain ANY unexpected IP. A resolved-IP allowlist prevents
    accidentally following public DNS answers or a DNS rebinding change.
    """
    name, host = t['name'], t['host']
    port, timeout = t.get('port', 443), t.get('timeoutSeconds', 3)
    expected = {_safe_ip(v, allow_loopback) for v in t['expectedIPs']}
    started = time.perf_counter()
    try:
        addrs = resolver(host, port) if resolver else socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        actual = {str(ipaddress.ip_address(a[4][0])) for a in addrs}
        if not actual:
            raise OSError('DNS returned no endpoints')
    except (OSError, ValueError) as e:
        return _record(name, 'FAIL', f'DNS resolution error ({type(e).__name__})')
    if not actual.issubset(expected):
        return _record(name, 'FAIL', 'DNS returned one or more unapproved IP addresses')
    if not expected.intersection(actual):
        return _record(name, 'FAIL', 'DNS did not resolve to an approved address')
    selected = sorted(actual)[0]
    try:
        ctx = ssl.create_default_context(cafile=t.get('caBundle'))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((selected, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as conn:
                conn.settimeout(timeout)
                reqpath = t.get('path', '/health')
                # No redirects or user-supplied headers/auth; no secret or response body logged.
                connection = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ctx)
                # Use the already authenticated connection; HTTPSConnection otherwise resolves DNS again.
                connection.sock = conn
                try:
                    connection.request('GET', reqpath, headers={'Host': host, 'Connection': 'close', 'User-Agent': 'az-private-ready-assurance/0.4'})
                    response = connection.getresponse()
                    status = response.status
                    response.read(32768)  # bounded data discard; no redirects followed
                finally:
                    connection.sock = None  # TLS context owner closes it
                elapsed = (time.perf_counter() - started) * 1000
                if status not in t.get('expectedStatus', [200]):
                    return _record(name, 'FAIL', f'Unexpected HTTP status {status}; expected {t.get("expectedStatus", [200])}')
                if elapsed > t.get('maxLatencyMs', 1000):
                    return _record(name, 'FAIL', 'Latency threshold exceeded')
                return {**_record(name, 'PASS', 'Approved DNS, authenticated TLS and HTTP contract passed'),
                        'latencyMs': round(elapsed, 2), 'httpStatus': status,
                        'selectedPrivateIp': selected, 'tlsVersion': conn.version()}
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as e:
        return _record(name, 'FAIL', f'TCP/TLS/HTTP check failed ({type(e).__name__})')


def verify_contract(doc: dict, *, allow_loopback: bool = False, resolver=None,
                    samples: int = 1, interval: float = 0) -> dict:
    """Bounded repeated probes, useful as a CI health gate or short canary window.

    This is NOT a daemon or a replacement for Azure Monitor/Network Watcher.
    """
    targets = validate_contract(doc, allow_loopback=allow_loopback)
    if type(samples) is not int or not (1 <= samples <= 30) or not (0 <= interval <= 60):
        raise ValueError('samples must be 1..30 and interval 0..60 seconds')
    run_at = datetime.now(timezone.utc).isoformat()
    items: list[dict] = []
    for i in range(samples):
        for target in targets:
            result = verify_target(target, allow_loopback=allow_loopback, resolver=resolver)
            result['sample'] = i + 1
            items.append(result)
        if i < samples - 1 and interval:
            time.sleep(interval)
    failures = [i for i in items if i['status'] != 'PASS']
    lats = sorted(i['latencyMs'] for i in items if i['status'] == 'PASS')
    return {'schemaVersion': 1, 'kind': 'in-network-service-contract', 'runAtUtc': run_at,
            'vantagePointClaim': doc.get('vantagePoint', 'not specified (unverified)'),
            'source': 'ACTUAL_NETWORK_PROBES' if not allow_loopback else 'LOCAL_LOOPBACK_INTEGRATION_TEST',
            'contractSha256': hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest(),
            'decision': 'FAIL' if failures else 'PASS', 'samples': samples, 'targets': len(targets),
            'checks': items, 'successRate': round((len(items) - len(failures)) / len(items), 4),
            'p95LatencyMs': lats[max(0, int(0.95 * len(lats) + 0.9999) - 1)] if lats else None}
