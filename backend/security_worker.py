"""Fixed security checks. Invoked with Python -I inside a read-only sandbox.
No sample execution, shell commands, credential submissions or exploit payloads.
"""
import ast
import collections
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path


def finding(rule, title, severity, evidence, remediation, confidence='medium', cwe=None):
    return dict(rule=rule, title=title, severity=severity, confidence=confidence,
                evidence=evidence, remediation=remediation, cwe=cwe)


def command(argv):
    # Child inherits the parent's process group and sandbox. Fixed argv only.
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=35)
    if len(result.stdout) > 700000:
        raise ValueError('Inspector output exceeds evidence limit')
    return result.returncode, result.stdout.decode(errors='replace')


def inspect_web(spec, module):
    address, port = spec['address'], spec['port']
    ipaddress.ip_address(address)  # No DNS lookup or redirect following.
    connection = (http.client.HTTPSConnection(address, port, timeout=4, context=ssl.create_default_context())
                  if spec['scheme'] == 'https' else http.client.HTTPConnection(address, port, timeout=4))
    findings, evidence = [], {}
    try:
        connection.request('GET', spec['path'], headers={'User-Agent': 'KrakenAuthorizedAudit/1.0', 'Connection': 'close'})
        response = connection.getresponse()
        headers = {k.lower(): v for k, v in response.getheaders() if k.lower() != 'set-cookie'}
        cookies = response.headers.get_all('Set-Cookie') or []
        # Discard content; never store page bodies, cookie values or auth tokens.
        response.read(65536)
        evidence = {'status': response.status, 'header_names': sorted(headers),
                    'cookie_count': len(cookies), 'redirect_followed': False, 'requests': 1}
        if module in ('web', 'vulnerability'):
            for header, title, remediation in [
                ('content-security-policy', 'Content Security Policy absent', 'Define a restrictive CSP suitable for this application.'),
                ('x-content-type-options', 'MIME-sniffing protection absent', 'Set X-Content-Type-Options: nosniff.'),
                ('referrer-policy', 'Referrer policy absent', 'Set a Referrer-Policy that limits sensitive referrer disclosure.')]:
                if header not in headers:
                    findings.append(finding(header, title, 'low', {'header': header, 'present': False}, remediation))
            if spec['scheme'] == 'https' and 'strict-transport-security' not in headers:
                findings.append(finding('hsts', 'HSTS absent', 'medium', {'header': 'strict-transport-security', 'present': False}, 'Enable HSTS after verifying HTTPS across the host.'))
            if headers.get('access-control-allow-origin') == '*' and headers.get('access-control-allow-credentials', '').lower() == 'true':
                findings.append(finding('cors', 'Contradictory credentialed CORS policy', 'medium', {'wildcard_origin': True, 'allow_credentials': True}, 'Use explicit trusted origins and test browser enforcement.', cwe='CWE-942'))
        if module == 'authentication':
            if spec['scheme'] != 'https':
                findings.append(finding('transport', 'Authentication transport is not HTTPS', 'medium', {'scheme': spec['scheme']}, 'Use HTTPS for authentication; loopback HTTP may be acceptable for a local development fixture.', cwe='CWE-319'))
            for number, cookie in enumerate(cookies, 1):
                # Attributes only; cookie name and value never enter evidence.
                attributes = {part.strip().split('=', 1)[0].lower() for part in cookie.split(';')[1:]}
                for attr in ('httponly', 'samesite', 'secure'):
                    if attr not in attributes:
                        findings.append(finding('cookie-' + attr, 'Cookie missing ' + attr + ' attribute', 'medium' if attr != 'samesite' else 'low', {'cookie_index': number, 'missing_attribute': attr}, 'Review this cookie role and apply ' + attr + ' where appropriate.', cwe='CWE-614' if attr == 'secure' else 'CWE-1004' if attr == 'httponly' else 'CWE-1275'))
    except ssl.SSLCertVerificationError:
        findings.append(finding('certificate', 'TLS certificate verification failed', 'high', {'certificate_verified': False}, 'Deploy a valid certificate matching the authorized IP and trusted chain. No insecure retry was made.', cwe='CWE-295'))
    finally:
        connection.close()
    return findings, evidence


def inspect_local(spec, module):
    root = Path(spec['input'])
    files = sorted(p for p in root.iterdir() if p.is_file())
    findings, evidence = [], {'files': []}
    for p in files:
        data = p.read_bytes()
        evidence['files'].append({'file': p.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    if module == 'code_review':
        rc, output = command([sys.executable, '-I', '-m', 'bandit', '-r', str(root), '-f', 'json', '--ignore-nosec', '--ini', '/dev/null', '-q'])
        if rc not in (0, 1):
            raise ValueError('Bandit could not inspect the snapshot')
        result = json.loads(output)
        guidance = {
            'B307': ('Dynamic evaluation of Python expressions', 'Replace eval with explicit input parsing. For literal data only, consider a bounded literal parser; never evaluate untrusted code.'),
            'B105': ('Possible hardcoded password', 'Move secrets to the OS keychain or runtime secret configuration; rotate any real secret committed to source.'),
            'B602': ('Subprocess uses a shell', 'Use a fixed executable with an argument list and shell=False; validate input before execution.'),
            'B501': ('TLS certificate verification disabled', 'Enable certificate and hostname verification with a trusted CA store.'),
        }
        for issue in result.get('results', []):
            title, remediation = guidance.get(issue['test_id'], (issue['test_name'], 'Review Bandit ' + issue['test_id'] + ' guidance; prefer safe APIs, validated input and least privilege.'))
            findings.append(finding(issue['test_id'], title, issue['issue_severity'].lower(),
                {'file': Path(issue['filename']).name, 'line': issue['line_number']},
                remediation,
                issue['issue_confidence'].lower(), 'CWE-' + str(issue.get('issue_cwe', {}).get('id', 'unknown'))))
        evidence['scanner'] = 'Bandit'
        evidence['parser_errors'] = len(result.get('errors', []))
    elif module == 'vulnerability':
        for p in files:
            text = p.read_text(errors='replace')
            if p.name.endswith('requirements.txt'):
                for line, value in enumerate(text.splitlines(), 1):
                    value = value.strip()
                    if value and not value.startswith('#') and '==' not in value and not value.startswith('--'):
                        findings.append(finding('unpinned-dependency', 'Dependency is not exactly pinned', 'low', {'file': p.name, 'line': line}, 'Review and lock dependency versions and hashes; use an independently maintained advisory scanner for CVE assessment.'))
            if p.name.endswith('package.json'):
                try:
                    package = json.loads(text)
                    for key, version in package.get('dependencies', {}).items():
                        if str(version).startswith(('*', '^', '~', 'latest')):
                            findings.append(finding('floating-version', 'Dependency uses a floating version range', 'low', {'package': key[:100], 'file': p.name}, 'Commit and verify a lockfile; review advisories separately.'))
                except ValueError:
                    evidence['manifest_parse_error'] = True
        evidence['advisory_database'] = 'Not available; dependency hygiene only, not a CVE assessment'
    elif module == 'malware':
        for p in files:
            data = p.read_bytes()
            counts = collections.Counter(data)
            entropy = -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()) if data else 0
            indicators = [name for name, pattern in [('dynamic-execution', rb'\b(?:eval|exec)\s*\('), ('process-launch', rb'\b(?:subprocess|os\.system)\b'), ('encoded-content', rb'\b(?:b64decode|fromhex)\b')]
                          if re.search(pattern, data)]
            evidence['files'][files.index(p)].update(entropy=round(entropy, 3), indicators=indicators, sample_executed=False)
            if indicators:
                findings.append(finding('static-indicators', 'Potentially sensitive behavior indicators', 'info', {'file': p.name, 'indicators': indicators}, 'Review behavior in a dedicated isolated analysis lab. These indicators do not establish that a file is malicious.', confidence='low'))
    elif module == 'reverse_engineering':
        for p in files:
            rc, output = command(['/usr/bin/file', '-b', str(p)])
            evidence['files'][files.index(p)]['format'] = output.strip()[:300]
            if p.read_bytes()[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'):
                rc, output = command(['/usr/bin/otool', '-hv', str(p)])
                if rc != 0:
                    raise ValueError('otool could not inspect this Mach-O header')
                evidence['files'][files.index(p)]['macho_header'] = output.replace(str(p), p.name)[:4000]
            evidence['files'][files.index(p)]['printable_string_count'] = len(re.findall(rb'[\x20-\x7e]{6,}', p.read_bytes()))
        evidence['mode'] = 'Static file/Mach-O header inspection; no sample execution, debugger or decompilation'
    return findings, evidence


def main():
    spec = json.loads(sys.argv[1])
    module = spec['module']
    if module == 'network':
        findings, evidence = [], {'connections': []}
        for port in spec['ports']:
            try:
                with socket.create_connection((spec['address'], port), timeout=1):
                    state = 'open'
            except OSError:
                state = 'closed-or-filtered'
            evidence['connections'].append({'port': port, 'state': state})
            if state == 'open':
                findings.append(finding('reachable-port', 'TCP service is reachable', 'info', {'port': port}, 'Confirm this service is intended and restricted to the required clients.', confidence='high'))
    elif spec['kind'] == 'web':
        findings, evidence = inspect_web(spec, module)
    else:
        findings, evidence = inspect_local(spec, module)
    print(json.dumps({'findings': findings[:300], 'evidence': evidence, 'limitations': 'Bounded observations; no guarantee of vulnerability coverage or absence of malware.'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'error': type(exc).__name__ + ': security inspector could not complete; no success is claimed'}))
        sys.exit(1)
