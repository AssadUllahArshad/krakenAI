"""Owner-authorized, scoped security modules with immutable input snapshots."""
import asyncio
import hashlib
import importlib.util
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

MODULES = {
    'network': {'title': 'Network auditing', 'active': True, 'kinds': ['network'], 'description': 'TCP reachability on at most eight explicitly authorized ports. No discovery or exploit traffic.'},
    'web': {'title': 'Web application security', 'active': True, 'kinds': ['web'], 'description': 'One GET; security header and TLS checks. No redirects, crawling or payload injection.'},
    'code_review': {'title': 'Secure code review', 'active': False, 'kinds': ['local'], 'description': 'Bandit static Python analysis on a read-only snapshot; source is never executed.'},
    'authentication': {'title': 'Authentication security', 'active': True, 'kinds': ['web'], 'description': 'Transport and cookie attribute review. No login attempts, credentials or brute force.'},
    'vulnerability': {'title': 'Vulnerability assessment', 'active': True, 'kinds': ['local', 'web'], 'description': 'Dependency pinning hygiene or web configuration checks. No CVE feed or exploit validation.'},
    'malware': {'title': 'Defensive malware triage', 'active': False, 'kinds': ['local'], 'description': 'SHA-256, entropy and behavioral text indicators. No execution or malware generation.'},
    'reverse_engineering': {'title': 'Reverse engineering', 'active': False, 'kinds': ['local'], 'description': 'Static file format, string counts and Mach-O headers using file/otool. No debugger execution.'},
}


class ScopeInput(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    kind: str
    target: str = Field(min_length=1, max_length=500)
    ports: list = Field(default_factory=list)
    expires_hours: int = Field(default=8, ge=1, le=24)
    authorization: str = Field(min_length=10, max_length=500)


class RunInput(BaseModel):
    module: str
    scope_id: str


class Cyber:
    def __init__(self, root, store, control, tools):
        self.root, self.store, self.control, self.tools = Path(root), store, control, tools
        self.running = {}
        store.db.executescript('''
        CREATE TABLE IF NOT EXISTS cyber_scopes (id TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cyber_reports (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, data TEXT NOT NULL, created REAL NOT NULL);
        ''')
        store.db.commit()

    def flags(self):
        saved = self.store.get('cyber_modules', {})
        return {key: bool(saved.get(key, False)) for key in MODULES}

    @staticmethod
    def address(value):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise HTTPException(400, 'Use a literal IPv4 address; DNS names, CIDRs and wildcards are not supported')
        if ip.version != 4 or ip.is_multicast or ip.is_link_local or ip.is_unspecified or ip.is_reserved or str(ip) == '255.255.255.255':
            raise HTTPException(400, 'Unsupported address; metadata/link-local, multicast and reserved targets are blocked')
        return str(ip)

    @staticmethod
    def ports(values):
        if not 1 <= len(values) <= 8 or any(type(p) is not int or p < 1 or p > 65535 for p in values):
            raise HTTPException(400, 'Authorize one to eight numeric TCP ports')
        # Never grant a route to KRAKEN administrative APIs or local inference.
        if any(p in (8765, 8766, 11434) for p in values):
            raise HTTPException(403, 'KRAKEN and Ollama control ports cannot be security targets')
        return sorted(set(values))

    def create_scope(self, body):
        data = {'id': uuid.uuid4().hex, 'label': body.label, 'kind': body.kind,
                'target': body.target, 'authorization': body.authorization,
                'created': time.time(), 'expires': time.time() + body.expires_hours * 3600}
        if body.kind == 'local':
            path = self.tools.path(body.target)
            if not path.exists() or path.is_symlink():
                raise HTTPException(400, 'Authorize an existing regular file or directory in workspace/projects')
            data['resolved'] = str(path)
        elif body.kind == 'network':
            data.update(address=self.address(body.target), ports=self.ports(body.ports))
        elif body.kind == 'web':
            parsed = urlsplit(body.target)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise HTTPException(400, 'Authorize a complete HTTP(S) URL with a literal IPv4 address, no credentials, query or fragment')
            try:
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            except ValueError:
                raise HTTPException(400, 'Invalid port')
            self.ports([port])
            data.update(address=self.address(parsed.hostname), port=port, scheme=parsed.scheme, path=parsed.path or '/')
        else:
            raise HTTPException(400, 'Scope kind must be local, network or web')
        self.store.execute('INSERT INTO cyber_scopes VALUES (?,?)', (data['id'], json.dumps(data)))
        self.store.event('Owner authorized security scope ' + data['label'])
        return data

    def scope(self, identifier):
        rows = self.store.rows('SELECT data FROM cyber_scopes WHERE id=?', (identifier,))
        if not rows:
            raise HTTPException(403, 'Explicit security scope is required or was revoked')
        scope = json.loads(rows[0]['data'])
        if scope['expires'] <= time.time():
            raise HTTPException(403, 'Security scope expired; authorize it again')
        return scope

    def guard(self, module, scope_id, authorized):
        self.control.check('security', 'computer')
        if not self.flags().get(module):
            raise HTTPException(403, 'Security module is disabled')
        authorized()  # Re-resolve the live owner session; never retain a password.
        scope = self.scope(scope_id)
        if scope['kind'] not in MODULES[module]['kinds']:
            raise HTTPException(400, 'Scope kind does not match this module')
        if scope['kind'] != 'local':
            self.control.check('internet')
        if module == 'code_review' and not importlib.util.find_spec('bandit'):
            raise HTTPException(503, 'Install the optional Bandit dependency before code review')
        return scope

    def snapshot(self, scope, destination):
        path = self.tools.path(scope['target'])
        if str(path) != scope['resolved']:
            raise HTTPException(403, 'Authorized path changed; configure scope again')
        candidates = [path] if path.is_file() else []
        if path.is_dir():
            directories = 0
            for current, folders, filenames in os.walk(path, followlinks=False):
                folders[:] = [name for name in folders if not name.startswith('.') and name != 'node_modules' and not (Path(current) / name).is_symlink()]
                directories += 1
                if directories > 200:
                    raise HTTPException(413, 'Choose a smaller directory scope')
                candidates.extend(Path(current) / name for name in filenames if not name.startswith('.'))
                if len(candidates) > 80:
                    raise HTTPException(413, 'Scope exceeds 80 files; choose a smaller scope')
        count, size, manifest = 0, 0, []
        for source in candidates:
            if source.is_symlink() or not source.is_file() or any(p.startswith('.') for p in source.relative_to(path.parent if path.is_file() else path).parts):
                continue
            resolved = self.tools.path(str(source.relative_to(self.root)))
            if path.is_dir() and path not in resolved.parents:
                raise HTTPException(403, 'Snapshot cannot follow links outside scope')
            with os.fdopen(os.open(str(source), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as handle:
                data = handle.read(2_000_001)
            size += len(data)
            count += 1
            if len(data) > 2_000_000 or size > 10_000_000 or count > 80:
                raise HTTPException(413, 'Scope exceeds 80 files, 2 MB/file or 10 MB total; choose a smaller scope')
            name = ('%03d-' % count) + source.name
            (destination / name).write_bytes(data)
            manifest.append({'source': str(source.relative_to(self.root)), 'snapshot': name,
                             'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
        if not manifest:
            raise HTTPException(400, 'Scope contains no accessible non-hidden regular files')
        return manifest

    def sandbox(self, inputs, scratch, scope):
        if sys.platform != 'darwin' or not shutil.which('sandbox-exec'):
            raise HTTPException(503, 'Security tools require the macOS sandbox; refusing unsandboxed execution')
        q = lambda p: json.dumps(str(p))
        read = ['/System', '/usr', '/bin', '/sbin', '/Library', '/private/etc', '/dev', self.root / '.venv', Path(sys.prefix),
                Path(__file__).with_name('security_worker.py'), inputs, scratch]
        rules = ['(version 1)', '(deny default)', '(allow process*)', '(allow sysctl-read)', '(allow mach-lookup)', '(allow file-read-metadata)', '(allow file-read-data (literal "/"))']
        rules += ['(allow file-read* (subpath %s))' % q(p) for p in read]
        rules += ['(allow file-write* (subpath %s))' % q(scratch), '(allow file-write* (literal "/dev/null"))']
        if scope['kind'] != 'local':
            # macOS accepts localhost or wildcard here, not literal remote IPs.
            # Only this immutable worker can use the permitted port(s); its argv
            # pins one authorized IP. Arbitrary project code is never launched.
            for port in scope.get('ports', [scope.get('port')]):
                host = 'localhost' if ipaddress.ip_address(scope['address']).is_loopback else '*'
                rules.append('(allow network-outbound (remote ip "%s:%s"))' % (host, port))
        return ['sandbox-exec', '-p', '\n'.join(rules)]

    def enqueue(self, module, scope_id, authorized):
        if module not in MODULES:
            raise HTTPException(400, 'Unknown security module')
        scope = self.guard(module, scope_id, authorized)
        if len(self.running) >= 2:
            raise HTTPException(429, 'At most two security assessments may run at once')
        identifier = uuid.uuid4().hex
        self.store.execute('INSERT INTO tasks VALUES (?,?,?,?,?,?)', (identifier, 'cyber.' + module,
                           json.dumps({'scope_id': scope_id}), 'queued', None, time.time()))
        async def work():
            try:
                self.store.execute("UPDATE tasks SET state='running' WHERE id=?", (identifier,))
                self.store.event('Security assessment started: ' + module + ' / ' + scope['label'])
                # Inputs are private snapshots outside projects. Generic coding
                # tools cannot read them; workers cannot execute the samples.
                base = self.root / 'memory/cyber-inputs'
                base.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(dir=str(base), prefix='snapshot-') as input_dir, tempfile.TemporaryDirectory(prefix='kraken-security-', dir='/private/tmp') as scratch_dir:
                    inputs, scratch = Path(input_dir), Path(scratch_dir)
                    manifest = self.snapshot(scope, inputs) if scope['kind'] == 'local' else []
                    spec = {k: v for k, v in scope.items() if k in ('kind', 'address', 'ports', 'port', 'scheme', 'path')}
                    spec.update(module=module, input=str(inputs))
                    guard = lambda: self.guard(module, scope_id, authorized)
                    result = await self.control.run(identifier,
                        self.sandbox(inputs, scratch, scope) + [sys.executable, '-I', str(Path(__file__).with_name('security_worker.py')), json.dumps(spec)],
                        scratch, {'PATH': '/usr/bin:/bin:/usr/local/bin', 'HOME': str(scratch), 'TMPDIR': str(scratch), 'PYTHONDONTWRITEBYTECODE': '1'},
                        capabilities=('security', 'computer') + (('internet',) if scope['kind'] != 'local' else ()), guard=guard, timeout=60)
                    guard()
                    if result['exit_code']:
                        raise HTTPException(422, 'Security worker exited ' + str(result['exit_code']) + ': ' + result['output'][:1000])
                    observation = json.loads(result['output'])
                    report = {'id': identifier, 'module': module, 'scope': scope, 'created': time.time(),
                              'status': 'completed', 'input_manifest': manifest, **observation}
                    report['evidence_sha256'] = hashlib.sha256(json.dumps({'evidence': report['evidence'], 'manifest': manifest, 'findings': report['findings']}, sort_keys=True).encode()).hexdigest()
                    self.store.execute('INSERT INTO cyber_reports VALUES (?,?,?,?)', (identifier, identifier, json.dumps(report), time.time()))
                    self.store.execute("UPDATE tasks SET state='completed',result=? WHERE id=?", (json.dumps({'report_id': identifier, 'findings': len(report['findings'])}), identifier))
                    self.store.event('Security assessment completed: ' + module)
            except asyncio.CancelledError:
                self.store.execute("UPDATE tasks SET state='cancelled',result='Security assessment cancelled' WHERE id=?", (identifier,))
                raise
            except Exception as exc:
                self.store.execute("UPDATE tasks SET state='failed',result=? WHERE id=?", (str(getattr(exc, 'detail', exc))[:2000], identifier))
                self.store.event('Security assessment failed: ' + module, 'error')
            finally:
                self.running.pop(identifier, None)
                self.control.tasks.pop(identifier, None)
        task = asyncio.create_task(work())
        self.running[identifier] = {'task': task, 'module': module, 'scope_id': scope_id}
        self.control.tasks[identifier] = task
        return identifier

    async def cancel_matching(self, module=None, scope_id=None):
        async with self.control.lock:
            for entry in list(self.running.values()):
                if (module is None or entry['module'] == module) and (scope_id is None or entry['scope_id'] == scope_id):
                    entry['task'].cancel()
        await asyncio.sleep(0)


def register_cyber(app, cyber, sessions):
    def authorized(request):
        def check():
            session = sessions.get(request.cookies.get('kraken_session', ''))
            if not cyber.store.get('password') or not session or not session.get('password_verified'):
                raise HTTPException(403, 'Configure an owner password in Settings, then sign in to authorize security operations')
            if session['expires'] < time.time() or session['verified'] < time.time() - 600:
                raise HTTPException(401, 'Re-enter the owner password to authorize security operations')
        check()
        return check

    from fastapi import Request

    @app.get('/api/cyber/status')
    async def status():
        return {'modules': {key: dict(value, enabled=cyber.flags()[key]) for key, value in MODULES.items()},
                'scopes': [json.loads(r['data']) for r in cyber.store.rows('SELECT data FROM cyber_scopes')],
                'password_required': not bool(cyber.store.get('password')),
                'dependencies': {'bandit': bool(importlib.util.find_spec('bandit')), 'file': bool(shutil.which('file')), 'otool': bool(shutil.which('otool'))},
                'active_jobs': [{'id': identifier, 'module': entry['module'], 'scope_id': entry['scope_id'], 'pid': cyber.control.processes[identifier].pid if identifier in cyber.control.processes else None} for identifier, entry in cyber.running.items()],
                'limits': {'max_ports': 8, 'max_files': 80, 'max_seconds': 60, 'max_concurrent': 2}}

    @app.patch('/api/cyber/modules/{module}')
    async def module_toggle(module: str, body: dict, request: Request):
        authorized(request)
        if module not in MODULES or type(body.get('enabled')) is not bool:
            raise HTTPException(400, 'Unknown module or invalid enabled value')
        if body['enabled'] and cyber.control.stopped:
            raise HTTPException(423, 'Manually reset emergency stop first')
        flags = cyber.flags()
        flags[module] = body['enabled']
        cyber.store.set('cyber_modules', flags)
        if not body['enabled']:
            await cyber.cancel_matching(module=module)
        cyber.store.event('Owner ' + ('enabled ' if body['enabled'] else 'disabled ') + 'security module ' + module)
        return {'modules': flags}

    @app.post('/api/cyber/scopes')
    async def add_scope(body: ScopeInput, request: Request):
        authorized(request)
        return cyber.create_scope(body)

    @app.delete('/api/cyber/scopes/{identifier}')
    async def remove_scope(identifier: str, request: Request):
        authorized(request)
        cyber.store.execute('DELETE FROM cyber_scopes WHERE id=?', (identifier,))
        await cyber.cancel_matching(scope_id=identifier)
        cyber.store.event('Owner revoked security scope ' + identifier)
        return {'revoked': True}

    @app.post('/api/cyber/run')
    async def run(body: RunInput, request: Request):
        check = authorized(request)
        return {'id': cyber.enqueue(body.module, body.scope_id, check)}

    @app.get('/api/cyber/reports')
    async def reports():
        return [json.loads(r['data']) for r in cyber.store.rows('SELECT data FROM cyber_reports ORDER BY created DESC LIMIT 50')]

    @app.get('/api/cyber/reports/{identifier}/export')
    async def export(identifier: str):
        rows = cyber.store.rows('SELECT data FROM cyber_reports WHERE id=?', (identifier,))
        if not rows:
            raise HTTPException(404, 'Report not found')
        return Response(rows[0]['data'], media_type='application/json', headers={'Content-Disposition': 'attachment; filename="kraken-security-' + identifier + '.json"'})
