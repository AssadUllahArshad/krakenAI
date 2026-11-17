import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse, quote

import httpx
from fastapi import HTTPException

TOOL_CAPS = {
    'files.list': ['computer'], 'files.read': ['computer'], 'files.write': ['computer', 'coding'],
    'code.run': ['computer', 'coding'], 'code.aider': ['computer', 'coding'],
    'git.status': ['computer', 'coding'], 'git.diff': ['computer', 'coding'],
    'web.fetch': ['internet'], 'web.search': ['internet'], 'web.download': ['internet', 'computer'],
    'browser.extract': ['internet'], 'document.read': ['computer'],
    'video.metadata': ['computer', 'coding'], 'video.frames': ['computer', 'coding'],
    'image.inspect': ['computer'], 'security.audit': ['computer', 'security'],
}

class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'noscript'):
            self.skip += 1
    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'noscript'):
            self.skip = max(0, self.skip - 1)
    def handle_data(self, data):
        if not self.skip and data.strip():
            self.parts.append(data.strip())

class Tools:
    def __init__(self, root, store, control):
        self.root, self.store, self.control = Path(root).resolve(), store, control
        self.browser = None

    def path(self, name):
        p = (self.root / name).resolve()
        roots = [self.root / 'workspace', self.root / 'projects']
        if not any(p == r or r in p.parents for r in roots):
            raise HTTPException(403, 'Paths must stay inside projects/ or workspace/')
        # Internal Git metadata and hidden credentials must never be model writable.
        if any(part.startswith('.') for part in p.relative_to(self.root).parts):
            raise HTTPException(403, 'Hidden paths are not available to tools')
        return p

    async def validate_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
            raise HTTPException(400, 'A public HTTP(S) URL without credentials is required')
        if parsed.port not in (None, 80, 443):
            raise HTTPException(403, 'Only public web ports 80 and 443 are allowed')
        try:
            records = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80), type=socket.SOCK_STREAM)
            addresses = {r[4][0] for r in records}
            if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
                raise HTTPException(403, 'Private, loopback and link-local destinations are blocked')
        except socket.gaierror as exc:
            raise HTTPException(502, 'Could not resolve public hostname') from exc
        return parsed, sorted(addresses)[0]

    async def fetch(self, url, binary=False):
        # Pin the validated IP to prevent DNS rebinding; validate every redirect.
        for _ in range(6):
            self.control.check('internet')
            parsed, address = await self.validate_url(url)
            pinned = parsed._replace(netloc=('[' + address + ']' if ':' in address else address)).geturl()
            async with httpx.AsyncClient(timeout=25, trust_env=False) as client:
                async with client.stream('GET', pinned, headers={'Host': parsed.hostname, 'User-Agent': 'KrakenAI/1.0'}, extensions={'sni_hostname': parsed.hostname.encode()}) as response:
                    if response.is_redirect:
                        from urllib.parse import urljoin
                        url = urljoin(url, response.headers['location'])
                        continue
                    response.raise_for_status()
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        self.control.check('internet')
                        data.extend(chunk)
                        if len(data) > 5_000_000:
                            raise HTTPException(413, 'Download limit is 5 MB')
                    if binary:
                        return bytes(data)
                    text = data.decode('utf-8', errors='replace')
                    parser = TextParser()
                    parser.feed(text)
                    return {'source': url, 'verified': True, 'text': '\n'.join(parser.parts)[:60000]}
        raise HTTPException(400, 'Too many redirects')

    def sandbox(self, project, network=False):
        if sys.platform != 'darwin' or not shutil.which('sandbox-exec'):
            raise HTTPException(503, 'Code execution requires the macOS sandbox; refusing unsandboxed execution')
        def quoted(p):
            return json.dumps(str(p))
        read_roots = ['/System', '/usr', '/bin', '/sbin', '/Library', '/private/etc', '/dev',
                      str(self.root / '.venv'), '/Users/ali/.local/share/uv', '/Users/ali/.local/bin']
        rules = ['(version 1)', '(deny default)', '(allow process*)', '(allow sysctl-read)',
                 '(allow mach-lookup)', '(allow file-read-metadata)', '(allow file-read* (literal "/"))']
        rules += ['(allow file-read* (subpath %s))' % quoted(p) for p in read_roots]
        rules += ['(allow file-read* file-write* (subpath %s))' % quoted(project),
                  '(allow file-read* file-write* (subpath "/private/tmp/kraken-exec"))',
                  '(allow file-write* (literal "/dev/null"))']
        # The sole network exception is the local inference service for Aider.
        if network:
            rules += ['(allow network-outbound (remote ip "localhost:8766"))']
        return ['sandbox-exec', '-p', '\n'.join(rules)]

    async def execute(self, tool, args, identifier):
        if tool not in TOOL_CAPS:
            raise HTTPException(404, 'Unknown tool')
        self.control.check(*TOOL_CAPS[tool])
        if tool == 'files.list':
            p = self.path(args.get('path', 'workspace'))
            return [{'path': str(x.relative_to(self.root)), 'directory': x.is_dir()} for x in sorted(p.iterdir()) if not x.name.startswith('.')][:500]
        if tool in ('files.read', 'document.read'):
            p = self.path(args['path'])
            if p.stat().st_size > 5_000_000:
                raise HTTPException(413, 'File exceeds 5 MB')
            if p.suffix.lower() == '.pdf':
                from pypdf import PdfReader
                return {'text': '\n'.join(page.extract_text() or '' for page in PdfReader(p).pages)[:100000]}
            return {'text': p.read_text()[:100000]}
        if tool == 'files.write':
            p = self.path(args['path'])
            content = args['content']
            if len(content.encode()) > 1_000_000:
                raise HTTPException(413, 'Write limit is 1 MB')
            p.parent.mkdir(parents=True, exist_ok=True)
            # No await between the permission check and the filesystem mutation.
            self.control.check('computer', 'coding')
            p.write_text(content)
            return {'path': str(p.relative_to(self.root)), 'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
        if tool in ('web.fetch', 'web.search', 'web.download'):
            url = args.get('url')
            if tool == 'web.search':
                provider = self.store.get('search_provider', 'duckduckgo')
                url = ('https://en.wikipedia.org/w/index.php?search=' if provider == 'wikipedia' else 'https://html.duckduckgo.com/html/?q=') + quote(args['query'])
            result = await self.fetch(url, tool == 'web.download')
            if tool == 'web.download':
                p = self.path(args['path'])
                self.control.check('internet', 'computer')
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(result)
                return {'path': str(p.relative_to(self.root)), 'bytes': len(result)}
            return result
        if tool == 'browser.extract':
            # Browser JS is disabled and every request is fulfilled through the pinned,
            # checked HTTP gateway. Chromium itself receives no unmediated web requests.
            from playwright.async_api import async_playwright
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(java_script_enabled=False, service_workers='block')
                    async def route(request_route):
                        if request_route.request.resource_type not in ('document',):
                            await request_route.abort()
                            return
                        try:
                            result = await self.fetch(request_route.request.url)
                            import html
                            await request_route.fulfill(body='<html><body><pre>' + html.escape(result['text']) + '</pre></body></html>', content_type='text/html')
                        except Exception:
                            await request_route.abort()
                    await context.route('**/*', route)
                    page = await context.new_page()
                    await page.goto(args['url'], wait_until='domcontentloaded', timeout=30000)
                    return {'source': args['url'], 'verified': True, 'text': (await page.inner_text('body'))[:60000], 'mode': 'Read-only browser extraction; JavaScript disabled'}
                finally:
                    await browser.close()
        if tool == 'image.inspect':
            p = self.path(args['path'])
            if p.stat().st_size > 5_000_000:
                raise HTTPException(413, 'Image exceeds 5 MB')
            model = self.store.get('vision_model', '')
            if not model:
                raise HTTPException(503, 'Configure an installed local vision model in settings first')
            async with httpx.AsyncClient(timeout=180, trust_env=False) as client:
                r = await client.post('http://127.0.0.1:11434/api/chat', json={'model': model, 'stream': False, 'messages': [{'role': 'user', 'content': args.get('prompt', 'Describe this image.'), 'images': [base64.b64encode(p.read_bytes()).decode()]}]})
                r.raise_for_status()
                return {'generated': True, 'text': r.json()['message']['content']}
        if tool == 'security.audit':
            if not self.store.get('cyber_modules', {}).get('code_review') or not self.store.get('password'):
                raise HTTPException(403, 'Enable owner-authenticated code review in the Cybersecurity Control Center first')
            p = self.path(args['path'])
            scope = self.store.get('security_targets', [])
            if not any(p == self.path(s) or self.path(s) in p.parents for s in scope):
                raise HTTPException(403, 'Path is outside the explicitly authorized security scope')
            text = p.read_text()[:200000]
            findings = []
            for number, line in enumerate(text.splitlines(), 1):
                for pattern, title in [(r'\beval\s*\(', 'Dynamic evaluation'), (r'shell\s*=\s*True', 'Shell execution'), (r'verify\s*=\s*False', 'TLS verification disabled'), (r'(?i)(password|api_key|secret)\s*=\s*[\x22\x27][^\x22\x27]+', 'Possible embedded credential')]:
                    if re.search(pattern, line):
                        findings.append({'line': number, 'finding': title})
            return {'path': args['path'], 'findings': findings, 'scope': 'Static heuristic review; no active testing, no completeness guarantee'}
        project = self.path(args.get('project', 'projects/test-app'))
        if not project.is_dir() or project in (self.root / 'projects', self.root / 'workspace'):
            raise HTTPException(400, 'Choose an existing project subdirectory')
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': '/private/tmp/kraken-exec', 'TMPDIR': '/private/tmp/kraken-exec', 'PYTHONDONTWRITEBYTECODE': '1', 'NO_COLOR': '1', 'OLLAMA_API_BASE': 'http://127.0.0.1:8766', 'OLLAMA_API_KEY': getattr(self, 'inference_token', ''), 'DO_NOT_TRACK': '1', 'AIDER_ANALYTICS': 'false', 'LITELLM_LOCAL_MODEL_COST_MAP': 'True'}
        Path('/private/tmp/kraken-exec').mkdir(mode=0o700, exist_ok=True)
        argv = []
        metadata_file = None
        local_inference = False
        if tool.startswith('git.'):
            argv = ['git', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', tool.split('.')[1], '--no-ext-diff'] if tool == 'git.diff' else ['git', '-c', 'core.fsmonitor=false', 'status', '--short']
        elif tool == 'code.run':
            language = args.get('language', 'python')
            script = self.path(args['path'])
            if project not in script.parents:
                raise HTTPException(403, 'Script must be inside the selected project')
            executables = {'python': sys.executable, 'javascript': shutil.which('node')}
            if language not in executables or not executables[language]:
                raise HTTPException(400, 'Supported execution languages: python, javascript')
            argv = [executables[language], str(script)]
        elif tool == 'code.aider':
            if not shutil.which('aider'):
                raise HTTPException(503, 'Aider is not installed')
            if not getattr(self, 'inference_token', None) or os.environ.get('KRAKEN_INFERENCE_PROXY') != '1':
                raise HTTPException(503, 'Start with scripts/start.sh to enable the restricted inference gateway')
            local_inference = True
            model_name = 'ollama_chat/' + self.store.get('model', 'kraken')
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', prefix='aider-model-', dir='/private/tmp/kraken-exec', delete=False) as metadata:
                json.dump({model_name: {'max_input_tokens': 4096, 'max_output_tokens': 2048,
                    'input_cost_per_token': 0, 'output_cost_per_token': 0,
                    'litellm_provider': 'ollama_chat', 'mode': 'chat'}}, metadata)
                metadata_file = metadata.name
            argv = ['aider', '--model', 'ollama_chat/' + self.store.get('model', 'kraken'), '--message', args['instruction'], '--yes-always', '--no-auto-commits', '--no-auto-test', '--no-auto-lint', '--no-detect-urls', '--no-check-update', '--no-show-release-notes', '--no-analytics', '--no-show-model-warnings', '--subtree-only', '--no-gitignore', '--model-metadata-file', metadata_file]
        elif tool.startswith('video.'):
            p = self.path(args['path'])
            if project not in p.parents:
                raise HTTPException(403, 'Video must be inside selected project')
            if tool == 'video.metadata':
                argv = ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', str(p)]
            else:
                out = project / 'frames'
                out.mkdir(exist_ok=True)
                argv = ['ffmpeg', '-nostdin', '-i', str(p), '-vf', 'fps=1/30', '-frames:v', '20', '-n', str(out / 'frame-%03d.jpg')]
        try:
            return await self.control.run(identifier, self.sandbox(project, local_inference) + argv, project, env)
        finally:
            if metadata_file:
                Path(metadata_file).unlink(missing_ok=True)


def tool_schema(name):
    """Expose only arguments relevant to a tool; small models need concrete paths."""
    path = {'type': 'string', 'description': 'Path relative to KRAKEN, starting with workspace/ or projects/. Never use dot or an absolute path.', 'examples': ['workspace', 'projects/test-app/calculator.py']}
    project = {'type': 'string', 'description': 'Existing project directory, for example projects/test-app.', 'default': 'projects/test-app'}
    url = {'type': 'string', 'description': 'Public HTTP(S) webpage URL, for example https://example.com.'}
    properties = {'path': path}
    required = ['path']
    if name == 'files.list':
        properties = {'path': dict(path, default='workspace', description='Directory to list. Use exactly workspace for the default workspace, or projects/test-app for that project. Never use dot.')}
        required = []
    elif name == 'files.write':
        properties = {'path': path, 'content': {'type': 'string', 'description': 'Complete UTF-8 file content to write.'}}
        required = ['path', 'content']
    elif name == 'code.run':
        properties = {'path': path, 'project': project, 'language': {'type': 'string', 'enum': ['python', 'javascript'], 'default': 'python'}}
    elif name == 'code.aider':
        properties = {'project': project, 'instruction': {'type': 'string', 'description': 'Concrete code change for Aider to make in the selected project.'}}
        required = ['instruction']
    elif name.startswith('git.'):
        properties, required = {'project': project}, []
    elif name in ('web.fetch', 'browser.extract'):
        properties, required = {'url': url}, ['url']
    elif name == 'web.search':
        properties, required = {'query': {'type': 'string', 'description': 'Web search terms.'}}, ['query']
    elif name == 'web.download':
        properties, required = {'url': url, 'path': path}, ['url', 'path']
    elif name.startswith('video.'):
        properties = {'path': path, 'project': project}
    elif name == 'image.inspect':
        properties = {'path': path, 'prompt': {'type': 'string', 'description': 'Question about this image.'}}
    return {'type': 'function', 'function': {'name': name.replace('.', '_'),
        'description': 'Execute ' + name + '. Returns verified tool output or an explicit error. Use only the listed arguments.',
        'parameters': {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}}}
