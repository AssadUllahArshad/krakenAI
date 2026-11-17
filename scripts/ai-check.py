"""Real Ollama/backend/Aider checks. Uses a dedicated validation conversation/project.
Requires the local server, an installed model and no active owner tasks.
"""
import asyncio
import json
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent

async def main():
    report = {}
    name = 'validation-' + uuid.uuid4().hex[:8]
    async with httpx.AsyncClient(base_url='http://127.0.0.1:8765', timeout=240,
                                trust_env=False, headers={'X-Kraken-Client': 'local'}) as c:
        (await c.post('/api/auth/session', json={})).raise_for_status()
        initial = (await c.get('/api/status')).json()
        if initial['running'] or initial['stopped']:
            raise RuntimeError('Leave active work / existing emergency latch undisturbed')
        if not initial['ready']:
            raise RuntimeError('Install and select the local model before running this check')
        async def flag(cap, enabled):
            (await c.patch('/api/permissions/' + cap, json={'enabled': enabled})).raise_for_status()
        async def task(tool, args):
            r = await c.post('/api/tools', json={'tool': tool, 'args': args})
            r.raise_for_status()
            identifier = r.json()['id']
            for _ in range(800):
                rows = (await c.get('/api/tasks')).json()
                row = next(t for t in rows if t['id'] == identifier)
                if row['state'] not in ('queued', 'running'):
                    print(tool, row['state'], (row['result'] or '')[:1500], flush=True)
                    assert row['state'] == 'completed', row
                    result = json.loads(row['result'])
                    if 'exit_code' in result:
                        assert result['exit_code'] == 0, result
                    return result
                await asyncio.sleep(.3)
            raise RuntimeError('Timed out waiting for ' + tool)
        try:
            await flag('agent', True)
            r = await c.post('/api/chat', json={'conversation': name,
                'message': 'Reply with exactly: KRAKEN connection verified. Do not use tools.'})
            r.raise_for_status()
            response = r.json()
            assert 'KRAKEN connection verified' in response['content'], response
            print('REAL CHAT:', json.dumps(response), flush=True)
            report['chat'] = response
            history = (await c.get('/api/conversations/' + name)).json()
            assert [m['role'] for m in history] == ['user', 'assistant']
            report['conversation'] = name
            # Verify the model can call a real permitted tool.
            await flag('computer', True)
            before = {t['id'] for t in (await c.get('/api/tasks')).json()}
            r = await c.post('/api/chat', json={'conversation': name + '-tool',
                'message': 'Call files_list with path exactly "workspace". Then briefly report what the tool returned.'})
            r.raise_for_status()
            after = (await c.get('/api/tasks')).json()
            called = [t for t in after if t['id'] not in before and t['tool'] == 'files.list' and t['state'] == 'completed']
            assert called, 'Model did not execute the requested tool: ' + r.text
            report['tool_call'] = {'content': r.json()['content'], 'task_ids': [t['id'] for t in called]}
            print('REAL MODEL TOOL CALL: PASS', flush=True)
            await flag('coding', True)
            project = ROOT / 'projects' / name
            project.mkdir()
            instruction = "Create greeting.py with a function greet(name) that returns 'Hello, ' plus name plus '!'. Only create this one Python file. Keep your reply brief."
            report['aider'] = await task('code.aider', {'project': 'projects/' + name, 'instruction': instruction})
            assert (project / 'greeting.py').exists()
            # Run generated code and assert behavior through the sandbox, not unsandboxed import.
            report['project'] = 'projects/' + name
            await task('files.write', {'path': 'projects/' + name + '/verify_greeting.py',
                'content': "from greeting import greet\nassert greet('Hamzi') == 'Hello, Hamzi!'\nprint('Generated Aider code verified')\n"})
            report['generated_execution'] = await task('code.run', {'project': 'projects/' + name,
                'path': 'projects/' + name + '/verify_greeting.py'})
            report['passed'] = True
        finally:
            # Restore permissions without altering owner data or existing project files.
            for cap, enabled in initial['permissions'].items():
                if not enabled:
                    await flag(cap, False)
            for cap, enabled in initial['permissions'].items():
                if enabled:
                    await flag(cap, True)
            (ROOT / 'logs').mkdir(exist_ok=True)
            (ROOT / 'logs/ai-validation.json').write_text(json.dumps(report, indent=2))
    print('Real model integration checks: PASS', flush=True)

if __name__ == '__main__':
    asyncio.run(main())
