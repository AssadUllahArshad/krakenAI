"""Live integration checks. Does not run a mock model or alter existing user files."""
import asyncio
import json
import time
from pathlib import Path
import httpx

async def main():
    async with httpx.AsyncClient(base_url='http://127.0.0.1:8765', headers={'X-Kraken-Client': 'local'}, timeout=40, trust_env=False) as c:
        r = await c.post('/api/auth/session', json={})
        r.raise_for_status()
        home = await c.get('/')
        assert home.status_code == 200 and 'KRAKEN' in home.text
        status = (await c.get('/api/status')).json()
        print('Dashboard HTML: PASS')
        print('Ollama installed models:', status['models'])
        print('Real model readiness:', status['ready'])
        for cap in ('agent', 'computer', 'coding', 'internet'):
            r = await c.patch('/api/permissions/' + cap, json={'enabled': True})
            r.raise_for_status()
        async def tool(name, args):
            r = await c.post('/api/tools', json={'tool': name, 'args': args})
            r.raise_for_status()
            identifier = r.json()['id']
            for _ in range(120):
                tasks = (await c.get('/api/tasks')).json()
                task = next(t for t in tasks if t['id'] == identifier)
                if task['state'] not in ('queued', 'running'):
                    print(name + ': ' + task['state'], (task['result'] or '')[:500])
                    return task
                await asyncio.sleep(.25)
            raise RuntimeError('Tool timed out: ' + name)
        name = 'projects/test-app/kraken_smoke_' + str(int(time.time())) + '.py'
        assert (await tool('files.write', {'path': name, 'content': "print('KRAKEN verified execution')\n"}))['state'] == 'completed'
        await tool('code.run', {'path': name, 'project': 'projects/test-app', 'language': 'python'})
        await tool('web.fetch', {'url': 'https://example.com'})
        await tool('browser.extract', {'url': 'https://example.com'})
        r = await c.post('/api/emergency-stop', json={'reason': 'Live integration verification'})
        assert r.json()['stopped']
        assert (await c.post('/api/tools', json={'tool': 'files.list'})).status_code == 423
        print('Live emergency latch and execution denial: PASS')
        assert (await c.post('/api/reset', json={})).status_code == 200
        assert not any((await c.get('/api/status')).json()['permissions'].values())
        print('Reset leaves capabilities disabled: PASS')
        # Remove only the exact temporary project file created by this check.
        Path(name).unlink(missing_ok=True)

if __name__ == '__main__':
    asyncio.run(main())
