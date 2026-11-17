import asyncio
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException

from backend.app import create_app
from backend.control import CAPABILITIES
from backend.store import Store
from backend.tools import TOOL_CAPS

@pytest.fixture
def app(tmp_path):
    for folder in ('workspace', 'projects/test-app', 'memory'):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
    application = create_app(tmp_path)
    yield application
    application.state.store.db.close()

@pytest.fixture
def client(app):
    c = TestClient(app, headers={'X-Kraken-Client': 'local'})
    assert c.post('/api/auth/session', json={}).status_code == 200
    yield c


def enable(client, *caps):
    for cap in caps:
        assert client.patch('/api/permissions/' + cap, json={'enabled': True}).status_code == 200


def test_auth_origin_host(client):
    fresh = TestClient(client.app)
    assert fresh.get('/api/memory').status_code == 401
    assert fresh.post('/api/auth/session', json={}).status_code == 403
    assert client.get('/api/memory', headers={'Host': 'evil.example'}).status_code == 403
    assert fresh.post('/api/auth/session', json={}, headers={'Origin': 'https://evil.example'}).status_code == 403


def test_memory_persistence_and_deletion(client, app):
    response = client.post('/api/memory', json={'kind': 'preference', 'content': 'Use concise explanations'})
    identifier = response.json()['id']
    second = Store(Path(app.state.store.db.execute('PRAGMA database_list').fetchone()[2]))
    assert second.rows('SELECT * FROM memory')[0]['content'] == 'Use concise explanations'
    second.db.close()
    assert len(client.get('/api/memory?q=concise').json()) == 1
    assert client.delete('/api/memory/' + str(identifier)).status_code == 200
    assert client.get('/api/memory').json() == []


@pytest.mark.parametrize('tool', list(TOOL_CAPS))
def test_each_tool_denied_by_each_disabled_dependency(client, tool):
    for cap in TOOL_CAPS[tool]:
        enable(client, *[c for c in TOOL_CAPS[tool] if c != cap])
        client.patch('/api/permissions/' + cap, json={'enabled': False})
        response = client.post('/api/tools', json={'tool': tool, 'args': {}})
        assert response.status_code == 403, (tool, cap, response.text)


def test_agent_pause_blocks_tools_and_chat(client):
    enable(client, 'computer')
    client.patch('/api/permissions/agent', json={'enabled': False})
    assert client.post('/api/tools', json={'tool': 'files.list'}).status_code == 403
    assert client.post('/api/chat', json={'message': 'Hello'}).status_code == 403


def test_path_traversal_and_symlink(app, tmp_path):
    tools = app.state.tools
    for name in ('/etc/passwd', 'workspace/../../secret', 'projects/test-app/.git/config'):
        with pytest.raises(HTTPException):
            tools.path(name)
    (tmp_path / 'workspace/link').symlink_to('/etc')
    with pytest.raises(HTTPException):
        tools.path('workspace/link/passwd')


def test_emergency_latched_across_restart(client, app):
    enable(client, 'computer', 'coding', 'internet', 'automation')
    client.post('/api/schedules', json={'tool': 'files.list', 'args': {}, 'due': time.time() + 600})
    assert client.post('/api/emergency-stop', json={'reason': 'Test stop'}).json()['stopped']
    assert client.post('/api/tools', json={'tool': 'files.list'}).status_code == 423
    assert client.patch('/api/permissions/computer', json={'enabled': True}).status_code == 423
    assert not any(app.state.control.flags.values())
    assert app.state.store.rows('SELECT state FROM schedules')[0]['state'] == 'cancelled'
    from backend.control import Control
    assert Control(app.state.store).stopped
    client.post('/api/reset', json={})
    assert not any(app.state.control.flags.values())
    assert client.post('/api/tools', json={'tool': 'files.list'}).status_code == 403


def test_face_unavailable(client):
    assert client.patch('/api/permissions/face', json={'enabled': True}).status_code == 501


def test_password_hash_sessions(client, app):
    assert client.post('/api/auth/password', json={'password': 'short'}).status_code == 400
    assert client.post('/api/auth/password', json={'password': 'a-good-password'}).status_code == 200
    assert app.state.store.get('password')['hash'] != 'a-good-password'
    assert client.get('/api/memory').status_code == 401
    assert client.post('/api/auth/session', json={'password': 'wrong'}).status_code == 401
    assert client.post('/api/auth/session', json={'password': 'a-good-password'}).status_code == 200
    assert client.get('/api/memory').status_code == 200


def test_network_cut_and_lock(client, app):
    enable(client, 'internet', 'computer', 'coding')
    client.post('/api/cut-network', json={})
    assert client.post('/api/tools', json={'tool': 'web.fetch', 'args': {'url': 'https://example.com'}}).status_code == 403
    client.post('/api/lock', json={})
    assert not any(app.state.control.flags.values())


def test_private_network_rejected(app):
    async def scenario():
        for url in ['http://127.0.0.1', 'http://169.254.169.254', 'file:///etc/passwd', 'https://user:pass@example.com', 'http://192.168.1.1', 'http://example.com:1234']:
            with pytest.raises(HTTPException):
                await app.state.tools.validate_url(url)
    asyncio.run(scenario())


def test_file_write_read_and_security_scope(app, tmp_path):
    async def scenario():
        c, tools = app.state.control, app.state.tools
        for cap in ('computer', 'coding', 'security'):
            c.flags[cap] = True
        result = await tools.execute('files.write', {'path': 'projects/test-app/a.py', 'content': 'print(42)'}, 'write')
        assert result['bytes'] == 9
        assert (await tools.execute('files.read', {'path': 'projects/test-app/a.py'}, 'read'))['text'] == 'print(42)'
        with pytest.raises(HTTPException):
            await tools.execute('security.audit', {'path': 'projects/test-app/a.py'}, 'audit')
        app.state.store.set('security_targets', ['projects/test-app'])
        # Legacy heuristic now also requires the new owner-controlled module.
        with pytest.raises(HTTPException):
            await tools.execute('security.audit', {'path': 'projects/test-app/a.py'}, 'audit')
        app.state.store.set('cyber_modules', {'code_review': True})
        app.state.store.set('password', {'test-only': 'configured'})
        assert (await tools.execute('security.audit', {'path': 'projects/test-app/a.py'}, 'audit'))['findings'] == []
    asyncio.run(scenario())


def test_emergency_cancels_pending_and_owned_process(app, tmp_path):
    async def scenario():
        c = app.state.control
        c.flags.update(computer=True, coding=True)
        script = tmp_path / 'projects/test-app/sleep.py'
        script.write_text('import time; time.sleep(120)')
        task = asyncio.create_task(c.run('owned', [sys.executable, str(script)], script.parent))
        c.tasks['owned'] = task
        for _ in range(100):
            if c.processes:
                break
            await asyncio.sleep(.01)
        assert c.processes
        proc = c.processes['owned']
        await c.revoke('Integration stop', stop=True)
        stopped = await asyncio.gather(task, return_exceptions=True)
        assert proc.returncode is not None, repr(stopped)
        assert c.stopped
        with pytest.raises(HTTPException):
            await c.run('new', [sys.executable, '-c', 'print(1)'], script.parent)
    asyncio.run(scenario())


def test_chat_ollama_adapter_and_persistence(client, app):
    from unittest.mock import AsyncMock, MagicMock
    response = MagicMock()
    response.json.return_value = {'message': {'role': 'assistant', 'content': 'Development adapter response'}}
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = response
    with patch('backend.app.httpx.AsyncClient', return_value=mock_client):
        result = client.post('/api/chat', json={'message': 'Hi'})
    assert result.status_code == 200
    assert result.json()['generated'] is True
    assert [m['role'] for m in client.get('/api/conversations/main').json()] == ['user', 'assistant']
    sent = mock_client.post.call_args.kwargs['json']
    assert sent['model'] == 'kraken'
    assert sent['stream'] is False
    client.delete('/api/conversations/main')
    assert client.get('/api/conversations/main').json() == []


def test_scheduling_requires_automation(client):
    response = client.post('/api/schedules', json={'tool': 'files.list', 'due': time.time() + 60})
    assert response.status_code == 403
    enable(client, 'automation', 'computer')
    response = client.post('/api/schedules', json={'tool': 'files.list', 'due': time.time() + 60})
    assert response.status_code == 200
    assert client.delete('/api/schedules/' + str(response.json()['id'])).status_code == 200


def test_settings_validation_atomic(client, app):
    assert client.patch('/api/settings', json={'security_targets': ['/etc']}).status_code == 403
    assert client.patch('/api/settings', json={'model': 'newmodel', 'bad': 'field'}).status_code == 400
    assert app.state.store.get('model', 'kraken') == 'kraken'


def test_interrupted_task_recovery(tmp_path):
    path = tmp_path / 'db.sqlite'
    s = Store(path)
    s.execute('INSERT INTO tasks VALUES (?,?,?,?,?,?)', ('id', 'files.list', '{}', 'running', None, time.time()))
    s.db.close()
    s = Store(path)
    assert s.rows('SELECT state FROM tasks')[0]['state'] == 'interrupted'
    s.db.close()


def test_inference_gateway_blocks_admin_and_unscoped_models(app):
    from backend.inference import create_gateway
    c = TestClient(create_gateway(app.state.store, app.state.control, 'test-token'))
    assert c.post('/api/pull', json={'model': 'kraken'}).status_code == 401
    c.headers['Authorization'] = 'Bearer test-token'
    app.state.control.flags.update(coding=True, computer=True)
    assert c.post('/api/pull', json={'model': 'kraken'}).status_code == 403
    assert c.post('/api/chat', json={'model': 'unapproved-model'}).status_code == 403
    app.state.control.flags['coding'] = False
    assert c.post('/api/chat', json={'model': 'kraken'}).status_code == 403


def test_public_fetch_pins_ip_and_preserves_hostname(app):
    from unittest.mock import AsyncMock
    control = app.state.control
    control.flags['internet'] = True
    tools = app.state.tools
    urls = []
    def handler(request):
        urls.append(request)
        return httpx.Response(200, text='<h1>Verified title</h1><script>ignore this</script>')
    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient
    async def scenario():
        with patch.object(tools, 'validate_url', new=AsyncMock(return_value=(__import__('urllib.parse', fromlist=['urlparse']).urlparse('https://example.com/path'), '93.184.216.34'))):
            with patch('backend.tools.httpx.AsyncClient', side_effect=lambda **kwargs: real_client(transport=transport, **kwargs)):
                result = await tools.fetch('https://example.com/path')
        assert result['verified']
        assert result['text'] == 'Verified title'
        assert str(urls[0].url) == 'https://93.184.216.34/path'
        assert urls[0].headers['host'] == 'example.com'
        assert urls[0].extensions['sni_hostname'] == b'example.com'
    asyncio.run(scenario())


def test_recent_authentication_required_but_emergency_available(client):
    with patch('backend.app.time.time', return_value=time.time() + 601):
        assert client.post('/api/memory', json={'content': 'note'}).status_code == 200
    # Password protection activates the recent-auth requirement.
    client.post('/api/auth/password', json={'password': 'owner-password-long'})
    client.post('/api/auth/session', json={'password': 'owner-password-long'})
    with patch('backend.app.time.time', return_value=time.time() + 601):
        assert client.post('/api/memory', json={'content': 'note'}).status_code == 401
        assert client.post('/api/emergency-stop', json={}).status_code == 200


def test_scheduler_executes_real_file_tool(tmp_path):
    for folder in ('workspace', 'projects/test-app', 'memory'):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
    application = create_app(tmp_path)
    with TestClient(application, headers={'X-Kraken-Client': 'local'}) as c:
        c.post('/api/auth/session', json={})
        enable(c, 'automation', 'computer', 'coding')
        r = c.post('/api/schedules', json={'tool': 'files.write', 'args': {'path': 'workspace/scheduled.txt', 'content': 'Scheduled output'}, 'due': time.time() + .1})
        assert r.status_code == 200
        for _ in range(30):
            if (tmp_path / 'workspace/scheduled.txt').exists():
                break
            time.sleep(.1)
        assert (tmp_path / 'workspace/scheduled.txt').read_text() == 'Scheduled output'
        assert c.get('/api/schedules').json()[0]['state'].startswith('dispatched:')
