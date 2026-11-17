"""Regression coverage for chat failures, permission gates and concurrent cancellation.
These adapter tests are separate from the real-model checks in scripts/ai-check.py.
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from scripts.serve import reserve_listeners


@pytest.fixture
def app(tmp_path):
    (tmp_path / 'memory').mkdir()
    application = create_app(tmp_path)
    yield application
    application.state.store.db.close()


def adapter(content='A real-shaped development adapter reply'):
    response = MagicMock()
    response.json.return_value = {'message': {'role': 'assistant', 'content': content}}
    mock = AsyncMock()
    mock.__aenter__.return_value = mock
    mock.post.return_value = response
    return mock


def owner(app):
    c = TestClient(app, headers={'X-Kraken-Client': 'local'})
    c.post('/api/auth/session', json={}).raise_for_status()
    return c


def test_plain_chat_omits_tools_and_disables_thinking(app):
    c = owner(app)
    mock = adapter()
    with patch('backend.app.httpx.AsyncClient', return_value=mock):
        r = c.post('/api/chat', json={'message': 'Hello'})
    assert r.status_code == 200
    payload = mock.post.call_args.kwargs['json']
    assert 'tools' not in payload
    assert payload['think'] is False
    assert payload['options']['num_ctx'] == 4096
    assert r.json()['model'] == 'kraken'
    assert r.json()['elapsed_seconds'] >= 0


@pytest.mark.parametrize('error,code,text', [
    (httpx.ConnectError('Unavailable'), 503, 'Cannot connect'),
    (httpx.ReadTimeout('Too slow'), 504, 'took too long'),
    (ValueError('Bad JSON'), 502, 'invalid response'),
])
def test_chat_errors_are_actionable(app, error, code, text):
    c = owner(app)
    mock = adapter()
    mock.post.side_effect = error
    with patch('backend.app.httpx.AsyncClient', return_value=mock):
        r = c.post('/api/chat', json={'message': 'Hello'})
    assert r.status_code == code
    assert text in r.json()['detail']
    assert app.state.control.tasks == {}


def test_ollama_model_error_is_preserved(app):
    c = owner(app)
    mock = adapter()
    response = httpx.Response(404, json={'error': "model 'missing' not found"}, request=httpx.Request('POST', 'http://127.0.0.1:11434/api/chat'))
    mock.post.return_value.raise_for_status.side_effect = httpx.HTTPStatusError('Missing model', request=response.request, response=response)
    with patch('backend.app.httpx.AsyncClient', return_value=mock):
        r = c.post('/api/chat', json={'message': 'Hello'})
    assert r.status_code == 502
    assert "model 'missing' not found" in r.json()['detail']


def test_empty_reply_is_not_reported_as_success(app):
    c = owner(app)
    with patch('backend.app.httpx.AsyncClient', return_value=adapter('')):
        assert c.post('/api/chat', json={'message': 'Hello'}).status_code == 502
    assert [m['role'] for m in c.get('/api/conversations/main').json()] == ['user']


def test_schemas_only_expose_enabled_tools_and_execution_rechecks(app):
    c = owner(app)
    c.patch('/api/permissions/computer', json={'enabled': True})
    mock = adapter()
    with patch('backend.app.httpx.AsyncClient', return_value=mock):
        c.post('/api/chat', json={'message': 'Hello'}).raise_for_status()
    names = {t['function']['name'] for t in mock.post.call_args.kwargs['json']['tools']}
    assert 'files_read' in names
    assert 'files_write' not in names
    assert 'web_fetch' not in names
    assert 'security_audit' not in names
    assert 'code_run' not in names


@pytest.mark.parametrize('action,expected', [('cancel', 409), ('emergency', 423)])
def test_stop_is_independent_of_waiting_inference(app, action, expected):
    real_client = httpx.AsyncClient
    mock = adapter()
    async def scenario():
        entered = asyncio.Event()
        async def stalled(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        mock.post.side_effect = stalled
        transport = httpx.ASGITransport(app=app)
        async with real_client(transport=transport, base_url='http://testserver', headers={'X-Kraken-Client': 'local'}) as c:
            (await c.post('/api/auth/session', json={})).raise_for_status()
            with patch('backend.app.httpx.AsyncClient', return_value=mock):
                reply = asyncio.create_task(c.post('/api/chat', json={'message': 'Wait', 'conversation': 'stop-test'}))
                await asyncio.wait_for(entered.wait(), 2)
                duplicate = await c.post('/api/chat', json={'message': 'Duplicate', 'conversation': 'stop-test'})
                assert duplicate.status_code == 409
                if action == 'cancel':
                    stopped = await c.post('/api/chat/stop-test/cancel', json={})
                    assert stopped.json()['cancelled']
                else:
                    stopped = await c.post('/api/emergency-stop', json={})
                    assert stopped.json()['stopped']
                result = await asyncio.wait_for(reply, 2)
                assert result.status_code == expected
                assert app.state.control.tasks == {}
                if action == 'emergency':
                    assert (await c.post('/api/tools', json={'tool': 'files.list'})).status_code == 423
    asyncio.run(scenario())


def test_startup_releases_first_listener_if_second_is_occupied():
    first, second = MagicMock(), MagicMock()
    second.bind.side_effect = OSError(48, 'Address already in use')
    with patch('scripts.serve.socket.socket', side_effect=[first, second]):
        with pytest.raises(RuntimeError, match='8766'):
            reserve_listeners()
    first.close.assert_called_once()
    second.close.assert_called_once()


def test_tool_schema_has_only_relevant_arguments():
    from backend.tools import tool_schema, TOOL_CAPS
    schema = tool_schema('files.list')['function']['parameters']
    assert set(schema['properties']) == {'path'}
    assert schema['properties']['path']['default'] == 'workspace'
    for name in TOOL_CAPS:
        parameters = tool_schema(name)['function']['parameters']
        assert set(parameters['required']) <= set(parameters['properties'])
        assert parameters['additionalProperties'] is False


def test_app_construction_does_not_interrupt_another_server(tmp_path):
    from backend.store import Store
    root = tmp_path / 'project'
    db = root / 'memory/kraken.sqlite3'
    s = Store(db)
    s.execute('INSERT INTO tasks VALUES (?,?,?,?,?,?)', ('active', 'files.list', '{}', 'running', None, 0))
    application = create_app(root)
    assert s.rows('SELECT state FROM tasks')[0]['state'] == 'running'
    application.state.store.db.close()
    s.db.close()


def test_model_cannot_bypass_disabled_tool_permission(app):
    c = owner(app)
    c.patch('/api/permissions/computer', json={'enabled': True})
    mock = adapter()
    first, second = MagicMock(), MagicMock()
    first.json.return_value = {'message': {'role': 'assistant', 'content': '', 'tool_calls': [
        {'function': {'name': 'files_write', 'arguments': {'path': 'workspace/forbidden.txt', 'content': 'not allowed'}}}]}}
    second.json.return_value = {'message': {'role': 'assistant', 'content': 'The tool was denied.'}}
    mock.post.side_effect = [first, second]
    with patch('backend.app.httpx.AsyncClient', return_value=mock):
        r = c.post('/api/chat', json={'message': 'Try the disabled tool'})
    assert r.status_code == 200
    assert not (app.state.tools.root / 'workspace/forbidden.txt').exists()
    tool_message = [m for m in mock.post.call_args.kwargs['json']['messages'] if m['role'] == 'tool'][0]
    assert 'coding is disabled' in tool_message['content']


def test_nonzero_process_exit_is_recorded_as_failure(app):
    import time
    with TestClient(app, headers={'X-Kraken-Client':'local'}) as c:
        c.post('/api/auth/session', json={})
        c.patch('/api/permissions/computer', json={'enabled': True})
        c.patch('/api/permissions/coding', json={'enabled': True})
        with patch.object(app.state.tools, 'execute', new=AsyncMock(return_value={'exit_code': 1, 'output': 'Actual failure'})):
            r = c.post('/api/tools', json={'tool':'code.run','args':{}})
            assert r.status_code == 200
            for _ in range(30):
                task = c.get('/api/tasks').json()[0]
                if task['state'] not in ('queued','running'):
                    break
                time.sleep(.01)
            assert task['state'] == 'failed'
            assert json.loads(task['result'])['exit_code'] == 1


def test_gateway_invalid_json_is_a_client_error(app):
    from backend.inference import create_gateway
    app.state.control.flags.update(computer=True,coding=True)
    c = TestClient(create_gateway(app.state.store,app.state.control,'test'))
    for body in ('not json','[]'):
        r = c.post('/api/chat', content=body, headers={'Authorization':'Bearer test'})
        assert r.status_code == 400


def test_aider_gateway_bounds_context_and_forwards_configured_model(app):
    from backend.inference import create_gateway
    app.state.control.flags.update(computer=True,coding=True)
    app.state.store.set('model','kraken:latest')
    gateway = TestClient(create_gateway(app.state.store,app.state.control,'test'))
    mock = AsyncMock()
    mock.build_request = MagicMock(return_value=httpx.Request('POST','http://127.0.0.1:11434/api/chat'))
    mock.send.return_value = httpx.Response(200,content=b'{"response":"ok"}',headers={'content-type':'application/json'})
    with patch('backend.inference.httpx.AsyncClient', return_value=mock):
        r = gateway.post('/api/chat',json={'model':'kraken','think':True,'options':{'num_ctx':30000}},headers={'Authorization':'Bearer test'})
    assert r.status_code == 200
    payload = mock.build_request.call_args.kwargs['json']
    assert payload['model'] == 'kraken:latest'
    assert payload['think'] is False
    assert payload['options']['num_ctx'] == 4096
    assert payload['options']['num_predict'] == 2048


def test_aider_uses_explicit_local_metadata_and_cleans_it(app):
    from pathlib import Path
    project = app.state.tools.root / 'projects/test-app'
    project.mkdir(parents=True)
    app.state.control.flags.update(computer=True,coding=True)
    metadata_paths = []
    async def run(identifier, argv, cwd, env):
        assert '--no-show-release-notes' in argv
        assert env['LITELLM_LOCAL_MODEL_COST_MAP'] == 'True'
        metadata = Path(argv[argv.index('--model-metadata-file') + 1])
        data = json.loads(metadata.read_text())
        assert data['ollama_chat/kraken']['input_cost_per_token'] == 0
        metadata_paths.append(metadata)
        return {'exit_code':0,'output':'Development process adapter only'}
    async def scenario():
        with patch.dict('os.environ',{'KRAKEN_INFERENCE_PROXY':'1'}), \
             patch('backend.tools.shutil.which',return_value='/usr/bin/true'), \
             patch.object(app.state.tools,'sandbox',return_value=[]), \
             patch.object(app.state.control,'run',new=run):
            await app.state.tools.execute('code.aider',{'instruction':'Inspect this test project'},'test')
    asyncio.run(scenario())
    assert metadata_paths and all(not path.exists() for path in metadata_paths)
