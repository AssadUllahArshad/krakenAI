import asyncio
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.cyber import MODULES, ScopeInput


@pytest.fixture
def app(tmp_path):
    for folder in ('memory','workspace','projects/test-app'):
        (tmp_path / folder).mkdir(parents=True,exist_ok=True)
    application = create_app(tmp_path)
    yield application
    application.state.store.db.close()


def owner(app):
    c = TestClient(app,headers={'X-Kraken-Client':'local'})
    c.post('/api/auth/session',json={}).raise_for_status()
    c.post('/api/auth/password',json={'password':'test-owner-password'}).raise_for_status()
    c.post('/api/auth/session',json={'password':'test-owner-password'}).raise_for_status()
    for capability in ('agent','computer','security','internet'):
        c.patch('/api/permissions/'+capability,json={'enabled':True}).raise_for_status()
    return c


def local_scope(c, target='projects/test-app'):
    r=c.post('/api/cyber/scopes',json={'label':'Owned test fixture','kind':'local','target':target,'authorization':'I own this local test fixture.'})
    r.raise_for_status()
    return r.json()['id']


def test_modules_default_off_and_passwordless_owner_cannot_enable(app):
    c=TestClient(app,headers={'X-Kraken-Client':'local'})
    c.post('/api/auth/session',json={})
    assert all(not m['enabled'] for m in c.get('/api/cyber/status').json()['modules'].values())
    for module in MODULES:
        assert c.patch('/api/cyber/modules/'+module,json={'enabled':True}).status_code==403
    assert c.post('/api/cyber/scopes',json={'label':'Invalid','kind':'network','target':'127.0.0.1','ports':[80],'authorization':'I own this fixture.'}).status_code==403


@pytest.mark.parametrize('module',MODULES)
def test_every_disabled_module_denies_execution(app,module):
    c=owner(app)
    scope=local_scope(c)
    r=c.post('/api/cyber/run',json={'module':module,'scope_id':scope})
    assert r.status_code==403
    assert 'disabled' in r.json()['detail']
    assert app.state.control.processes=={}


@pytest.mark.parametrize('capability',['agent','security','computer','internet'])
def test_master_capabilities_cannot_be_bypassed(app,capability):
    c=owner(app)
    c.patch('/api/cyber/modules/network',json={'enabled':True})
    scope=c.post('/api/cyber/scopes',json={'label':'Owned fixture','kind':'network','target':'127.0.0.1','ports':[8080],'authorization':'I own this local fixture.'}).json()['id']
    c.patch('/api/permissions/'+capability,json={'enabled':False})
    assert c.post('/api/cyber/run',json={'module':'network','scope_id':scope}).status_code==403


def test_missing_expired_wrong_and_revoked_scope(app):
    c=owner(app)
    c.patch('/api/cyber/modules/network',json={'enabled':True})
    assert c.post('/api/cyber/run',json={'module':'network','scope_id':'none'}).status_code==403
    sid=local_scope(c)
    assert c.post('/api/cyber/run',json={'module':'network','scope_id':sid}).status_code==400
    scope=app.state.cyber.scope(sid)
    scope['expires']=0
    app.state.store.execute('UPDATE cyber_scopes SET data=? WHERE id=?',(json.dumps(scope),sid))
    assert c.post('/api/cyber/run',json={'module':'network','scope_id':sid}).status_code==403
    c.delete('/api/cyber/scopes/'+sid)
    assert c.post('/api/cyber/run',json={'module':'network','scope_id':sid}).status_code==403


@pytest.mark.parametrize('target,ports', [('169.254.169.254',[80]),('0.0.0.0',[80]),('224.0.0.1',[80]),('127.0.0.1',[8765]),('127.0.0.1',[8766]),('127.0.0.1',[11434]),('10.0.0.0/8',[80]),('example.com',[80]),('127.0.0.1',[True]),('127.0.0.1',list(range(1,10)))])
def test_invalid_target_scopes_rejected(app,target,ports):
    c=owner(app)
    r=c.post('/api/cyber/scopes',json={'label':'Invalid scope','kind':'network','target':target,'ports':ports,'authorization':'I own a test fixture.'})
    assert r.status_code in (400,403)


def test_scope_path_escape_and_snapshot_symlinks(app,tmp_path):
    c=owner(app)
    assert c.post('/api/cyber/scopes',json={'label':'Invalid','kind':'local','target':'/etc','authorization':'I own a test fixture.'}).status_code==403
    project=tmp_path/'projects/test-app'
    (project/'a.py').write_text('print(1)')
    (project/'leak').symlink_to('/etc/passwd')
    sid=local_scope(c)
    destination=tmp_path/'snapshot'
    destination.mkdir()
    manifest=app.state.cyber.snapshot(app.state.cyber.scope(sid),destination)
    assert len(manifest)==1
    assert manifest[0]['sha256']==hashlib.sha256(b'print(1)').hexdigest()
    with pytest.raises(HTTPException):
        app.state.tools.path('memory/cyber-inputs/sample.py')


def test_generic_tools_cannot_call_cyber_or_legacy_disabled_review(app):
    c=owner(app)
    assert c.post('/api/tools',json={'tool':'cyber.network','args':{}}).status_code==404
    with pytest.raises(HTTPException):
        asyncio.run(app.state.tools.execute('security.audit',{'path':'projects/test-app/a.py'},'audit'))
    profile=app.state.tools.sandbox(app.state.tools.root/'projects/test-app')
    assert 'network-outbound' not in profile[-1]
    aider_profile=app.state.tools.sandbox(app.state.tools.root/'projects/test-app',network=True)[-1]
    assert 'localhost:8766' in aider_profile
    assert '*:' not in aider_profile


@pytest.mark.parametrize('action',['emergency','module','scope','logout'])
def test_running_security_process_stops_on_revocation(app,tmp_path,action):
    # A real child process tests ownership/cancellation; the fixed analyzer argv
    # is substituted with a sleeper only inside this test.
    async def scenario():
        real_client=httpx.AsyncClient
        transport=httpx.ASGITransport(app=app)
        async with real_client(transport=transport,base_url='http://testserver',headers={'X-Kraken-Client':'local'}) as c:
            await c.post('/api/auth/session',json={})
            await c.post('/api/auth/password',json={'password':'test-owner-password'})
            await c.post('/api/auth/session',json={'password':'test-owner-password'})
            for cap in ('agent','computer','security'):
                await c.patch('/api/permissions/'+cap,json={'enabled':True})
            (tmp_path/'projects/test-app/sample.py').write_text('print(1)')
            sid=(await c.post('/api/cyber/scopes',json={'label':'Owned','kind':'local','target':'projects/test-app/sample.py','authorization':'I own this test fixture.'})).json()['id']
            await c.patch('/api/cyber/modules/malware',json={'enabled':True})
            real_run=app.state.control.run
            async def sleeper(identifier,argv,cwd,env,**kwargs):
                return await real_run(identifier,[sys.executable,'-c','import time; time.sleep(120)'],cwd,env,**kwargs)
            with patch.object(app.state.control,'run',new=sleeper):
                r=await c.post('/api/cyber/run',json={'module':'malware','scope_id':sid})
                assert r.status_code==200,r.text
                identifier=r.json()['id']
                for _ in range(100):
                    if identifier in app.state.control.processes: break
                    await asyncio.sleep(.02)
                assert identifier in app.state.control.processes
                proc=app.state.control.processes[identifier]
                task=app.state.control.tasks[identifier]
                if action=='emergency':
                    assert (await c.post('/api/emergency-stop',json={})).status_code==200
                elif action=='module':
                    assert (await c.patch('/api/cyber/modules/malware',json={'enabled':False})).status_code==200
                elif action=='scope':
                    assert (await c.delete('/api/cyber/scopes/'+sid)).status_code==200
                else:
                    assert (await c.delete('/api/auth/session')).status_code==200
                await asyncio.wait_for(asyncio.gather(task,return_exceptions=True),3)
                assert proc.returncode is not None
                row=app.state.store.rows('SELECT state FROM tasks WHERE id=?',(identifier,))[0]
                assert row['state'] in ('cancelled','failed')
                if action=='emergency':
                    assert not any(app.state.cyber.flags().values())
                    assert (await c.post('/api/cyber/run',json={'module':'malware','scope_id':sid})).status_code==423
    asyncio.run(scenario())


def test_worker_static_malware_never_executes_sample(tmp_path):
    from backend import security_worker
    sample=tmp_path/'danger.py'
    marker=tmp_path/'executed'
    sample.write_text("import os\nos.system('touch "+str(marker)+"')")
    spec={'input':str(tmp_path)}
    findings,evidence=security_worker.inspect_local(spec,'malware')
    assert findings and not marker.exists()
    assert evidence['files'][0]['sample_executed'] is False


def test_worker_bandit_classifies_without_storing_source(tmp_path):
    from backend import security_worker
    (tmp_path/'example.py').write_text("password = 'do-not-store-this-secret'\neval(input())\n")
    findings,evidence=security_worker.inspect_local({'input':str(tmp_path)},'code_review')
    assert any(f['rule']=='B307' for f in findings)
    assert all(f['severity'] in ('high','medium','low') for f in findings)
    assert 'do-not-store-this-secret' not in json.dumps(findings)+json.dumps(evidence)


def test_password_session_survives_browser_reload_status(app):
    c=owner(app)
    assert c.get('/api/auth/status').json()=={'password_required':True,'authenticated':True}
    with patch('backend.app.time.time',return_value=time.time()+3601):
        assert c.get('/api/auth/status').json()['authenticated'] is False
    c.delete('/api/auth/session')
    assert c.get('/api/auth/status').json()['authenticated'] is False


def test_cancel_during_spawn_does_not_orphan_child(app,tmp_path):
    async def scenario():
        control=app.state.control
        control.flags.update(computer=True,coding=True)
        created=[]
        started=asyncio.Event()
        real_spawn=asyncio.create_subprocess_exec
        async def delayed(*argv,**kwargs):
            started.set()
            await asyncio.sleep(.1)
            proc=await real_spawn(*argv,**kwargs)
            created.append(proc)
            return proc
        with patch('backend.control.asyncio.create_subprocess_exec',new=delayed):
            task=asyncio.create_task(control.run('spawn-race',[sys.executable,'-c','import time; time.sleep(120)'],tmp_path))
            await started.wait()
            task.cancel()
            await asyncio.wait_for(asyncio.gather(task,return_exceptions=True),3)
        assert created and created[0].returncode is not None
        assert control.processes=={}
    asyncio.run(scenario())


def test_cancelled_process_leaves_no_unretrieved_async_exception(app,tmp_path):
    async def scenario():
        import gc
        control=app.state.control
        control.flags.update(computer=True,coding=True)
        errors=[]
        loop=asyncio.get_running_loop()
        loop.set_exception_handler(lambda loop,context:errors.append(context))
        task=asyncio.create_task(control.run('cancel',[sys.executable,'-c','import time; time.sleep(120)'],tmp_path))
        for _ in range(100):
            if control.processes:break
            await asyncio.sleep(.01)
        assert control.processes
        task.cancel()
        await asyncio.gather(task,return_exceptions=True)
        gc.collect()
        await asyncio.sleep(.05)
        assert not errors
    asyncio.run(scenario())
