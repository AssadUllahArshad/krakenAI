"""Live macOS security workers and dashboard QA against disposable OWNED fixtures.
Production passwords/settings/projects are never modified. No public scanning.
"""
import http.server
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))


def serve():
    import uvicorn
    from backend.app import create_app
    uvicorn.run(create_app(Path(sys.argv[2])),host='127.0.0.1',port=int(sys.argv[3]),access_log=False)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


def main():
    import httpx
    from playwright.sync_api import sync_playwright
    slow_started = threading.Event()
    class Fixture(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=='/slow':
                slow_started.set()
                time.sleep(8)
            self.send_response(200)
            self.send_header('Content-Type','text/plain')
            self.send_header('Set-Cookie','session=qa-cookie-token-not-retained; Path=/')
            self.end_headers()
            try:self.wfile.write(b'Owned security QA fixture')
            except (BrokenPipeError,ConnectionResetError):pass
        def log_message(self,*args):pass
    target=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fixture)
    threading.Thread(target=target.serve_forever,daemon=True).start()
    port=free_port()
    base='http://127.0.0.1:'+str(port)
    report={'checks':{},'public_targets_tested':False}
    with tempfile.TemporaryDirectory(prefix='kraken-cyber-qa-',dir='/private/tmp') as directory:
        root=Path(directory)
        for folder in ('memory','workspace','projects/qa','frontend'):
            (root/folder).mkdir(parents=True,exist_ok=True)
        (root/'frontend/dist').symlink_to(ROOT/'frontend/dist',target_is_directory=True)
        sample=root/'projects/qa/sample.py'
        sample.write_text("password = 'qa-sensitive-value-never-retained'\neval(input())\n")
        (root/'projects/qa/requirements.txt').write_text('requests>=2\n')
        shutil.copyfile('/usr/bin/true',root/'projects/qa/owned-test-binary')
        password=secrets.token_urlsafe(24)
        with (ROOT/'logs/cyber-qa-server.log').open('w') as log:
            proc=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'serve',directory,str(port)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env=dict(os.environ,KRAKEN_INFERENCE_PROXY='0'))
        try:
            with httpx.Client(base_url=base,timeout=10,trust_env=False,headers={'X-Kraken-Client':'local'}) as client:
                for _ in range(100):
                    try:
                        if client.get('/api/health').status_code==200:break
                    except httpx.HTTPError:pass
                    if proc.poll() is not None:raise RuntimeError('QA server exited; inspect logs/cyber-qa-server.log')
                    time.sleep(.1)
                else:raise RuntimeError('QA startup timed out')
                def api(path,method='GET',body=None):
                    r=client.request(method,'/api'+path,**({'json':body} if body is not None else {}))
                    r.raise_for_status()
                    return r.json()
                api('/auth/session','POST',{})
                assert not any(m['enabled'] for m in api('/cyber/status')['modules'].values())
                denied=client.patch('/api/cyber/modules/network',json={'enabled':True})
                assert denied.status_code==403
                api('/auth/password','POST',{'password':password})
                api('/auth/session','POST',{'password':password})
                for cap in ('agent','security','computer','internet'):
                    api('/permissions/'+cap,'PATCH',{'enabled':True})
                def scope(kind,target_value,ports=None):
                    return api('/cyber/scopes','POST',{'label':'Owned '+kind+' fixture','kind':kind,'target':target_value,'ports':ports or [],'authorization':'I own this disposable localhost QA fixture.'})['id']
                def wait_task(identifier):
                    for _ in range(300):
                        t=next(t for t in api('/tasks') if t['id']==identifier)
                        if t['state'] not in ('running','queued'):
                            assert t['state']=='completed',t
                            rows=api('/cyber/reports')
                            return next(r for r in rows if r['id']==identifier)
                        time.sleep(.2)
                    raise RuntimeError('Assessment timeout '+identifier)
                with sync_playwright() as pw:
                    browser=pw.chromium.launch(headless=True)
                    page=browser.new_page(viewport={'width':1440,'height':1100})
                    errors=[]
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(base,wait_until='networkidle')
                    page.get_by_placeholder('Owner password').fill(password)
                    page.get_by_role('button',name='Unlock command center',exact=True).click()
                    page.get_by_role('button',name='Cybersecurity',exact=True).click()
                    page.get_by_role('heading',name='Security modules',exact=True).wait_for()
                    modules=api('/cyber/status')['modules']
                    for key,m in modules.items():
                        switch=page.get_by_role('switch',name=m['title'],exact=True)
                        assert switch.get_attribute('aria-checked')=='false'
                        switch.click()
                        for _ in range(100):
                            if api('/cyber/status')['modules'][key]['enabled']:break
                            time.sleep(.05)
                        assert api('/cyber/status')['modules'][key]['enabled']
                        page.wait_for_function('(title)=>!document.querySelector(\'[role="switch"][aria-label="\'+title+\'"]\').disabled',arg=m['title'])
                    # Exercise scope creation and first assessment through the actual UI.
                    page.get_by_label('SCOPE LABEL',exact=True).fill('Owned Python fixture')
                    page.get_by_label('EXPLICIT TARGET',exact=True).fill('projects/qa/sample.py')
                    page.get_by_label('OWNERSHIP / WRITTEN AUTHORIZATION',exact=True).fill('I own this disposable Python test fixture.')
                    page.get_by_role('button',name='Save authorized scope',exact=True).click()
                    page.get_by_text('Owned Python fixture',exact=True).first.wait_for()
                    page.get_by_role('button',name='Run assessment',exact=True).click()
                    for _ in range(300):
                        rows=api('/cyber/reports')
                        if rows:break
                        failures=[t for t in api('/tasks') if t['state']=='failed']
                        if failures:raise AssertionError(failures)
                        time.sleep(.2)
                    assert rows and rows[0]['module']=='code_review'
                    assert any(f['rule']=='B307' for f in rows[0]['findings'])
                    report['checks']['code_review']={'findings':len(rows[0]['findings']),'verified':True}
                    def run(module,sid):
                        r=wait_task(api('/cyber/run','POST',{'module':module,'scope_id':sid})['id'])
                        assert 'qa-sensitive-value-never-retained' not in json.dumps(r)
                        assert 'qa-cookie-token-not-retained' not in json.dumps(r)
                        report['checks'][module]={'findings':len(r['findings']),'verified':True}
                        print(module,'PASS',flush=True)
                        return r
                    code_scope=scope('local','projects/qa/sample.py')
                    run('malware',code_scope)
                    reverse=run('reverse_engineering',scope('local','projects/qa/owned-test-binary'))
                    assert 'macho_header' in reverse['evidence']['files'][0]
                    run('vulnerability',scope('local','projects/qa/requirements.txt'))
                    network=run('network',scope('network','127.0.0.1',[target.server_port]))
                    assert network['evidence']['connections'][0]['state']=='open'
                    url='http://127.0.0.1:'+str(target.server_port)+'/'
                    web_scope=scope('web',url)
                    run('web',web_scope)
                    authentication=run('authentication',web_scope)
                    assert any(f['rule']=='cookie-httponly' for f in authentication['findings'])
                    exported=client.get('/api/cyber/reports/'+authentication['id']+'/export')
                    assert exported.status_code==200 and exported.json()['evidence_sha256']
                    assert 'attachment' in exported.headers['content-disposition']
                    page.reload(wait_until='networkidle')
                    page.get_by_role('button',name='Cybersecurity',exact=True).click()
                    page.get_by_role('heading',name='Security reports',exact=True).wait_for()
                    page.wait_for_timeout(2500)
                    page.screenshot(path=str(ROOT/'logs/cyber-center-desktop.png'),full_page=True)
                    slow_scope=scope('web',url+'slow')
                    identifier=api('/cyber/run','POST',{'module':'web','scope_id':slow_scope})['id']
                    assert slow_started.wait(5),'Worker did not reach owned HTTP fixture'
                    jobs=api('/cyber/status')['active_jobs']
                    pid=next(j['pid'] for j in jobs if j['id']==identifier)
                    assert pid
                    started=time.monotonic()
                    page.get_by_role('button',name='EMERGENCY STOP').click()
                    page.get_by_text('EMERGENCY STOPPED',exact=True).wait_for()
                    for _ in range(100):
                        try:os.kill(pid,0)
                        except ProcessLookupError:break
                        time.sleep(.03)
                    else:raise AssertionError('Managed security process survived emergency stop')
                    report['emergency_process_termination_seconds']=round(time.monotonic()-started,2)
                    assert not any(m['enabled'] for m in api('/cyber/status')['modules'].values())
                    assert client.post('/api/cyber/run',json={'module':'web','scope_id':web_scope}).status_code==423
                    page.get_by_role('button',name='Manually reset').click()
                    page.get_by_role('button',name='Enable AI agent',exact=True).wait_for()
                    page.set_viewport_size({'width':390,'height':844})
                    page.screenshot(path=str(ROOT/'logs/cyber-center-mobile.png'),full_page=True)
                    assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
                    assert not errors,errors
                    report.update(browser_errors=errors,mobile_overflow=False,report_export=True,passed=True)
                    browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
            target.shutdown()
            target.server_close()
            (ROOT/'logs/cyber-validation.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='serve':serve()
    else:main()
