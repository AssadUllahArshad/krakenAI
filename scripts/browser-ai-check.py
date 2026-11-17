"""Real browser chat, permission controls and inference-independent stop validation."""
import json
import time
import uuid
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
name = 'browser-validation-' + uuid.uuid4().hex[:8]
report = {'conversation': name}
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1440, 'height': 1100})
    page.set_default_timeout(15000)
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto('http://127.0.0.1:8765/?conversation=' + name, wait_until='networkidle')
    page.get_by_role('heading', name='Command center', exact=True).wait_for()
    def api(path, method='GET', body=None):
        response = page.request.fetch('http://127.0.0.1:8765/api' + path, method=method,
            headers={'X-Kraken-Client': 'local'}, **({'data': body} if body is not None else {}))
        assert response.ok, response.text()
        return response.json()
    initial = api('/status')
    assert not initial['running'] and not initial['stopped'], 'Do not disturb active work or a latched emergency stop'
    try:
        if initial['permissions']['agent']:
            page.get_by_role('switch', name='AI agent', exact=True).click()
        page.get_by_role('button', name='Enable AI agent', exact=True).click()
        assert api('/status')['permissions']['agent'] is True
        # Verify each available switch changes the corresponding backend permission.
        for key, label in [('internet','Internet'),('computer','Computer control'),('coding','Coding engine'),('security','Security research'),('automation','Automation')]:
            switch = page.get_by_role('switch', name=label, exact=True)
            old = api('/status')['permissions'][key]
            switch.click()
            page.wait_for_function("([label,value])=>document.querySelector('[aria-label=\"'+label+'\"][role=switch]').getAttribute('aria-checked')===String(value)", arg=[label,not old])
            assert api('/status')['permissions'][key] is (not old)
            switch.click()
            page.wait_for_function("([label,value])=>document.querySelector('[aria-label=\"'+label+'\"][role=switch]').getAttribute('aria-checked')===String(value)", arg=[label,old])
            assert api('/status')['permissions'][key] is old
        assert page.get_by_role('switch', name='Face recognition', exact=True).is_disabled()
        report['switches'] = 'All six available switches verified; face remains unavailable'
        page.screenshot(path=str(ROOT / 'logs/dashboard-desktop.png'), full_page=True)
        page.get_by_role('button', name='AI workspace', exact=True).click()
        message = page.get_by_role('textbox', name='Message to KRAKEN')
        message.fill('Reply with exactly: Dashboard connection verified. Do not use any tools.')
        started = time.monotonic()
        with page.expect_response(lambda r:r.url.endswith('/api/chat') and r.request.method=='POST', timeout=180000) as pending:
            page.get_by_role('button', name='Send', exact=True).click()
        result = pending.value
        assert result.status == 200, result.text()
        reply = result.json()
        assert 'Dashboard connection verified' in reply['content'], reply
        page.locator('.message.assistant').filter(has_text='Dashboard connection verified').wait_for()
        report['chat'] = reply
        report['browser_roundtrip_seconds'] = round(time.monotonic()-started,2)
        page.screenshot(path=str(ROOT / 'logs/dashboard-chat.png'), full_page=True)
        page.reload(wait_until='networkidle')
        page.get_by_role('button', name='AI workspace', exact=True).click()
        page.locator('.message.assistant').filter(has_text='Dashboard connection verified').wait_for()
        report['reload_persistence'] = True
        # Stop only the reply; agent stays enabled.
        message = page.get_by_role('textbox', name='Message to KRAKEN')
        message.fill('Write a detailed 1000-word essay on local software development. Do not use tools.')
        page.get_by_role('button', name='Send', exact=True).click()
        page.get_by_role('button', name='Stop reply', exact=True).wait_for()
        for _ in range(30):
            if name in api('/status')['active_conversations']:
                break
            page.wait_for_timeout(100)
        else:
            raise AssertionError('No active chat found before cancellation')
        page.get_by_role('button', name='Stop reply', exact=True).click()
        page.get_by_role('button', name='Send', exact=True).wait_for()
        assert api('/status')['permissions']['agent']
        assert name not in api('/status')['active_conversations']
        report['stop_reply'] = True
        # Emergency stop while a real inference request is pending.
        message.fill('Write a detailed 1000-word essay about databases. Do not use tools.')
        page.get_by_role('button', name='Send', exact=True).click()
        for _ in range(30):
            if name in api('/status')['active_conversations']:
                break
            page.wait_for_timeout(100)
        else:
            raise AssertionError('No active chat found before emergency stop')
        started = time.monotonic()
        page.get_by_role('button', name='EMERGENCY STOP').click()
        page.get_by_text('EMERGENCY STOPPED', exact=True).wait_for()
        report['emergency_response_seconds'] = round(time.monotonic()-started,2)
        stopped = api('/status')
        assert stopped['stopped'] and not any(stopped['permissions'].values())
        denied = page.request.post('http://127.0.0.1:8765/api/tools', headers={'X-Kraken-Client':'local'}, data={'tool':'files.list'})
        assert denied.status == 423
        report['emergency_during_inference'] = True
        page.get_by_role('button', name='Manually reset').click()
        page.get_by_role('button', name='Enable AI agent', exact=True).wait_for()
        assert not any(api('/status')['permissions'].values())
        # Simulate a failed status request to exercise offline/reconnect UI.
        page.route('**/api/status', lambda route:route.abort())
        page.get_by_text('Backend disconnected', exact=True).wait_for(timeout=10000)
        page.unroute('**/api/status')
        page.get_by_role('button', name='Reconnect', exact=True).click()
        page.get_by_text('Backend disconnected', exact=True).wait_for(state='hidden')
        report['simulated_disconnect_recovery'] = True
        page.get_by_role('button', name='Command center', exact=True).click()
        page.set_viewport_size({'width':390,'height':844})
        page.screenshot(path=str(ROOT / 'logs/dashboard-mobile.png'), full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        assert not errors, errors
        report['javascript_errors'] = errors
        report['passed'] = True
        print(json.dumps(report, indent=2), flush=True)
    finally:
        if api('/status')['stopped']:
            api('/reset','POST',{})
        for key, enabled in initial['permissions'].items():
            if not enabled:
                api('/permissions/' + key, 'PATCH', {'enabled':False})
        for key, enabled in initial['permissions'].items():
            if enabled:
                api('/permissions/' + key, 'PATCH', {'enabled':True})
        (ROOT / 'logs/browser-ai-validation.json').write_text(json.dumps(report,indent=2))
        browser.close()
