from pathlib import Path
from playwright.sync_api import sync_playwright

root = Path(__file__).resolve().parent.parent
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1440, 'height': 1100}, device_scale_factor=1)
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto('http://127.0.0.1:8765', wait_until='networkidle')
    page.get_by_role('heading', name='Command center', exact=True).wait_for()
    page.get_by_role('switch', name='AI agent', exact=True).click()
    page.wait_for_timeout(300)
    assert page.get_by_role('switch', name='AI agent', exact=True).get_attribute('aria-checked') == 'true'
    page.get_by_role('button', name='EMERGENCY STOP').click()
    page.get_by_text('EMERGENCY STOPPED', exact=True).wait_for()
    assert page.get_by_role('switch', name='AI agent', exact=True).is_disabled()
    page.get_by_role('button', name='Manually reset').click()
    page.get_by_role('switch', name='AI agent', exact=True).wait_for(state='visible')
    page.wait_for_timeout(300)
    assert page.get_by_role('switch', name='AI agent', exact=True).get_attribute('aria-checked') == 'false'
    page.screenshot(path=str(root / 'logs/dashboard-desktop.png'), full_page=True)
    page.get_by_role('button', name='Memory', exact=True).click()
    page.get_by_placeholder('Remember something useful…').fill('Browser QA temporary memory')
    page.get_by_role('button', name='Save memory', exact=True).click()
    page.get_by_text('Browser QA temporary memory', exact=True).wait_for()
    page.locator('article.memory').filter(has_text='Browser QA temporary memory').get_by_role('button', name='Delete memory', exact=True).click()
    page.get_by_text('No saved memories found.', exact=True).wait_for()
    page.get_by_role('button', name='Tools & projects', exact=True).click()
    page.get_by_role('heading', name='Tool runner', exact=True).wait_for()
    page.get_by_role('button', name='Command center', exact=True).click()
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path=str(root / 'logs/dashboard-mobile.png'), full_page=True)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert not errors, errors
    print('Browser QA: PASS — real toggle, emergency stop/reset, memory save/delete, navigation, mobile overflow, no JS errors')
    browser.close()
