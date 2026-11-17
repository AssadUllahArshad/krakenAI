"""Live sandbox boundary checks against temporary files only."""
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from backend.app import app

async def main():
    root = Path(__file__).resolve().parent.parent
    project = root / 'projects/test-app'
    app.state.control.flags.update(agent=True, computer=True, coding=True)
    code = '''import socket
from pathlib import Path
checks = {}
try:
    Path('/Users/ali/KrakenAI/memory/kraken.sqlite3').read_bytes()
    checks['private_read'] = 'FAILED'
except PermissionError:
    checks['private_read'] = 'blocked'
try:
    socket.create_connection(('127.0.0.1',11434), timeout=2)
    checks['network'] = 'FAILED'
except OSError:
    checks['network'] = 'blocked'
print(checks)
assert checks == {'private_read':'blocked','network':'blocked'}
'''
    script = project / 'kraken_isolation_check.py'
    script.write_text(code)
    try:
        result = await app.state.tools.execute('code.run', {'project': 'projects/test-app', 'path': str(script.relative_to(root))}, 'isolation')
        print(json.dumps(result))
        assert result['exit_code'] == 0
        # Check the installed Aider accepts our CLI options inside the same sandbox.
        tools = app.state.tools
        env = {'PATH': os.environ['PATH'], 'HOME': '/private/tmp/kraken-exec', 'TMPDIR': '/private/tmp/kraken-exec', 'PYTHONDONTWRITEBYTECODE': '1'}
        Path('/private/tmp/kraken-exec').mkdir(exist_ok=True)
        argv = tools.sandbox(project, network=True) + ['aider', '--no-auto-commits', '--no-auto-test', '--no-auto-lint', '--no-detect-urls', '--no-check-update', '--no-show-release-notes', '--no-analytics', '--no-show-model-warnings', '--subtree-only', '--no-gitignore', '--help']
        result = await app.state.control.run('aider-cli', argv, project, env)
        print('Sandboxed Aider CLI:', result['exit_code'], result['output'][:150])
        assert result['exit_code'] == 0
    finally:
        script.unlink(missing_ok=True)

asyncio.run(main())
