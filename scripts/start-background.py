"""Launch KRAKEN independently of the calling terminal and retain all startup output."""
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parent.parent


def ready(opener):
    try:
        with opener.open('http://127.0.0.1:8765/api/health', timeout=1) as response:
            if response.status != 200 or json.load(response).get('service') != 'kraken-ai':
                return False
        with opener.open('http://127.0.0.1:8765/', timeout=1) as response:
            return response.status == 200
    except (OSError, URLError, ValueError):
        return False


def owns_listeners(pid):
    result = subprocess.run(['lsof', '-nP', '-a', '-p', str(pid), '-iTCP', '-sTCP:LISTEN', '-Fn'],
                            capture_output=True, text=True, timeout=3)
    names = {line[1:] for line in result.stdout.splitlines() if line.startswith('n')}
    return {'127.0.0.1:8765', '127.0.0.1:8766'} <= names


def main():
    logs = ROOT / 'logs'
    logs.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    log_path = logs / ('startup-' + stamp + '.log')
    env = dict(os.environ, PYTHONUNBUFFERED='1')
    # start.sh still reserves both ports before importing the backend. Never stop
    # or replace an existing listener to make room for this launch.
    with log_path.open('ab', buffering=0) as output:
        proc = subprocess.Popen([str(ROOT / 'scripts/start.sh')], cwd=ROOT, env=env,
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True)
    print('KRAKEN process: %s\nComplete startup log: %s' % (proc.pid, log_path), flush=True)
    opener = build_opener(ProxyHandler({}))
    for _ in range(180):
        if proc.poll() is not None:
            print(log_path.read_text(errors='replace'), file=sys.stderr)
            print('This launch exited (%s). No existing process was stopped.' % proc.returncode, file=sys.stderr)
            return 1
        if ready(opener) and owns_listeners(proc.pid):
            # A healthy older instance must never be mistaken for this launch.
            if proc.poll() is not None:
                continue
            (logs / 'server.pid').write_text(str(proc.pid) + '\n')
            (logs / 'server-log.txt').write_text(str(log_path) + '\n')
            print('Dashboard verified: HTTP 200 at http://127.0.0.1:8765/\nServer remains running in the background.', flush=True)
            return 0
        time.sleep(.5)
    print('Startup is still pending; process %s was left running. Inspect %s.' % (proc.pid, log_path), file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
