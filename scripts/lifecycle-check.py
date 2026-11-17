"""Start and gracefully stop the real server, verifying both owned listeners close."""
import os
import socket
import signal
import subprocess
import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parent.parent
proc = subprocess.Popen([str(root / 'scripts/start.sh')], cwd=root)
try:
    for _ in range(100):
        if proc.poll() is not None:
            raise RuntimeError('Server stopped during startup')
        try:
            with socket.create_connection(('127.0.0.1', 8765), timeout=.2):
                break
        except OSError:
            time.sleep(.1)
    else:
        raise RuntimeError('Server did not start')
    with socket.create_connection(('127.0.0.1', 8766), timeout=2):
        pass
    duplicate = subprocess.run([str(root / 'scripts/start.sh')], cwd=root, capture_output=True, text=True, timeout=15)
    assert duplicate.returncode != 0
    assert 'already running' in duplicate.stderr
    assert 'Traceback' not in duplicate.stderr
    assert proc.poll() is None
    print('Duplicate launch rejected cleanly without stopping the running server: PASS')
    proc.terminate()
    result = proc.wait(timeout=15)
    # Uvicorn re-raises the received signal after graceful lifespan teardown.
    assert result in (0, -signal.SIGTERM), result
    for port in (8765, 8766):
        try:
            connection = socket.create_connection(('127.0.0.1', port), timeout=.2)
        except OSError:
            continue
        connection.close()
        raise AssertionError('Owned listener remains: ' + str(port))
    print('Real startup and graceful shutdown of both listeners: PASS')
    # A busy gateway must not leave a partially started dashboard behind.
    with socket.socket() as occupied:
        occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupied.bind(('127.0.0.1',8766))
        occupied.listen()
        blocked = subprocess.run([str(root / 'scripts/start.sh')], cwd=root, capture_output=True, text=True, timeout=15)
        assert blocked.returncode != 0 and '8766' in blocked.stderr
        assert 'Traceback' not in blocked.stderr
        try:
            connection = socket.create_connection(('127.0.0.1',8765),timeout=.2)
        except OSError:
            pass
        else:
            connection.close()
            raise AssertionError('Partial dashboard listener remains')
    print('Occupied gateway fails before application startup; dashboard port released: PASS')
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
