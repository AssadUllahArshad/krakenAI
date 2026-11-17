"""Reserve both loopback listeners before importing application state."""
import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def reserve_listeners():
    sockets = []
    try:
        for port in (8765, 8766):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                listener.bind(('127.0.0.1', port))
            except OSError as exc:
                raise RuntimeError('Cannot start KRAKEN: local port %s is unavailable (%s). '
                                   'If KRAKEN is already running, open http://127.0.0.1:8765. '
                                   'Otherwise stop the process using that port and try again.' % (port, exc.strerror)) from exc
            listener.setblocking(False)
        return sockets
    except Exception:
        for listener in sockets:
            listener.close()
        raise


def main():
    try:
        listeners = reserve_listeners()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    try:
        import uvicorn
        from backend.app import app
        app.state.gateway_socket = listeners[1]
        config = uvicorn.Config(app, host='127.0.0.1', port=8765, access_log=False,
                                timeout_graceful_shutdown=5)
        print('KRAKEN dashboard: http://127.0.0.1:8765', flush=True)
        asyncio.run(uvicorn.Server(config).serve(sockets=[listeners[0]]))
        return 0
    finally:
        for listener in listeners:
            listener.close()


if __name__ == '__main__':
    sys.exit(main())
