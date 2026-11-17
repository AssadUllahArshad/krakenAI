import asyncio
import os
import signal
import time
import contextlib

from fastapi import HTTPException

CAPABILITIES = ['agent', 'internet', 'computer', 'coding', 'security', 'automation', 'face']


class Control:
    def __init__(self, store):
        self.store = store
        self.flags = store.get('permissions', {k: k == 'agent' for k in CAPABILITIES})
        self.stopped = store.get('stopped', False)
        self.tasks = {}
        self.processes = {}
        self.killed_groups = set()
        self._lock = None

    @property
    def lock(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def check(self, *capabilities):
        if self.stopped:
            raise HTTPException(423, 'Emergency stop is latched. Manually reset before enabling tools.')
        for cap in ('agent',) + capabilities:
            if not self.flags.get(cap, False):
                raise HTTPException(403, '%s is disabled' % cap)

    def save(self):
        self.store.set('permissions', self.flags)
        self.store.set('stopped', self.stopped)

    def kill_group(self, proc):
        if proc.pid in self.killed_groups:
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:
            # A restricted host may reject signalling an already reaped child.
            # Never suppress a permission failure for a still-running process.
            if proc.returncode is None:
                raise
        else:
            self.killed_groups.add(proc.pid)

    async def revoke(self, reason, stop=False, capability=None):
        # The same lock protects process/task registration and permission revocation.
        async with self.lock:
            if stop:
                self.stopped = True
            if capability:
                self.flags[capability] = False
            else:
                self.flags = {k: False for k in CAPABILITIES}
            self.save()
            if stop or capability is None or capability == 'security':
                self.store.set('cyber_modules', {})
            for task in list(self.tasks.values()):
                task.cancel()
            for proc in list(self.processes.values()):
                self.kill_group(proc)
            self.store.execute("UPDATE tasks SET state='cancelled',result=? WHERE state IN ('queued','running')", (reason,))
            self.store.event(reason, 'critical' if stop else 'warning')

    async def run(self, identifier, argv, cwd, env=None, capabilities=('coding', 'computer'), guard=None, timeout=180):
        async with self.lock:
            self.check(*capabilities)
            if guard:
                guard()
            spawn = asyncio.create_task(asyncio.create_subprocess_exec(*argv, cwd=str(cwd), env=env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, start_new_session=True))
            try:
                proc = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                # Cancellation during spawn must not orphan an unregistered child.
                proc = await spawn
                self.kill_group(proc)
                await proc.wait()
                self.killed_groups.discard(proc.pid)
                raise
            self.processes[identifier] = proc
        output = bytearray()
        collector = watcher = None
        try:
            async def collect():
                while True:
                    chunk = await proc.stdout.read(8192)
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > 1024 * 1024:
                        raise HTTPException(413, 'Process output exceeded 1 MB')
                await proc.wait()
            async def watch():
                while proc.returncode is None:
                    self.check(*capabilities)
                    if guard:
                        guard()
                    await asyncio.sleep(.2)
            collector = asyncio.create_task(collect())
            watcher = asyncio.create_task(watch())
            deadline = time.monotonic() + timeout
            done, pending = await asyncio.wait((collector, watcher), timeout=timeout,
                                               return_when=asyncio.FIRST_COMPLETED)
            if not done:
                raise asyncio.TimeoutError('Managed process exceeded its time limit')
            for task in done:
                task.result()
            if not collector.done():
                await asyncio.wait_for(collector, max(.01, deadline - time.monotonic()))
            return {'exit_code': proc.returncode, 'output': output.decode(errors='replace')}
        finally:
            self.kill_group(proc)
            await proc.wait()
            for task in (collector, watcher):
                if task and not task.done():
                    task.cancel()
            for task in (collector, watcher):
                if task:
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            self.processes.pop(identifier, None)
            self.killed_groups.discard(proc.pid)
