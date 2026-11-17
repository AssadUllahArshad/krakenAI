"""Background launch must identify its own listeners and reject a failed child."""
import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('background_start', Path(__file__).parents[1] / 'scripts/start-background.py')
background = importlib.util.module_from_spec(spec)
spec.loader.exec_module(background)


def test_listener_ownership_requires_both_loopback_ports():
    with patch.object(background.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,'p42\nn127.0.0.1:8765\nn127.0.0.1:8766\n','')) as run:
        assert background.owns_listeners(42)
        assert run.call_args.args[0][4] == '42'
    with patch.object(background.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,'p42\nn127.0.0.1:8765\n','')):
        assert not background.owns_listeners(42)


def test_failed_launch_does_not_replace_existing_pid_or_terminate_processes(tmp_path):
    (tmp_path / 'logs').mkdir()
    pid_file = tmp_path / 'logs/server.pid'
    pid_file.write_text('existing-pid\n')
    proc = MagicMock(pid=999)
    proc.poll.return_value = 1
    with patch.object(background, 'ROOT', tmp_path), patch.object(background.subprocess, 'Popen', return_value=proc) as spawn:
        assert background.main() == 1
    assert pid_file.read_text() == 'existing-pid\n'
    assert spawn.call_args.kwargs['start_new_session'] is True
    assert spawn.call_args.kwargs['stdin'] == subprocess.DEVNULL
    proc.terminate.assert_not_called()
    proc.kill.assert_not_called()
