#!/usr/bin/env python3
"""Qualify a surviving terminal owner using only PTYs and processes created here."""
import os
from pathlib import Path
import select
import shlex
import signal
import sys
import tempfile
import termios

from check_linux_outer_terminal import OwnedPty


def child_handle(binary, data):
    fd = os.pidfd_open(data['child'])
    try:
        assert not select.select([fd], [], [], 0)[0]
        fields = Path(f"/proc/{data['child']}/stat").read_text().rsplit(') ', 1)[1].split()
        assert int(fields[1]) == int(fields[2]) == data['pid']
        assert os.path.samefile(f"/proc/{data['child']}/exe", binary)
        return fd
    except BaseException:
        os.close(fd)
        raise


def cleanup_child(fd):
    if fd is not None:
        if not select.select([fd], [], [], 0)[0]:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        os.close(fd)


def direct(binary, scenario):
    with tempfile.TemporaryDirectory(prefix='aswp-terminal-owner-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root)
        child = None
        try:
            data = owned.ready(greeting=b'OWNED-CHILD-READY\r\n')
            child = child_handle(binary, data)
            if scenario == 'normal':
                owned.send(b'exit\n')
                owned.finish()
                assert (root / 'owner-restored-exit').read_text() == 'Some(0):None'
            elif scenario == 'child-sigkill':
                signal.pidfd_send_signal(child, signal.SIGKILL)
                owned.finish(-signal.SIGKILL)
                assert (root / 'owner-restored-exit').read_text() == 'None:Some(9)'
            elif scenario == 'owner-sigterm':
                os.kill(owned.pid, signal.SIGTERM)
                owned.finish(-signal.SIGTERM)
                assert (root / 'owner-restored-exit').read_text() == 'None:Some(15)'
            elif scenario == 'external-stop-refusal':
                # This signal is explicitly outside the prototype's supported
                # stop protocol. The error path must retire the owned child
                # before its retained pidfd permits restoration.
                os.kill(owned.pid, signal.SIGTSTP)
                owned.finish(125)
                assert not (root / 'owner-restored-exit').exists()
            else:
                raise AssertionError('unknown terminal-owner scenario')
            assert select.select([child], [], [], 0)[0]
            assert termios.tcgetattr(owned.master) == owned.original
            print(f'terminal-owner-{scenario}: pass', flush=True)
        finally:
            cleanup_child(child)
            owned.close()


def shell_job(binary, forced, cancel=False):
    with tempfile.TemporaryDirectory(prefix='aswp-terminal-owner-shell-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True)
        child = None
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            owned.send(f'/usr/bin/stty -g > before; {shlex.quote(str(binary))} {shlex.quote(str(root))}\n'.encode())
            data = owned.ready(greeting=b'OWNED-CHILD-READY\r\n')
            child = child_handle(binary, data)
            offset = len(owned.output)
            if forced:
                signal.pidfd_send_signal(child, signal.SIGSTOP)
            else:
                owned.send(b'stop\n')
            owned.wait(lambda: prompt in owned.output[offset:] and os.tcgetpgrp(owned.master) == owned.pid)
            expected = signal.SIGSTOP if forced else signal.SIGTSTP
            assert (root / 'owner-restored-stop').read_text() == str(int(expected))
            for pid in (data['pid'], data['child']):
                assert Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[0] == 'T'
            offset = len(owned.output)
            owned.send(b'bg\n')
            owned.wait(lambda: prompt in owned.output[offset:])
            assert not (root / 'child-foreground').exists()
            owned.send(b'/usr/bin/stty -g > background-mode\n')
            owned.wait(lambda: (root / 'background-mode').exists())
            assert (root / 'background-mode').read_text() == (root / 'before').read_text()
            if cancel:
                owned.send(b'/usr/bin/stty -ixon; /usr/bin/stty -g > changed-mode\n')
                owned.wait(lambda: (root / 'changed-mode').exists())
                assert (root / 'changed-mode').read_text() != (root / 'before').read_text()
                signal.pidfd_send_signal(owned.probe_fd, signal.SIGTERM)
                owned.wait(lambda: select.select([owned.probe_fd], [], [], 0)[0] and (root / 'owner-background-exit').exists())
                assert select.select([child], [], [], 0)[0]
                assert not (root / 'owner-restored-exit').exists()
                owned.send(b'/usr/bin/stty -g > after-cancellation\n')
                owned.wait(lambda: (root / 'after-cancellation').exists())
                assert (root / 'after-cancellation').read_text() == (root / 'changed-mode').read_text()
                assert os.tcgetpgrp(owned.master) == owned.pid
                print(f'terminal-owner-background-cancel-{"sigstop" if forced else "self-stop"}: pass', flush=True)
                return
            owned.send(b'fg\n')
            if forced:
                owned.wait(lambda: os.tcgetpgrp(owned.master) == data['group'] and termios.tcgetattr(owned.master)[3] & (termios.ICANON | termios.ECHO | termios.ISIG) == 0)
            else:
                owned.wait(lambda: b'OWNED-CHILD-RESUMED\r\n' in owned.output)
            offset = len(owned.output)
            owned.send(b'exit\n')
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'owner-restored-exit').exists())
            owned.send(b'/usr/bin/stty -g > after\n')
            owned.wait(lambda: (root / 'after').exists())
            assert (root / 'after').read_text() == (root / 'before').read_text()
            assert select.select([child], [], [], 0)[0]
            print(f'terminal-owner-shell-{"sigstop" if forced else "self-stop"}: pass', flush=True)
        finally:
            cleanup_child(child)
            owned.close()


def main():
    assert sys.platform == 'linux' and len(sys.argv) == 2
    binary = Path(sys.argv[1]).resolve(strict=True)
    for scenario in ('normal', 'child-sigkill', 'owner-sigterm', 'external-stop-refusal'):
        direct(binary, scenario)
    shell_job(binary, False)
    shell_job(binary, True)
    shell_job(binary, False, cancel=True)
    shell_job(binary, True, cancel=True)
    print('::notice::surviving terminal owner: eight owned-PTY cases passed; error cleanup verifies child exit; background cancellation preserves subsequent shell mode changes; individual child death only; no whole-group loss guarantee', flush=True)


if __name__ == '__main__':
    main()
