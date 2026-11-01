#!/usr/bin/env python3
"""Connect the hosted fixed guardian to a relay inside newly created outer PTYs."""
import fcntl
import os
from pathlib import Path
import shlex
import signal
import struct
import sys
import tempfile
import termios

from check_linux_outer_terminal import OwnedPty


def environment():
    keys = ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'ASWP_CI_SOCKET_ACTIVATION',
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ASWP_ACTIVATION_PREFIX',
            'ASWP_CI_ACTIVATED_JOURNAL')
    values = {key: os.environ[key] for key in keys}
    assert values['GITHUB_ACTIONS'] == 'true' and values['RUNNER_ENVIRONMENT'] == 'github-hosted'
    assert values['ASWP_CI_SOCKET_ACTIVATION'] == values['ASWP_CI_ACTIVATED_JOURNAL'] == '1'
    assert values['ASWP_ACTIVATION_PREFIX'] == f"aswp-activation-{values['GITHUB_RUN_ID']}-{values['GITHUB_RUN_ATTEMPT']}"
    return values


def state(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[0]


def retired(owned, root):
    assert (root / 'retired').is_file() and (root / 'restored').is_file()
    assert 'outcome unresolved' in (root / 'intent').read_text()
    # No guardian or client copy may retain the original OFD lease afterwards.
    with (root / 'lease').open('rb+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert termios.tcgetattr(owned.master) == owned.original


def target_command(owned, command, response):
    offset = len(owned.output)
    owned.send(command + b'\n')
    owned.wait(lambda: response in owned.output[offset:])


def direct(binary, scenario, env):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-relay-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, environment=env)
        try:
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            assert (root / 'relay-ready').is_file() and (root / 'intent').is_file()
            target_command(owned, b'size', b'SIZE:24:80\r\n')
            if scenario == 'bytes-resize-tail':
                target_command(owned, b'secret', b'SECRET>')
                secret = b'owned-relay-secret-canary'
                owned.send(secret + b'\n')
                owned.wait(lambda: b'SECRET-OK\r\n' in owned.output)
                assert secret not in owned.output
                target_command(owned, b'raw', b'RAW>')
                payload = 'é→'.encode() + b'\x03\x1a\x1b[A\r\x7f\x15\x17\x04\x16\x13\x11\x1c'
                owned.send(payload + b'\n')
                owned.wait(lambda: b'RAW:' + payload.hex().encode() + b'\r\n' in owned.output)
                fcntl.ioctl(owned.master, termios.TIOCSWINSZ, struct.pack('HHHH', 41, 113, 0, 0))
                target_command(owned, b'size', b'SIZE:41:113\r\n')
                target_command(owned, b'finish', 'FINAL:\x1b[34m→\x1b[0m\r\n'.encode())
                owned.finish()
                assert (root / 'drained').is_file()
                assert all(0 < int(value) <= 16384 for value in (root / 'buffers').read_text().split(':'))
            elif scenario == 'orphan-stop':
                owned.send(b'\x1a')
                owned.wait(lambda: (root / 'resumed-foreground').exists())
                assert (root / 'discarded-stop').exists() and not (root / 'continued').exists()
                assert state(data['target']) != 'T'
                target_command(owned, b'size', b'SIZE:24:80\r\n')
                owned.send(b'\x03')
                owned.finish()
            elif scenario == 'nested':
                target_command(owned, b'nested', b'NESTED-RUNNING:')
                owned.send(b'\x1a')
                owned.wait(lambda: b'NESTED-STOPPED:' in owned.output)
                assert not (root / 'restored-before-stop').exists()
                assert termios.tcgetattr(owned.master)[3] & (termios.ISIG | termios.ICANON | termios.ECHO) == 0
                target_command(owned, b'resume-nested', b'NESTED-DONE\r\n')
                owned.send(b'\x03')
                owned.finish()
            elif scenario == 'flood-term':
                owned.send(b'flood\n')
                owned.wait(lambda: (root / 'backpressure').exists(), pump=False)
                assert (root / 'backpressure').read_text() == '16384'
                os.kill(owned.pid, signal.SIGTERM)
                owned.finish(-signal.SIGTERM, pump=False)
                assert (root / 'cancelled').is_file()
            else:
                raise AssertionError('unknown managed relay scenario')
            retired(owned, root)
            print(f'managed-relay-{scenario}: pass', flush=True)
        finally:
            owned.close()


def shell_job(binary, raw_stop, env):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-relay-shell-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True, environment=env)
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            owned.send(f'/usr/bin/stty -g > before; {shlex.quote(str(binary))} {shlex.quote(str(root))}\n'.encode())
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            offset = len(owned.output)
            owned.send(b'suspend\n' if raw_stop else b'\x1a')
            owned.wait(lambda: prompt in owned.output[offset:] and os.tcgetpgrp(owned.master) == owned.pid)
            assert (root / 'restored-before-stop').read_text() == str(signal.SIGTSTP)
            assert state(data['pid']) == state(data['target']) == 'T'
            offset = len(owned.output)
            owned.send(b'bg\n')
            owned.wait(lambda: (root / 'continued').exists() and prompt in owned.output[offset:])
            assert not (root / 'resumed-foreground').exists() and state(data['target']) == 'T'
            owned.send(b'/usr/bin/stty -g > background-mode\n')
            owned.wait(lambda: (root / 'background-mode').exists())
            assert (root / 'background-mode').read_text() == (root / 'before').read_text()
            fcntl.ioctl(owned.master, termios.TIOCSWINSZ, struct.pack('HHHH', 42, 111, 0, 0))
            owned.send(b'fg\n')
            owned.wait(lambda: (root / 'resumed-foreground').exists())
            assert os.tcgetpgrp(owned.master) == data['group'] and state(data['target']) != 'T'
            if raw_stop:
                owned.wait(lambda: b'RESUMED\r\n' in owned.output)
            target_command(owned, b'size', b'SIZE:42:111\r\n')
            offset = len(owned.output)
            owned.send(b'\x03')
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'retired').exists())
            owned.send(b'/usr/bin/stty -g > after\n')
            owned.wait(lambda: (root / 'after').exists())
            assert (root / 'after').read_text() == (root / 'before').read_text()
            retired(owned, root)
            print(f'managed-relay-shell-{"raw-self-stop" if raw_stop else "typed-ctrl-z"}: pass', flush=True)
        finally:
            owned.close()


def main():
    assert sys.platform == 'linux' and len(sys.argv) == 2
    binary = Path(sys.argv[1]).resolve(strict=True)
    env = environment()
    for scenario in ('bytes-resize-tail', 'orphan-stop', 'nested', 'flood-term'):
        direct(binary, scenario, env)
    shell_job(binary, False, env)
    shell_job(binary, True, env)
    print('::notice::managed two-terminal relay: six owned-PTY cases passed; fixed target and synced fixture intent only; no production custody, exec/exit receipt, or provider qualification', flush=True)


if __name__ == '__main__':
    main()
