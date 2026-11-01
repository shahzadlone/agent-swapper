#!/usr/bin/env python3
"""Exercise the fixed outer-terminal probe only inside PTYs created here."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import sys
import tempfile
import termios
import time


class OwnedPty:
    def __init__(self, binary, root, shell=False, redirect=False, environment=None, arguments=()):
        self.root, self.binary, self.shell = root, binary, shell
        self.master, slave = pty.openpty()
        stat = os.fstat(slave)
        (root / 'terminal.json').write_text(json.dumps([stat.st_dev, stat.st_ino, stat.st_rdev]))
        self.original = termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        self.status, self.probe_fd = None, None
        self.output = bytearray()
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(self.master)
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                for fd in (0, 1, 2):
                    os.dup2(slave, fd)
                if slave > 2:
                    os.close(slave)
                if redirect:
                    fd = os.open('/dev/null', os.O_WRONLY)
                    os.dup2(fd, 1)
                    if fd > 2:
                        os.close(fd)
                os.chdir(root)
                env = {'HOME': str(root), 'PATH': '/usr/bin:/bin', 'TERM': 'xterm-256color',
                       'LANG': 'C.UTF-8', 'ASWP_OWNED_OUTER_PTY': '1',
                       'HISTFILE': '/dev/null', 'PS1': '__ASWP_OUTER_PROMPT__ '}
                if environment is not None:
                    env.update(environment)
                if shell:
                    os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-i'], env)
                os.execve(binary, [str(binary), *arguments, str(root)], env)
            except BaseException:
                os._exit(126)
        os.close(slave)
        os.set_blocking(self.master, False)

    def pump(self):
        if select.select([self.master], [], [], 0.01)[0]:
            try:
                self.output.extend(os.read(self.master, 65536))
            except OSError as error:
                if error.errno not in (errno.EIO, errno.EAGAIN):
                    raise
        assert len(self.output) < 2 * 1024 * 1024, 'outer fixture exceeded output budget'

    def wait(self, predicate, seconds=6, pump=True):
        until = time.monotonic() + seconds
        while not predicate():
            assert time.monotonic() < until, f'outer fixture deadline: {bytes(self.output[-1400:])!r}'
            if pump:
                self.pump()
            time.sleep(0.005)

    def send(self, data):
        assert os.write(self.master, data) == len(data), 'short fixture input write'

    def poll(self):
        if self.status is None:
            found, status = os.waitpid(self.pid, os.WNOHANG)
            if found:
                self.status = status
        return self.status

    def ready(self, greeting=b'OUTER-READY\r\n'):
        self.wait(lambda: greeting in self.output and (self.root / 'ready').exists())
        data = json.loads((self.root / 'ready').read_text())
        if self.shell:
            self.probe_fd = os.pidfd_open(data['pid'])
            stat = Path(f"/proc/{data['pid']}/stat").read_text().rsplit(') ', 1)[1].split()
            assert int(stat[1]) == self.pid and int(stat[3]) == self.pid, 'probe is not this shell child'
            assert os.path.samefile(f"/proc/{data['pid']}/exe", self.binary), 'probe executable differs'
        else:
            assert data['pid'] == self.pid and data['session'] == self.pid
        assert data['group'] == data['pid'] == os.tcgetpgrp(self.master)
        assert termios.tcgetattr(self.master)[3] & (termios.ICANON | termios.ECHO | termios.ISIG) == 0
        return data

    def finish(self, code=0, pump=True):
        self.wait(lambda: self.poll() is not None, pump=pump)
        assert os.waitstatus_to_exitcode(self.status) == code, (self.status, bytes(self.output[-1400:]))
        assert termios.tcgetattr(self.master) == self.original, 'outer terminal was not fully restored'

    def close(self):
        if self.probe_fd is not None:
            if not select.select([self.probe_fd], [], [], 0)[0]:
                signal.pidfd_send_signal(self.probe_fd, signal.SIGKILL)
            os.close(self.probe_fd)
        if self.poll() is None:
            # Only the original unreaped child; no PID from a marker is killed.
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        if self.master is not None:
            os.close(self.master)


def direct(binary, scenario):
    with tempfile.TemporaryDirectory(prefix='aswp-outer-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, redirect=scenario == 'redirect')
        try:
            if scenario == 'redirect':
                owned.finish(125)
                assert not (root / 'ready').exists()
            else:
                owned.ready()
                if scenario == 'bytes-resize':
                    payload = 'é→'.encode() + b'\x03\x1a\x1b[A\r\x7f\x15\x17\x04\x16\x13\x11\x1c'
                    owned.send(payload + b'\nfirst\nsecond\n')
                    for value in (payload, b'first', b'second'):
                        expected = b'DATA:' + value.hex().encode() + b'\r\n'
                        owned.wait(lambda: expected in owned.output)
                    fcntl.ioctl(owned.master, termios.TIOCSWINSZ, struct.pack('HHHH', 41, 113, 0, 0))
                    owned.wait(lambda: (root / 'size').exists())
                    assert (root / 'size').read_text() == '41:113'
                    owned.send(b'exit\n')
                    owned.finish()
                elif scenario == 'orphan-stop':
                    owned.send(b'stop\n')
                    owned.wait(lambda: b'OUTER-RESUMED\r\n' in owned.output)
                    assert (root / 'discarded-stop').exists() and not (root / 'continued').exists()
                    owned.send(b'alive\n')
                    owned.wait(lambda: b'DATA:616c697665\r\n' in owned.output)
                    owned.send(b'exit\n')
                    owned.finish()
                elif scenario in ('flood-exit', 'flood-term'):
                    owned.send(b'flood\n')
                    owned.wait(lambda: (root / 'flood').exists(), pump=False)
                    owned.wait(lambda: (root / 'backpressure').exists(), pump=False)
                    assert 0 < int((root / 'backpressure').read_text()) <= 17000
                    if scenario == 'flood-term':
                        os.kill(owned.pid, signal.SIGTERM)
                        owned.finish(-signal.SIGTERM, pump=False)
                    else:
                        owned.send(b'exit\n')
                        owned.finish(pump=False)
                elif scenario == 'failure':
                    owned.send(b'fail\n')
                    owned.finish(125)
                elif scenario == 'oversize':
                    owned.send(b'x' * 256)
                    owned.finish(125)
                else:
                    raise AssertionError('unknown fixed outer scenario')
            print(f'outer-{scenario}: pass', flush=True)
        finally:
            owned.close()


def shell_job(binary, external=False):
    with tempfile.TemporaryDirectory(prefix='aswp-outer-shell-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True)
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            command = f'/usr/bin/stty -g > before; {shlex.quote(str(binary))} {shlex.quote(str(root))}\n'
            owned.send(command.encode())
            data = owned.ready()
            offset = len(owned.output)
            if external:
                signal.pidfd_send_signal(owned.probe_fd, signal.SIGTSTP)
            else:
                owned.send(b'stop\n')
            owned.wait(lambda: prompt in owned.output[offset:] and os.tcgetpgrp(owned.master) == owned.pid)
            assert (root / 'restored-before-stop').exists()
            stat = Path(f"/proc/{data['pid']}/stat").read_text().rsplit(') ', 1)[1].split()
            assert stat[0] == 'T', 'outer process did not actually stop'
            offset = len(owned.output)
            owned.send(b'bg\n')
            owned.wait(lambda: (root / 'continued').exists() and prompt in owned.output[offset:])
            assert not (root / 'resumed-foreground').exists(), 'background resume entered raw mode'
            owned.send(b'/usr/bin/stty -g > background-mode\n')
            owned.wait(lambda: (root / 'background-mode').exists())
            assert (root / 'background-mode').read_text() == (root / 'before').read_text()
            offset = len(owned.output)
            owned.send(b'fg\n')
            owned.wait(lambda: b'OUTER-RESUMED\r\n' in owned.output[offset:])
            assert (root / 'resumed-foreground').exists()
            assert os.tcgetpgrp(owned.master) == data['group']
            offset = len(owned.output)
            owned.send(b'exit\n')
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'restored').exists())
            owned.send(b'/usr/bin/stty -g > after\n')
            owned.wait(lambda: (root / 'after').exists())
            assert (root / 'after').read_text() == (root / 'before').read_text()
            print(f'outer-shell-{"signal" if external else "command"}-stop-bg-fg: pass', flush=True)
        finally:
            owned.close()


def main():
    assert sys.platform == 'linux' and len(sys.argv) == 2, 'requires the Linux fixed outer probe'
    binary = Path(sys.argv[1]).resolve(strict=True)
    assert binary.is_file() and os.access(binary, os.X_OK)
    for scenario in ('bytes-resize', 'orphan-stop', 'flood-exit', 'flood-term', 'failure', 'oversize', 'redirect'):
        direct(binary, scenario)
    shell_job(binary)
    shell_job(binary, external=True)
    print('::notice::owned outer PTYs: bytes, resize, restoration, stop/bg/fg, orphan-stop fallback and cancellation under backpressure passed; no inner relay or provider qualification', flush=True)


if __name__ == '__main__':
    main()
