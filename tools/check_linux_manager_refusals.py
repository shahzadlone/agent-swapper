#!/usr/bin/env python3
"""Refusal controls in disposable hosted CI mount namespaces only."""
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import tempfile

CASES = {
    'map-overlay': 'kernel metadata crosses a mount boundary',
    'fake-proc': 'process metadata is not procfs',
    'socket-owner': 'bus path is not root-owned',
    'socket-peer': 'bus listener peer is not root',
}
PRESERVE = 'GITHUB_ACTIONS,RUNNER_ENVIRONMENT,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ASWP_MANAGER_REFUSALS'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def gate():
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('ASWP_MANAGER_REFUSALS') == '1'
            and re.fullmatch(r'[0-9]{1,24}', os.environ.get('GITHUB_RUN_ID', ''))
            and re.fullmatch(r'[0-9]{1,8}', os.environ.get('GITHUB_RUN_ATTEMPT', '')),
            'refusal mounts are limited to an opted-in disposable hosted runner')


def identity(uid, gid):
    uid, gid = int(uid), int(gid)
    require(0 < uid < 2**31 and 0 < gid < 2**31, 'ordinary fixture identity required')
    return uid, gid


def drop(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    require(os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == gid,
            'fixture identity change failed')


def stop(child):
    if child is not None:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def mounted_case(case, binary, uid, gid):
    require(os.geteuid() == 0 and case in CASES, 'invalid namespace fixture role')
    # unshare --mount must have created a private namespace. Do not accept an
    # invocation still in PID 1's mount namespace, even on a hosted runner.
    require(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'),
            'fixture did not enter a separate mount namespace')
    target = listener = None
    with tempfile.TemporaryDirectory(prefix='aswp-manager-refusals-') as temporary:
        root = Path(temporary)
        script = str(Path(__file__).resolve())
        try:
            # Hold the owned child at its input gate while installing only the
            # private namespace overlay. It executes the observer as the user.
            target = subprocess.Popen(['/usr/bin/python3', script, '--probe-child', binary, str(uid), str(gid)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if case == 'map-overlay':
                source = root / 'uid_map'
                source.write_text('         0          0 4294967295\n')
                source.chmod(0o644)
                destination = f'/proc/{target.pid}/uid_map'
            elif case == 'fake-proc':
                source = root / 'proc'
                source.mkdir(mode=0o755)
                destination = '/proc'
            else:
                os.chown(root, uid, gid)
                source = root / 'bus'
                listener = subprocess.Popen(['/usr/bin/python3', script, '--listen', str(source), str(uid), str(gid)],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with selectors.DefaultSelector() as selector:
                    selector.register(listener.stdout, selectors.EVENT_READ)
                    require(selector.select(5) and os.read(listener.stdout.fileno(), 1) == b'R',
                            'ordinary listener did not become ready')
                os.chown(root, 0, 0)
                source.chmod(0o666)
                if case == 'socket-peer':
                    os.chown(source, 0, 0)
                destination = '/run/dbus/system_bus_socket'
            subprocess.run(['/usr/bin/mount', '--bind', str(source), destination], check=True,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            stdout, stderr = target.communicate(input=b'GO', timeout=12)
            detail = stderr.decode('utf-8', errors='replace')
            require(target.returncode == 125 and not stdout and CASES[case] in detail,
                    f'{case}: observer did not refuse at the expected check: ' + detail[-2000:])
            print(f'::notice title=Linux manager refusal::{case}: intended check refused the controlled overlay; no observation issued', flush=True)
        finally:
            try:
                stop(target)
            finally:
                stop(listener)


def main():
    gate()
    args = sys.argv[1:]
    if len(args) == 4 and args[0] in ('--probe-child', '--listen'):
        require(os.geteuid() == 0, 'fixture child must start inside the owned root namespace')
        role, path, uid, gid = args
        uid, gid = identity(uid, gid)
        if role == '--probe-child':
            require(sys.stdin.buffer.read(2) == b'GO', 'missing fixture release')
            drop(uid, gid)
            os.execv(path, [path])
        drop(uid, gid)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.settimeout(10)
            listener.bind(path)
            listener.listen(1)
            os.write(sys.stdout.fileno(), b'R')
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                connection.recv(1)
        return
    if len(args) == 5 and args[0] == '--inside':
        _, case, binary, uid, gid = args
        mounted_case(case, binary, *identity(uid, gid))
        return
    require(len(args) == 1 and os.geteuid() != 0, 'ordinary hosted fixture runner required')
    binary = Path(args[0])
    require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(), 'invalid observer binary')
    for case in CASES:
        subprocess.run(['sudo', '-n', '--preserve-env=' + PRESERVE,
                        '/usr/bin/timeout', '--kill-after=3s', '25s', '/usr/bin/unshare',
                        '--mount', '--propagation', 'private', '--fork', '--kill-child',
                        '/usr/bin/python3', str(Path(__file__).resolve()), '--inside', case,
                        str(binary), str(os.getuid()), str(os.getgid())],
                       stdin=subprocess.DEVNULL, check=True, timeout=35)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        diagnostic = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux manager refusal::' + diagnostic, flush=True)
        sys.exit(1)
