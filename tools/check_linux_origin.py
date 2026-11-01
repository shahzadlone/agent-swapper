#!/usr/bin/env python3
"""Read-only positives and hosted-only, disposable namespace refusal controls."""
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location(
    'aswp_origin_mount_controls', Path(__file__).with_name('check_linux_image_mounts.py'))
_mounts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mounts)
require = _mounts.require
PRESERVE = 'GITHUB_ACTIONS,RUNNER_ENVIRONMENT,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ASWP_CI_ORIGIN'
INITIAL_USER = 'user:[4026531837]'
CASES = {
    'private-mount': None,
    'root': 'ordinary capability-free identity',
    'full-map-user': 'outside the initial user namespace',
    'fake-proc': 'origin metadata is not a procfs root',
    'proc-subdirectory': 'origin metadata is not a procfs root',
    'status-overlay': 'origin metadata crosses a mount boundary',
    'namespace-directory': 'origin metadata crosses a mount boundary',
}


def gate():
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('ASWP_CI_ORIGIN') == '1'
            and re.fullmatch(r'[0-9]{1,24}', os.environ.get('GITHUB_RUN_ID', ''))
            and re.fullmatch(r'[0-9]{1,8}', os.environ.get('GITHUB_RUN_ATTEMPT', '')),
            'origin namespace fixtures require opted-in disposable hosted CI')


def stop(child):
    if child is not None:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                stream.close()


def ready(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        require(selector.select(5) and os.read(child.stdout.fileno(), 1) == b'R',
                'origin fixture child did not reach its barrier')


def expected(result, reason):
    if reason is None:
        require(result.returncode == 0 and result.stdout.startswith('origin: admitted ')
                and not result.stderr, 'origin positive failed: ' + result.stderr[-1500:])
    else:
        require(result.returncode == 125 and result.stdout == '' and reason in result.stderr,
                'origin refused at an unexpected boundary: ' + result.stderr[-1500:])


def positives(binary, pidfd_support):
    require(os.geteuid() != 0, 'origin positives require an ordinary user')
    for thread in ([], ['thread']):
        observed = []
        for backend in ([], ['procfs'], ['pidfd']):
            result = subprocess.run([binary, *backend, *thread], capture_output=True, text=True, timeout=8)
            if backend == ['pidfd'] and pidfd_support == 'unsupported':
                require(result.returncode == 77 and result.stdout == 'origin: unsupported\n'
                        and not result.stderr, 'old-kernel pidfd support did not match the measured contract')
            else:
                expected(result, None)
                observed.append(result.stdout.split(' namespaces=', 1)[1])
        require(len(set(observed)) == 1, 'independent origin backends disagree')
    print('::notice title=Linux origin::ordinary leader and nonleader captures agree; pidfd=' + pidfd_support,
          flush=True)


def child(binary, backend, uid, gid, user_namespace):
    if user_namespace:
        require(os.readlink('/proc/self/ns/user') != INITIAL_USER
                and not Path('/proc/self/uid_map').read_text().strip()
                and not Path('/proc/self/gid_map').read_text().strip(), 'user namespace was not freshly created')
    else:
        _mounts.private_namespace()
    os.write(sys.stdout.fileno(), b'R')
    require(sys.stdin.buffer.read(2) == b'GO', 'missing origin fixture release')
    if user_namespace:
        for kind in ('uid', 'gid'):
            require(Path(f'/proc/self/{kind}_map').read_text().split() == ['0', '0', '4294967295'],
                    'identity map fixture did not install its full map')
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    require(os.getresuid() == (uid, uid, uid) and os.getresgid() == (gid, gid, gid),
            'ordinary identity transition failed')
    arguments = [] if backend == 'auto' else [backend]
    os.execv(binary, [binary, *arguments])


def inside(case, binary, backend, uid, gid):
    require(case in CASES and backend in ('auto', 'procfs', 'pidfd'), 'unknown origin fixture case')
    _mounts.private_namespace()
    if case == 'root':
        expected(subprocess.run([binary, *([] if backend == 'auto' else [backend])],
                                capture_output=True, text=True, timeout=8), CASES[case])
        return
    target = None
    mounted = None
    destination = None
    with tempfile.TemporaryDirectory(prefix='aswp-origin-') as temporary:
        base = Path(temporary)
        try:
            command = ['/usr/bin/python3', '-I', '-B', '-S', str(Path(__file__).resolve()),
                       '--child', binary, backend, str(uid), str(gid),
                       'user' if case == 'full-map-user' else 'mount']
            if case == 'full-map-user':
                # No map helpers, subordinate-ID changes or policy overrides.
                # The root parent maps only its blocked, still-live owned child.
                command = ['/usr/bin/unshare', '--user', *command]
            target = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ready(target)
            if case == 'full-map-user':
                require(target.poll() is None and os.readlink(f'/proc/{target.pid}/ns/user') != INITIAL_USER,
                        'full-map target is not the owned user namespace child')
                for kind in ('uid', 'gid'):
                    Path(f'/proc/{target.pid}/{kind}_map').write_text('0 0 4294967295\n')
            elif case in ('fake-proc', 'namespace-directory'):
                source = base / 'fake'
                source.mkdir(mode=0o755)
                (source / 'user').symlink_to(INITIAL_USER)
                destination = '/proc' if case == 'fake-proc' else f'/proc/{target.pid}/ns'
            elif case == 'proc-subdirectory':
                source = Path(f'/proc/{target.pid}')
                destination = '/proc'
            elif case == 'status-overlay':
                source = base / 'status'
                source.write_bytes(Path(f'/proc/{target.pid}/status').read_bytes())
                source.chmod(0o644)
                destination = f'/proc/{target.pid}/status'
            if destination:
                subprocess.run(['/usr/bin/mount', '--bind', str(source), destination],
                               check=True, capture_output=True, timeout=5)
                mounted = destination
            stdout, stderr = target.communicate(input=b'GO', timeout=10)
            expected(subprocess.CompletedProcess([], target.returncode, stdout.decode(), stderr.decode()), CASES[case])
            print(f'::notice title=Linux origin::{case}/{backend}: intended result verified', flush=True)
        finally:
            try:
                stop(target)
            finally:
                # /proc/PID names disappear when the owned child is reaped.
                # Those mounts die with this private namespace, including its
                # waiting unshare parent; no mount is shared with the host.
                if mounted == '/proc':
                    subprocess.run(['/usr/bin/umount', mounted], check=True, capture_output=True, timeout=5)


def main():
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == '--positive' and args[2] in ('available', 'unsupported'):
        positives(args[1], args[2])
        return
    gate()
    if len(args) == 6 and args[0] == '--child':
        _, binary, backend, uid, gid, kind = args
        require(kind in ('user', 'mount') and backend in ('auto', 'procfs', 'pidfd'), 'invalid origin child')
        child(binary, backend, *_mounts.identity(uid, gid), kind == 'user')
        return
    if len(args) == 6 and args[0] == '--inside':
        _, case, binary, backend, uid, gid = args
        inside(case, binary, backend, *_mounts.identity(uid, gid))
        return
    require(len(args) == 2 and args[1] in ('available', 'unsupported') and os.geteuid() != 0,
            'ordinary origin fixture runner required')
    binary = Path(args[0])
    require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(), 'invalid origin probe binary')
    for case in CASES:
        backends = ['auto', 'procfs'] + (['pidfd'] if args[1] == 'available' else [])
        # Metadata substitutions target the procfs mechanism explicitly; the
        # pidfd path deliberately does not consult these filesystem names.
        if case in ('fake-proc', 'proc-subdirectory', 'status-overlay', 'namespace-directory'):
            backends = ['procfs']
        for backend in backends:
            subprocess.run(['sudo', '-n', '--preserve-env=' + PRESERVE,
                            '/usr/bin/timeout', '--kill-after=3s', '25s', '/usr/bin/unshare',
                            '--mount', '--propagation', 'private', '--fork', '--kill-child',
                            '/usr/bin/python3', '-I', '-B', '-S', str(Path(__file__).resolve()),
                            '--inside', case, str(binary), backend, str(os.getuid()), str(os.getgid())],
                           stdin=subprocess.DEVNULL, check=True, timeout=35)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux origin::' + detail, flush=True)
        sys.exit(1)
