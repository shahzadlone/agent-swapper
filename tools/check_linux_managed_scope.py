#!/usr/bin/env python3
"""Qualify a nondelegated systemd scope on a disposable hosted Linux runner."""
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(check, seconds=15):
    deadline = time.monotonic() + seconds
    while not check():
        require(time.monotonic() < deadline, "managed-scope fixture deadline exceeded")
        time.sleep(0.02)


def membership():
    entries = [line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
               if line.startswith('0::')]
    require(len(entries) == 1, "cgroup v2 membership is ambiguous")
    return entries[0]


def private_directory(directory):
    metadata = directory.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
            and metadata.st_mode & 0o077 == 0, "fixture directory is not private")


def check_controls(scope):
    require(os.geteuid() != 0, "target must be unprivileged")
    for directory in (scope, scope.parent, scope.parent.parent):
        metadata = directory.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_mode & 0o022 == 0, "cgroup directory is not manager-owned")
        control = directory / 'cgroup.procs'
        metadata = control.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_mode & 0o022 == 0, "migration control is writable by another principal")
        try:
            descriptor = os.open(control, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except PermissionError:
            continue
        else:
            os.close(descriptor)
            raise RuntimeError("unprivileged target can open a migration control for writing")


def tick(directory, name, seconds, stop_name=None):
    deadline = time.monotonic() + seconds
    counter = 0
    while time.monotonic() < deadline:
        if stop_name and (directory / stop_name).exists():
            return
        temporary = directory / (name + '.tmp')
        temporary.write_text(str(counter))
        temporary.replace(directory / name)
        counter += 1
        time.sleep(0.02)


def role(name, directory, expected, forced):
    private_directory(directory)
    if name == 'outside':
        tick(directory, 'outside-heartbeat', 40, 'outside-stop')
        return
    if name == 'peer':
        require(membership() != expected, "peer is inside the target scope")
        check_controls(Path('/sys/fs/cgroup' + expected))
        (directory / 'peer-controls-checked').write_text('checked')
        return
    require(membership() == expected, "target is outside its managed scope")
    scope = Path('/sys/fs/cgroup' + expected)
    check_controls(scope)
    if name == 'writer':
        require(os.getsid(0) == os.getpid(), "writer did not detach its session")
        if forced:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        (directory / 'writer-ready').write_text('ready')
        tick(directory, 'worker-heartbeat', 30)
        return
    require(name == 'service', "unknown fixture role")
    (directory / 'controls-checked').write_text('checked')
    # Deliberately let this bounded child outlive the service's main process.
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'writer',
                      str(directory), expected, str(int(forced))],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    wait_for(lambda: (directory / 'writer-ready').exists())
    (directory / 'service-ready').write_text('ready')
    wait_for(lambda: (directory / 'allow-main-exit').exists())


def trial(root, forced, run_id, attempt):
    directory = root / ('forced' if forced else 'graceful')
    directory.mkdir(mode=0o700)
    unit = f"aswp-managed-{run_id}-{attempt}-{'forced' if forced else 'graceful'}"
    expected = '/system.slice/' + unit + '.service'
    scope = Path('/sys/fs/cgroup' + expected)
    require(not scope.exists(), "managed scope already exists")
    executable = str(Path(__file__).resolve())
    outside = subprocess.Popen([sys.executable, executable, 'outside', str(directory), '', '0'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, close_fds=True)
    manager = None
    try:
        wait_for(lambda: (directory / 'outside-heartbeat').exists())
        with (directory / 'manager.log').open('wb') as log:
            manager = subprocess.Popen([
                'sudo', '-n', 'systemd-run', '--wait', '--pipe', '--collect', '--service-type=exec',
                '--uid=' + str(os.getuid()), '--gid=' + str(os.getgid()),
                '--property=Delegate=no', '--property=KillMode=control-group',
                '--property=SendSIGKILL=yes', '--property=TimeoutStopSec=2s',
                '--property=RuntimeMaxSec=30s', '--unit=' + unit,
                '/usr/bin/python3', executable, 'service', str(directory), expected, str(int(forced)),
            ], stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True)
            wait_for(lambda: (directory / 'service-ready').exists() or manager.poll() is not None)
            require((directory / 'service-ready').exists(), "managed service failed before readiness")
            require((directory / 'controls-checked').exists(), "control permissions were not checked")
            subprocess.run([sys.executable, executable, 'peer', str(directory), expected, str(int(forced))],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=5)
            require((directory / 'peer-controls-checked').exists(), "same-user peer permissions were not checked")
            require(scope.exists() and 'populated 1' in (scope / 'cgroup.events').read_text().splitlines(),
                    "managed scope was not populated before cleanup")
            before = (directory / 'outside-heartbeat').read_text()
            (directory / 'allow-main-exit').write_text('exit')
            result = manager.wait(timeout=15)
            if not forced:
                require(result == 0, "graceful managed service failed")
            wait_for(lambda: not scope.exists(), seconds=5)
            heartbeat = (directory / 'worker-heartbeat').read_text()
            time.sleep(0.15)
            require((directory / 'worker-heartbeat').read_text() == heartbeat,
                    "detached worker survived manager cleanup")
            wait_for(lambda: (directory / 'outside-heartbeat').read_text() != before)
            require(outside.poll() is None, "outside writer was terminated")
            label = 'forced' if forced else 'graceful'
            print(f'::notice title=Linux managed scope {label}::target and same-user peer refused migration writes; detached writer stopped; original scope removed; outside writer continued; manager exit {result}', flush=True)
    finally:
        (directory / 'outside-stop').write_text('stop')
        try:
            outside.wait(timeout=3)
        except subprocess.TimeoutExpired:
            outside.kill()
            outside.wait(timeout=3)
        if manager is not None and manager.poll() is None:
            # The manager's RuntimeMaxSec bounds target lifetime even if its
            # client is lost; cleanup uses the exact disposable unit name.
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit + '.service'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15, check=False)
            manager.wait(timeout=15)


def main():
    require(sys.platform == 'linux' and os.geteuid() != 0, "fixture needs an ordinary Linux user")
    if len(sys.argv) == 5:
        role(sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4] == '1')
        return
    require(len(sys.argv) == 1, "unexpected fixture arguments")
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            "manager setup is limited to a disposable hosted CI runner")
    run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch(r'[0-9]{1,24}', run_id) and re.fullmatch(r'[0-9]{1,8}', attempt),
            "invalid hosted run identity")
    with tempfile.TemporaryDirectory(prefix='aswp-managed-') as temporary:
        for forced in (False, True):
            trial(Path(temporary), forced, run_id, attempt)


if __name__ == '__main__':
    main()
