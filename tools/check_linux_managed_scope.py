#!/usr/bin/env python3
"""Qualify a nondelegated systemd scope on a disposable hosted Linux runner."""
import os
import json
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

from linux_manager_observer import Observer, check_bound, check_retired


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


def private_directory(directory, owner=None):
    metadata = directory.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == (os.getuid() if owner is None else owner)
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


def parse_identity(output, unit, expected, uid, main_pid):
    require(len(output) <= 4096, "manager identity output exceeds bounds")
    fields = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in fields, "invalid or duplicate manager identity field")
        fields[key] = value
    require(set(fields) == {'Id', 'ControlGroup', 'MainPID', 'InvocationID', 'Transient', 'User', 'ActiveState'},
            "manager identity inventory does not match")
    require(fields['Id'] == unit + '.service' and fields['ControlGroup'] == expected
            and fields['User'] == str(uid) and fields['Transient'] == 'yes'
            and fields['ActiveState'] == 'active', "manager identity binding does not match")
    require(fields['MainPID'] == str(main_pid) and main_pid > 0, "manager main process does not match")
    invocation = fields['InvocationID']
    require(re.fullmatch(r'[0-9a-f]{32}', invocation) and invocation != '0' * 32,
            "invalid manager invocation identity")
    return invocation


def inspect_identity(unit, expected, uid, main_pid, expected_invocation=None):
    result = subprocess.run(['systemctl', 'show', unit + '.service', '--no-pager',
                             '--property=Id,ControlGroup,MainPID,InvocationID,Transient,User,ActiveState'],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            check=True, timeout=5)
    invocation = parse_identity(result.stdout, unit, expected, uid, main_pid)
    if expected_invocation is not None:
        require(invocation == expected_invocation, "manager invocation was replaced")
    validator = os.environ.get('ASWP_MANAGED_VALIDATOR')
    require(validator is not None, "Rust manager validator is not configured")
    arguments = [validator, unit + '.service', str(uid), str(main_pid)]
    if expected_invocation is not None:
        arguments.append(expected_invocation)
    checked = subprocess.run(arguments, input=result.stdout, text=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             check=False, timeout=5)
    require(checked.returncode == 0, "Rust core refused manager identity")
    observer = os.environ.get('ASWP_MANAGED_OBSERVER')
    require(observer is not None, "Rust manager transport observer is not configured")
    arguments = [observer, unit + '.service', str(uid), str(main_pid)]
    if expected_invocation is not None:
        arguments.append(expected_invocation)
    observed = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, encoding='utf-8', errors='replace',
                              check=False, timeout=12)
    require(observed.returncode == 0,
            "Rust manager transport observation failed: " + observed.stderr[-2000:])
    require(len(observed.stdout) <= 8192, "manager observation exceeds bounds")
    report = json.loads(observed.stdout)
    require(report['manager_uid'] == 0 and report['manager_pid'] == 1 and report['peer_uid'] == 0,
            "manager transport identity disagrees")
    fact = report['unit']
    require(fact['unit'] == unit + '.service' and fact['invocation'] == invocation
            and fact['user'] == uid and fact['pid'] == main_pid and fact['control_group'] == expected
            and fact['delegate'] is False and fact['kill_mode'] == 'control-group',
            "direct manager observation disagrees with differential snapshot")
    kernel = fact['kernel']
    named = os.stat('/sys/fs/cgroup' + expected, follow_symlinks=False)
    require(kernel['device'] == named.st_dev and kernel['inode'] == named.st_ino
            and kernel['populated'] is True and kernel['main_pidfd_live'] is True
            and kernel['migration_controls_refused'] is True,
            "Rust kernel corroboration disagrees with fixture scope")
    # Only fixture metadata is reported. JSON escapes control characters before
    # the workflow-command escape, keeping the annotation on a single line.
    diagnostic = json.dumps(report, sort_keys=True).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    print('::notice title=Linux manager transport::' + diagnostic, flush=True)
    return invocation


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


def manager_command(directory, unit, expected, uid, gid, forced):
    return ['systemd-run', '--wait', '--pipe', '--collect', '--service-type=exec',
            '--uid=' + str(uid), '--gid=' + str(gid),
            '--property=Delegate=no', '--property=KillMode=control-group',
            '--property=SendSIGKILL=yes', '--property=TimeoutStopSec=2s',
            '--property=RuntimeMaxSec=30s', '--unit=' + unit,
            '/usr/bin/python3', str(Path(__file__).resolve()), 'service',
            str(directory), expected, str(int(forced))]


def client_helper(directory, expected):
    # CI-only failure injector. It starts a fixed service as the directory's
    # ordinary owner; no caller-supplied service properties or root target.
    import pwd
    require(os.geteuid() == 0, "client helper requires the disposable manager authority")
    require(re.fullmatch(r'/system\.slice/aswp-managed-[0-9]{1,24}-[0-9]{1,8}-client-loss\.service', expected),
            "invalid disposable client-loss unit")
    owner = directory.lstat().st_uid
    require(owner != 0, "client helper cannot launch a root target")
    private_directory(directory, owner)
    group = pwd.getpwuid(owner).pw_gid
    unit = expected.rsplit('/', 1)[1].removesuffix('.service')
    client = subprocess.Popen(manager_command(directory, unit, expected, owner, group, False),
                              stdin=subprocess.DEVNULL, close_fds=True)
    try:
        wait_for(lambda: (directory / 'kill-client').exists() or client.poll() is not None)
        require(client.poll() is None, "manager client exited before failure injection")
        require(Path(f'/proc/{client.pid}/comm').read_text().strip() == 'systemd-run',
                "failure injector does not own the systemd-run client")
        client.kill()
        result = client.wait(timeout=3)
        require(result == -signal.SIGKILL, "manager client was not killed through its owned handle")
        (directory / 'client-status').write_text(str(result))
    finally:
        if client.poll() is None:
            client.kill()
            client.wait(timeout=3)


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
    (directory / 'service-main-pid').write_text(str(os.getpid()))
    # Deliberately let this bounded child outlive the service's main process.
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'writer',
                      str(directory), expected, str(int(forced))],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    wait_for(lambda: (directory / 'writer-ready').exists())
    (directory / 'service-ready').write_text('ready')
    wait_for(lambda: (directory / 'allow-main-exit').exists())


def trial(root, forced, run_id, attempt, client_loss=False):
    label = 'client-loss' if client_loss else ('forced' if forced else 'graceful')
    directory = root / label
    directory.mkdir(mode=0o700)
    unit = f"aswp-managed-{run_id}-{attempt}-{label}"
    expected = '/system.slice/' + unit + '.service'
    scope = Path('/sys/fs/cgroup' + expected)
    require(not scope.exists(), "managed scope already exists")
    executable = str(Path(__file__).resolve())
    outside = subprocess.Popen([sys.executable, executable, 'outside', str(directory), '', '0'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, close_fds=True)
    manager = None
    scope_descriptor = None
    observer = None
    try:
        wait_for(lambda: (directory / 'outside-heartbeat').exists())
        with (directory / 'manager.log').open('wb') as log:
            command = (['sudo', '-n', '/usr/bin/python3', executable, 'client-helper', str(directory), expected]
                       if client_loss else ['sudo', '-n'] + manager_command(
                           directory, unit, expected, os.getuid(), os.getgid(), forced))
            manager = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True)
            wait_for(lambda: (directory / 'service-ready').exists() or manager.poll() is not None)
            require((directory / 'service-ready').exists(), "managed service failed before readiness")
            require((directory / 'controls-checked').exists(), "control permissions were not checked")
            main_pid_text = (directory / 'service-main-pid').read_text()
            require(re.fullmatch(r'[1-9][0-9]{0,9}', main_pid_text), "invalid main process observation")
            main_pid = int(main_pid_text)
            invocation = inspect_identity(unit, expected, os.getuid(), main_pid)
            require(main_pid_text in (scope / 'cgroup.procs').read_text().splitlines(),
                    "manager main process is outside its reported scope")
            subprocess.run([sys.executable, executable, 'peer', str(directory), expected, str(int(forced))],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=5)
            require((directory / 'peer-controls-checked').exists(), "same-user peer permissions were not checked")
            require(scope.exists() and 'populated 1' in (scope / 'cgroup.events').read_text().splitlines(),
                    "managed scope was not populated before cleanup")
            scope_descriptor = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
            opened, named = os.fstat(scope_descriptor), scope.stat()
            require((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
                    and opened.st_uid == 0, "opened scope identity does not match")
            observer = Observer(os.environ['ASWP_MANAGED_OBSERVER'], unit, os.getuid(), main_pid, invocation)
            bound = observer.receive(10)
            check_bound(bound, unit, os.getuid(), main_pid, invocation, opened.st_dev, opened.st_ino)
            before = (directory / 'outside-heartbeat').read_text()
            if client_loss:
                (directory / 'kill-client').write_text('kill')
                wait_for(lambda: (directory / 'client-status').exists() or manager.poll() is not None)
                require((directory / 'client-status').exists(), "client failure injection did not complete")
                result = int((directory / 'client-status').read_text())
                require(result == -signal.SIGKILL and manager.wait(timeout=3) == 0,
                        "manager client-loss observation is invalid")
                # Losing the owned client is not evidence that the target
                # stopped. The root manager still owns its populated scope.
                require(scope.exists() and 'populated 1' in (scope / 'cgroup.events').read_text().splitlines(),
                        "client-loss scope state was not observed")
                require(inspect_identity(unit, expected, os.getuid(), main_pid, invocation) == invocation,
                        "manager invocation changed after client loss")
            (directory / 'allow-main-exit').write_text('exit')
            if not client_loss:
                result = manager.wait(timeout=15)
            if not forced and not client_loss:
                require(result == 0, "graceful managed service failed")
            wait_for(lambda: not scope.exists(), seconds=5)
            try:
                events = os.open('cgroup.events', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 dir_fd=scope_descriptor)
            except FileNotFoundError:
                pass
            else:
                os.close(events)
                raise RuntimeError("original managed scope retirement was not observed")
            retired = observer.receive(12)
            check_retired(retired, bound)
            observer.finish()
            heartbeat = (directory / 'worker-heartbeat').read_text()
            time.sleep(0.15)
            require((directory / 'worker-heartbeat').read_text() == heartbeat,
                    "detached worker survived manager cleanup")
            wait_for(lambda: (directory / 'outside-heartbeat').read_text() != before)
            require(outside.poll() is None, "outside writer was terminated")
            print(f'::notice title=Linux Rust retirement {label}::authenticated original invocation retired; held cgroup directory removed; bound pidfd exited; Python kernel observations agree; no production custody receipt', flush=True)
            print(f'::notice title=Linux managed scope {label}::target and same-user peer refused migration writes; detached writer stopped; original scope removed; outside writer continued; systemd-run exit {result}', flush=True)
    finally:
        observer_cleanup = None
        if observer is not None:
            try:
                observer.close()
            except Exception as error:
                observer_cleanup = error
        if scope_descriptor is not None:
            os.close(scope_descriptor)
        (directory / 'outside-stop').write_text('stop')
        try:
            outside.wait(timeout=3)
        except subprocess.TimeoutExpired:
            outside.kill()
            outside.wait(timeout=3)
        if manager is not None and scope.exists():
            # The manager's RuntimeMaxSec bounds target lifetime even if its
            # client is lost; cleanup uses the exact disposable unit name.
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit + '.service'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15, check=False)
        if manager is not None and manager.poll() is None:
            manager.wait(timeout=15)
        if observer_cleanup is not None:
            raise observer_cleanup


def main():
    if sys.platform == 'linux' and len(sys.argv) == 4 and sys.argv[1] == 'client-helper':
        client_helper(Path(sys.argv[2]), sys.argv[3])
        return
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
    validator = Path(os.environ.get('ASWP_MANAGED_VALIDATOR', ''))
    require(validator.is_absolute() and validator.is_file() and not validator.is_symlink(),
            "Rust manager validator is missing or invalid")
    observer = Path(os.environ.get('ASWP_MANAGED_OBSERVER', ''))
    require(observer.is_absolute() and observer.is_file() and not observer.is_symlink(),
            "Rust manager observer is missing or invalid")
    with tempfile.TemporaryDirectory(prefix='aswp-managed-') as temporary:
        for forced in (False, True):
            trial(Path(temporary), forced, run_id, attempt)
        trial(Path(temporary), False, run_id, attempt, client_loss=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux managed scope::' + message, flush=True)
        sys.exit(1)
