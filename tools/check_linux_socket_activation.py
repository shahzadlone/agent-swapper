#!/usr/bin/env python3
"""Fixed-user activation experiment; disposable hosted CI only, never installation."""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

from check_linux_managed_scope import check_controls, private_directory, wait_for

PRESERVE = 'GITHUB_ACTIONS,RUNNER_ENVIRONMENT,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ASWP_CI_SOCKET_ACTIVATION,ASWP_MANAGED_OBSERVER'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def owned_fixture(command, environment, seconds=90):
    """Bound the owned cargo/test/client group, retaining timeout diagnostics."""
    process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        output, errors = process.communicate(timeout=seconds)
    except subprocess.TimeoutExpired as expired:
        # No poll/wait has reaped the session leader before this group signal.
        # These fixed test roles do not leave their session; systemd workers
        # are separately bounded and stopped by the administrator teardown.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            output, errors = process.communicate(timeout=5)
        except subprocess.TimeoutExpired as remaining:
            def decoded(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
            output, errors = decoded(remaining.stdout), decoded(remaining.stderr)
            process.stdout.close()
            process.stderr.close()
            process.wait(timeout=2)
        raise RuntimeError('owned activation test group timed out; output: '
                           + output[-3000:] + '; stderr: ' + errors[-3000:]) from expired
    return subprocess.CompletedProcess(command, process.returncode, output, errors)


def read_bind_refusal(connection, directory, invocation):
    require(isinstance(invocation, str) and re.fullmatch(r'[0-9a-f]{32}', invocation)
            and invocation != '0' * 32, 'invalid bind refusal invocation')
    reset = False
    try:
        diagnostic = connection.recv(4096)
    except ConnectionResetError:
        # Unread trailing records can discard an already queued diagnostic.
        # A reset alone never proves the intended guardian refusal.
        reset, diagnostic = True, b''
    refusal = directory / (invocation + '.bind-refused')
    wait_for(refusal.exists, seconds=2)
    require(refusal.read_text() == 'bind-only probe sent launch data'
            and (reset or b'bind-only probe sent launch data' in diagnostic),
            'bind fault did not reach the intended refusal')
    refusal.unlink()


def fixture_prefix():
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('ASWP_CI_SOCKET_ACTIVATION') == '1',
            'socket activation fixture requires opted-in disposable hosted CI')
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch(r'[0-9]{1,24}', run) and re.fullmatch(r'[0-9]{1,8}', attempt),
            'invalid hosted run identity')
    return f'aswp-activation-{run}-{attempt}'


def endpoint(prefix):
    return Path('/run') / (prefix + '.sock')


def guardian_image(prefix):
    # /run is commonly noexec. Keep executable fixture content in a protected
    # executable parent; sockets and ownership metadata still belong in /run.
    return Path('/usr/lib') / (prefix + '.guardian')


def protected_image_parent(prefix):
    for path in reversed(guardian_image(prefix).parents):
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
                f'guardian image parent is not root-owned and protected: {path}')


def source_image(uid):
    path = Path(os.environ.get('ASWP_MANAGED_OBSERVER', ''))
    require(path.is_absolute(), 'compiled Rust guardian source is required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == uid and meta.st_mode & 0o022 == 0,
                'compiled guardian source is not owned and protected')
        data = stream.read(64 * 1024 * 1024 + 1)
    require(len(data) <= 64 * 1024 * 1024 and data.startswith(b'\x7fELF'),
            'compiled guardian source is not a bounded ELF image')
    return data


def verify_image(path, digest):
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_mode & 0o7777 == 0o755,
            'installed guardian image is not root-owned and protected')
    with path.open('rb') as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    require(len(data) <= 64 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == digest,
            'installed guardian image differs from ownership marker')


def ordinary_ids(uid, gid):
    uid, gid = int(uid), int(gid)
    require(0 < uid < 2**31 and 0 < gid < 2**31, 'ordinary target UID and GID required')
    return uid, gid


def unit_files(prefix, directory, uid, gid):
    uid, gid = ordinary_ids(uid, gid)
    for path in (guardian_image(prefix), directory):
        require(path.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))
                and '..' not in path.parts, 'fixture path cannot be represented as a fixed unit argument')
    require(re.fullmatch(r'aswp-activation-[0-9]{1,24}-[0-9]{1,8}', prefix), 'invalid fixture unit prefix')
    run, attempt = prefix.removeprefix('aswp-activation-').split('-')
    socket_unit = f'''[Unit]
Description=AgentSwapper disposable activation fixture
[Socket]
ListenSequentialPacket={endpoint(prefix)}
SocketUser={uid}
SocketGroup={gid}
SocketMode=0600
Accept=yes
MaxConnections=4
TriggerLimitIntervalSec=30s
TriggerLimitBurst=56
RemoveOnStop=yes
'''
    service_unit = f'''[Unit]
Description=AgentSwapper disposable fixed-user guardian
CollectMode=inactive-or-failed
[Service]
Type=exec
Restart=no
User={uid}
Group={gid}
ExecStart={guardian_image(prefix)} --activation-guardian {prefix} {uid} {gid} {directory} %n
Environment=GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted ASWP_CI_SOCKET_ACTIVATION=1 GITHUB_RUN_ID={run} GITHUB_RUN_ATTEMPT={attempt}
StandardInput=socket
StandardOutput=socket
StandardError=journal
Slice=system.slice
Delegate=no
KillMode=control-group
SendSIGKILL=yes
TimeoutStartSec=10s
TimeoutStopSec=2s
RuntimeMaxSec=60s
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
'''
    return {prefix + '.socket': socket_unit, prefix + '@.service': service_unit}


def systemctl(*args, check=True):
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                   'SYSTEMD_COLORS': '0', 'DBUS_SYSTEM_BUS_ADDRESS': 'unix:path=/run/dbus/system_bus_socket'}
    result = subprocess.run(['/usr/bin/systemctl', '--system', '--no-pager', *args], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding='utf-8', errors='replace',
                            timeout=12, check=False, env=environment)
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'manager diagnostic exceeds bounds')
    require(not check or result.returncode == 0,
            'fixture manager command failed: ' + result.stderr[-1500:])
    return result


def unit_properties(name, names):
    result = systemctl('show', name, '--property=' + ','.join(names), check=False)
    rows = [line.split('=', 1) for line in result.stdout.splitlines()]
    require(all(len(row) == 2 for row in rows), 'invalid manager property response')
    fields = dict(rows)
    require(len(fields) == len(rows) and set(fields) == set(names), 'incomplete manager property response')
    return fields


def effective_unit(name, fragment):
    fields = unit_properties(name, ('LoadState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload'))
    require(fields == {'LoadState': 'loaded', 'FragmentPath': str(fragment),
                       'DropInPaths': '', 'NeedDaemonReload': 'no'},
            'effective fixture unit differs from the protected runtime configuration')


def create_owned_file(path, contents, mode, created):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        meta = os.fstat(stream.fileno())
        created.append((path, meta.st_dev, meta.st_ino))
        stream.write(contents)
        stream.flush()
        os.fchmod(stream.fileno(), mode)


def rollback_created(created):
    # Only before daemon-reload: these names have not been activated. Retain
    # the exclusive-create identity, even if writing or chmod failed midway.
    for path, device, inode in reversed(created):
        meta = path.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid()
                and (meta.st_dev, meta.st_ino) == (device, inode),
                'partial fixture file changed; refusing rollback')
        path.unlink()


def template_refusal(template, contents, prefix, uid, gid):
    """Caller has authenticated the owned marker, image and every unit file."""
    before = unit_properties(prefix + '.socket', ('NAccepted', 'NConnections'))
    require(before['NConnections'] == '0' and re.fullmatch(r'[0-9]{1,20}', before['NAccepted']),
            'template control requires an idle activation socket')
    descriptor = os.open(template, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and stat.S_IMODE(metadata.st_mode) == 0o644,
                'template control requires the original protected file')
        observer = os.environ.get('ASWP_MANAGED_OBSERVER', '')
        require(Path(observer).is_absolute() and Path(observer).is_file(),
                'template control requires the fixed Rust observer')
        environment = {name: os.environ[name] for name in PRESERVE.split(',') if name in os.environ}
        environment.update(PATH='/usr/bin:/bin', LC_ALL='C')
        try:
            os.fchmod(descriptor, 0o664)
            result = subprocess.run(['/usr/bin/setpriv', '--reuid', str(uid), '--regid', str(gid),
                '--clear-groups', '--inh-caps=-all', '--bounding-set=-all', '--no-new-privs',
                observer, '--activation-probe', prefix], env=environment, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=12, check=False)
            require(result.returncode == 125 and not result.stdout
                    and 'installed file is not a root-owned protected regular file' in result.stderr,
                    'mutable template did not refuse at the installed-file check: ' + result.stderr[-2000:])
            after = unit_properties(prefix + '.socket', ('NAccepted', 'NConnections'))
            require(after == before, 'mutable-template observer connected before refusing')
        finally:
            os.fchmod(descriptor, 0o644)
            require(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o644,
                    'owned template mode was not restored')
        require(template.read_text() == contents, 'owned template contents changed during control')
        effective_unit(f'{prefix}@0-1-{uid}.service', template)
    finally:
        os.close(descriptor)
    print('::notice title=Linux activation template::ordinary observer refused the owned mode-0664 template; accepted connection count unchanged; original mode restored', flush=True)


def admin(verb, directory, uid, gid):
    prefix = fixture_prefix()
    require(os.geteuid() == 0 and verb in ('install', 'cleanup', 'template-refusal'), 'invalid fixture administrator role')
    uid, gid = ordinary_ids(uid, gid)
    private_directory(directory, uid)
    files = unit_files(prefix, directory, uid, gid)
    identity = {'uid': uid, 'gid': gid, 'directory': str(directory), 'units': files}
    marker = Path('/run') / (prefix + '.owner')
    parent = Path('/run/systemd/system')
    metadata = parent.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
            'runtime unit directory is not root-owned and protected')
    if verb == 'install':
        protected_image_parent(prefix)
        require(not os.path.lexists(endpoint(prefix)), 'fixture activation endpoint already exists')
        require(not os.statvfs(guardian_image(prefix).parent).f_flag & os.ST_NOEXEC,
                'disposable Rust fixture requires an executable /usr/lib mount; no host mount will be changed')
        require(not os.path.lexists(guardian_image(prefix)), 'fixture guardian image already exists')
        for name in files:
            require(not os.path.lexists(parent / name), 'fixture unit name already exists')
        for name in [prefix + '.socket', f'{prefix}@0-1-{uid}.service']:
            require(unit_properties(name, ('LoadState',)) == {'LoadState': 'not-found'},
                    'fixture unit name already resolves in the system manager')
        data = source_image(uid)
        ownership = json.dumps(identity | {'guardian_sha256': hashlib.sha256(data).hexdigest()}, sort_keys=True)
        created = []
        try:
            create_owned_file(marker, ownership.encode(), 0o600, created)
            create_owned_file(guardian_image(prefix), data, 0o755, created)
            verify_image(guardian_image(prefix), hashlib.sha256(data).hexdigest())
            for name, contents in files.items():
                create_owned_file(parent / name, contents.encode(), 0o644, created)
        except BaseException:
            rollback_created(created)
            raise
        systemctl('daemon-reload')
        effective_unit(prefix + '.socket', parent / (prefix + '.socket'))
        effective_unit(f'{prefix}@0-1-{uid}.service', parent / (prefix + '@.service'))
        systemctl('start', prefix + '.socket')
        effective_unit(prefix + '.socket', parent / (prefix + '.socket'))
        return
    if not os.path.lexists(marker):
        require(verb == 'cleanup', 'template control lacks its ownership marker')
        # Installation refused before reserving anything. Never stop or remove
        # a pre-existing unit merely because its name matches this fixture.
        return
    marker_meta = marker.lstat()
    require(stat.S_ISREG(marker_meta.st_mode) and marker_meta.st_uid == 0
            and marker_meta.st_mode & 0o077 == 0,
            'fixture ownership marker is absent, changed or not protected')
    try:
        ownership = json.loads(marker.read_text())
    except ValueError as error:
        raise RuntimeError('fixture ownership marker is invalid') from error
    require(isinstance(ownership, dict) and set(ownership) == set(identity) | {'guardian_sha256'}
            and all(ownership[key] == value for key, value in identity.items())
            and isinstance(ownership['guardian_sha256'], str)
            and re.fullmatch(r'[0-9a-f]{64}', ownership['guardian_sha256']),
            'fixture ownership marker differs from this run')
    protected_image_parent(prefix)
    if os.path.lexists(guardian_image(prefix)):
        verify_image(guardian_image(prefix), ownership['guardian_sha256'])
    for name, contents in files.items():
        path = parent / name
        if verb == 'template-refusal':
            require(os.path.lexists(path), 'template control lacks an installed fixture unit')
        if os.path.lexists(path):
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and metadata.st_mode & 0o022 == 0 and path.read_text() == contents,
                    'fixture unit changed; refusing service control')
    if verb == 'template-refusal':
        template_refusal(parent / (prefix + '@.service'), files[prefix + '@.service'], prefix, uid, gid)
        return
    # All names are reserved to this run. Stop activation before collecting its
    # service instances; no wildcard includes any unrelated unit prefix.
    loaded = unit_properties(prefix + '.socket', ('LoadState',))['LoadState']
    if loaded != 'not-found':
        effective_unit(prefix + '.socket', parent / (prefix + '.socket'))
        systemctl('stop', prefix + '.socket')
        require(unit_properties(prefix + '.socket', ('ActiveState',))['ActiveState'] in ('inactive', 'failed'),
                'fixture activation socket did not stop')
    listing = systemctl('list-units', '--all', '--plain', '--no-legend', '--full', prefix + '@*.service')
    for row in listing.stdout.splitlines():
        name = row.split()[0]
        require(re.fullmatch(re.escape(prefix) + r'@[0-9]+-[0-9]+-[0-9]+\.service', name),
                'unexpected activation service name')
        effective_unit(name, parent / (prefix + '@.service'))
        systemctl('stop', name)
    # Stop completion can precede final cgroup-directory teardown. Enumerate
    # names afresh; missing parents or other errors still refuse cleanup.
    wait_for(lambda: not any(p.name.startswith(prefix + '@')
                            for p in Path('/sys/fs/cgroup/system.slice').iterdir()), seconds=5)
    for name, contents in files.items():
        path = parent / name
        if os.path.lexists(path):
            require(not path.is_symlink() and path.read_text() == contents,
                    'fixture unit changed; refusing to remove it')
            path.unlink()
    systemctl('daemon-reload')
    require(not os.path.lexists(endpoint(prefix)), 'activation endpoint survived cleanup')
    if os.path.lexists(guardian_image(prefix)):
        verify_image(guardian_image(prefix), ownership['guardian_sha256'])
        guardian_image(prefix).unlink()
    marker.unlink()


def deny_other_user():
    prefix = fixture_prefix()
    require(os.geteuid() == 0, 'separate-user probe requires the disposable fixture authority')
    target = endpoint(prefix)
    require(target.stat().st_uid != 65534, 'fixture owner conflicts with the negative-control UID')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as root_peer:
        root_peer.settimeout(3)
        root_peer.connect(str(target))
        # Peer validation happens before reading a command. Sending no record
        # also avoids resetting the diagnostic with unread client input.
        require(b'activation client identity differs' in root_peer.recv(4096),
                'root peer was not refused by the fixed-user guardian')
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(3)
        try:
            connection.connect(str(target))
        except PermissionError as error:
            require(error.errno == errno.EACCES, 'unexpected separate-user refusal')
        else:
            raise RuntimeError('another ordinary UID could connect to the fixture socket')
    print('::notice title=Linux fixed-user activation::root peer refused by guardian; different ordinary UID refused at socket permission check', flush=True)


def activate(prefix, directory):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    descriptor = None
    try:
        connection.settimeout(8)
        connection.connect(str(endpoint(prefix)))
        peer_pid, peer_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer_uid == 0 and peer_pid == 1, 'activation listener is not the system manager')
        connection.sendall(b'GO\n')
        data, ancillary, flags, _ = connection.recvmsg(4096, 0)
        require(data.endswith(b'\n') and not ancillary
                and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'invalid activation report packet')
        report = json.loads(data)
        require(re.fullmatch(re.escape(prefix) + rf'@[0-9]+-{os.getpid()}-{os.getuid()}\.service', report['unit'])
                and re.fullmatch(r'[0-9a-f]{32}', report['invocation'])
                and report['uid'] == report['peer_uid'] == os.getuid()
                and report['peer_pid'] == os.getpid() and report['pid'] > 1,
                'activation identities disagree')
        scope = Path('/sys/fs/cgroup/system.slice') / report['unit']
        require(report['group'] == '/system.slice/' + report['unit'], 'activation group disagrees')
        descriptor = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        check_controls(scope)
        procs = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
        with os.fdopen(procs) as stream:
            members = stream.read(65537)
        require(len(members) <= 65536 and str(report['pid']) in members.split(),
                'guardian is outside the retained service scope')
        # Differential fixture metadata only; this is not the authenticated
        # production observer or a receipt that can authorize transfer.
        effective_unit(report['unit'], Path('/run/systemd/system') / (prefix + '@.service'))
        fields = unit_properties(report['unit'], ('User', 'Group', 'MainPID', 'InvocationID', 'Delegate', 'KillMode'))
        require(fields == {'User': str(os.getuid()), 'Group': str(os.getgid()), 'MainPID': str(report['pid']),
                           'InvocationID': report['invocation'], 'Delegate': 'no', 'KillMode': 'control-group'},
                'activated manager properties disagree')
        retained, current = os.fstat(descriptor), scope.stat()
        require((retained.st_dev, retained.st_ino) == (current.st_dev, current.st_ino),
                'activation scope changed during fixture checks')
        return connection, report, descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        connection.close()
        raise


def retired(directory, report, descriptor):
    scope = Path('/sys/fs/cgroup' + report['group'])
    wait_for(lambda: not scope.exists(), seconds=5)
    try:
        events = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
    except FileNotFoundError:
        pass
    else:
        os.close(events)
        raise RuntimeError('original activation scope was not removed')
    heartbeat = directory / report['invocation'] / 'heartbeat'
    before = heartbeat.read_text()
    time.sleep(0.15)
    require(heartbeat.read_text() == before, 'activation worker survived original scope removal')
    require(not (heartbeat.parent / 'voluntary-exit').exists(), 'writer reached its own deadline before retirement')
    eof_marker = heartbeat.parent / 'guardian-clean-eof'
    require(eof_marker.is_file() and eof_marker.read_text() == report['invocation'],
            'guardian did not record clean client EOF before original scope retirement')


def live_before_disconnect(directory, report):
    heartbeat = directory / report['invocation'] / 'heartbeat'
    before = heartbeat.read_text()
    wait_for(lambda: heartbeat.read_text() != before, seconds=2)
    # Both processes use Linux CLOCK_MONOTONIC in the same time namespace;
    # these fixture units do not create a private time namespace.
    require(0 <= time.monotonic() - report['started'] < 25,
            'disconnect is too close to the fixture runtime deadline')
    require('populated 1' in Path('/sys/fs/cgroup' + report['group'], 'cgroup.events').read_text().splitlines(),
            'activation scope was not populated before disconnect')


def suite():
    prefix = fixture_prefix()
    require(os.geteuid() != 0, 'activation suite requires an ordinary runner')
    script = str(Path(__file__).resolve())
    connections, descriptors = [], []
    with tempfile.TemporaryDirectory(prefix='aswp-activation-') as temporary:
        directory = Path(temporary)
        admin_args = ['sudo', '-n', '--preserve-env=' + PRESERVE,
                      '/usr/bin/timeout', '--kill-after=3s', '40s', '/usr/bin/python3', script,
                      '--admin']
        identity_args = [str(directory), str(os.getuid()), str(os.getgid())]
        try:
            subprocess.run(admin_args + ['install'] + identity_args, check=True, timeout=50)
            meta = endpoint(prefix).lstat()
            require(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == os.getuid() and meta.st_mode & 0o777 == 0o600,
                    'activation socket ownership or mode differs')
            observer = os.environ.get('ASWP_MANAGED_OBSERVER')
            require(observer and Path(observer).is_absolute(), 'Rust activation observer path is required')
            observed = subprocess.run([observer, '--activation-probe', prefix], stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=40, check=False)
            require(observed.returncode == 0, 'Rust activation binding failed: ' + observed.stderr[-2000:])
            require(len(observed.stdout) <= 16384, 'activation observer report exceeds bounds')
            records = [json.loads(line) for line in observed.stdout.splitlines()]
            require(len(records) == 2 and [r['phase'] for r in records] == ['activation_bound', 'activation_retired']
                    and records[0]['unit'] == records[1]['unit']
                    and records[0]['activation'] == records[1]['activation']
                    and records[0]['activation']['sender_pid'] == records[0]['unit']['pid']
                    and records[0]['activation']['sender_uid'] == os.getuid()
                    and records[0]['activation']['launch_data_sent'] is False
                    and records[0]['activation']['manager_connection_substitution_refused'] is True
                    and records[1]['retirement']['original_directory_removed'] is True
                    and records[1]['retirement']['main_pidfd_exited'] is True,
                    'Rust activation binding or retirement evidence differs')
            invocation = records[0]['unit']['invocation']
            bind_marker = directory / (invocation + '.bind-clean-eof')
            require(set(directory.iterdir()) == {bind_marker} and bind_marker.read_text() == invocation,
                    'bind-only guardian did not record clean EOF or created unexpected files')
            bind_marker.unlink()
            subprocess.run(admin_args + ['template-refusal'] + identity_args, check=True, timeout=50)
            require(not any(directory.iterdir()), 'mutable-template refusal created an activation worker or marker')
            print('::notice title=Linux activation binding::kernel message sender matched manager MainPID and invocation; guardian recorded clean EOF and original scope retired; no launch data or worker', flush=True)
            for packets, shutdown in [((b'X',), False), ((b'',), False),
                                      ((b'',), True), ((b'', b'X'), True)]:
                hold = directory / 'bind-eof-hold'
                hold.write_text('queue complete fault before guardian EOF read')
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as invalid_bind:
                    invalid_bind.settimeout(8)
                    invalid_bind.connect(str(endpoint(prefix)))
                    invalid_bind.sendall(b'BIND\n')
                    offer = json.loads(invalid_bind.recv(4096))
                    require(re.fullmatch(re.escape(prefix) + rf'@[0-9]+-{os.getpid()}-{os.getuid()}\.service', offer['unit']),
                            'invalid bind negative-control unit')
                    for packet in packets:
                        require(invalid_bind.send(packet) == len(packet), 'incomplete bind fault packet')
                    if shutdown:
                        invalid_bind.shutdown(socket.SHUT_WR)
                    hold.unlink()
                    read_bind_refusal(invalid_bind, directory, offer['invocation'])
                wait_for(lambda: not (Path('/sys/fs/cgroup/system.slice') / offer['unit']).exists(), seconds=5)
                require(not any(directory.iterdir()), 'failed bind created an EOF marker or worker')
            print('::notice title=Linux activation bind EOF control::unexpected and empty records refused before and after peer shutdown, including trailing data; no clean EOF marker or worker', flush=True)
            with open('/dev/null', 'rb') as harmless:
                faults = [('oversized control packet', b'GO\nextra', []),
                          ('unexpected descriptor', b'GO\n',
                           [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', harmless.fileno()))])]
                for label, packet, rights in faults:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as malformed:
                        malformed.settimeout(8)
                        malformed.connect(str(endpoint(prefix)))
                        require(malformed.sendmsg([packet], rights) == len(packet), 'incomplete negative-control packet')
                        diagnostic = malformed.recv(4096)
                        require(b'invalid fixture activation request' in diagnostic,
                                label + ' was not refused at its framing check')
                        require(not any(directory.iterdir()), 'invalid activation packet started a fixture worker')
                    print('Linux fixed-user activation: ' + label + ' refused before worker creation', flush=True)
            for label, packets, shutdown in [
                    ('unexpected command', (b'X',), False),
                    ('empty record on open peer', (b'',), False),
                    ('empty record before shutdown', (b'',), True)]:
                faulty, faulty_report, faulty_fd = activate(prefix, directory)
                connections.append(faulty)
                descriptors.append(faulty_fd)
                live_before_disconnect(directory, faulty_report)
                # sendall(b'') performs no send syscall; send is needed to
                # create an actual zero-length sequenced-packet record.
                for packet in packets:
                    require(faulty.send(packet) == len(packet), 'incomplete guardian error control')
                if shutdown:
                    faulty.shutdown(socket.SHUT_WR)
                require(b'unexpected fixture activation command' in faulty.recv(4096),
                        'guardian error control did not reach the intended protocol refusal')
                faulty.close()
                try:
                    retired(directory, faulty_report, faulty_fd)
                except RuntimeError as error:
                    require(str(error) == 'guardian did not record clean client EOF before original scope retirement',
                            'guardian error control failed at a different observation')
                else:
                    raise RuntimeError('guardian error was accepted as clean client EOF')
                print('Linux activation EOF control: ' + label
                      + ': worker stopped and scope removed but refused as clean EOF evidence', flush=True)
            first, first_report, first_fd = activate(prefix, directory)
            connections.append(first)
            descriptors.append(first_fd)
            second, second_report, second_fd = activate(prefix, directory)
            connections.append(second)
            descriptors.append(second_fd)
            require(first_report['invocation'] != second_report['invocation']
                    and first_report['unit'] != second_report['unit'], 'connections share an activation invocation')
            subprocess.run(['sudo', '-n', '--preserve-env=' + PRESERVE, '/usr/bin/python3', script, '--deny-other-user'],
                           check=True, timeout=8)
            live_before_disconnect(directory, first_report)
            first.close()
            retired(directory, first_report, first_fd)
            before = (directory / second_report['invocation'] / 'heartbeat').read_text()
            wait_for(lambda: (directory / second_report['invocation'] / 'heartbeat').read_text() != before, seconds=3)
            require(Path('/sys/fs/cgroup' + second_report['group']).exists(), 'first disconnect retired the other connection')
            live_before_disconnect(directory, second_report)
            second.close()
            retired(directory, second_report, second_fd)
            print('::notice title=Linux fixed-user activation::two ordinary connections received distinct root-managed scopes; both refused migration writes; each guardian recorded clean client EOF before stopped detached writer and original scope removal; sibling continued; no production launch qualification', flush=True)
            if os.environ.get('ASWP_CI_ACTIVATED_JOURNAL') == '1':
                test_env = dict(os.environ, ASWP_ACTIVATION_PREFIX=prefix,
                                ASWP_ACTIVATION_DIRECTORY=str(directory))
                passed = []
                for test in ('cancellation_after_durable_journal_never_releases_target_or_completes_run',
                             'actual_lease_and_journal_gate_two_independent_activations',
                             'sqlite_write_failure_withholds_go_and_keeps_unresolved_intent',
                             'invalid_or_independently_locked_lease_never_spawns_writer',
                             'guardian_sigkill_retires_writer_without_clearing_journal',
                             'client_sigkill_retires_writer_without_running_client_cleanup',
                             'inner_terminal_exec_is_journal_gated_and_retires_with_master_open',
                             'guardian_session_stops_resume_and_retire_without_releasing_journal_policy',
                             'exec_stop_precedes_spawn_journal_and_release_or_retirement',
                             'authenticated_target_exit_survives_guardian_retirement_but_loss_stays_unknown',
                             'opaque_scope_retirement_rejects_substitution_and_preserves_unknown_target_exit'):
                    result = owned_fixture(['cargo', '+1.98.0', 'test', '--locked', '-p', 'agentswapper-core',
                                    '--features', 'linux-journal-qualification',
                                    '--lib', 'store::linux_activated_journal_tests::' + test,
                                    '--', '--exact', '--ignored', '--test-threads=1', '--nocapture'],
                                   environment=test_env)
                    print(result.stdout[-16000:], end='', flush=True)
                    print(result.stderr[-8000:], end='', file=sys.stderr, flush=True)
                    require(result.returncode == 0
                            and 'test result: ok. 1 passed; 0 failed;' in result.stdout,
                            'activated journal test did not pass exactly once: '
                            + (result.stdout + result.stderr)[-3000:])
                    passed.append(test)
                    print('Linux activated journal qualification: ' + test
                          + ': exactly one test passed', flush=True)
                # Keep the complete result and cleanup visible within GitHub's
                # per-step annotation limit as the qualification matrix grows.
                print('::notice title=Linux activated journal qualification::'
                      + '; '.join(passed)
                      + ': each passed exactly once with real Store and retained witnesses', flush=True)
                relay = Path(__file__).resolve().parent / 'linux-manager-evaluation/target/debug/examples/managed_terminal_relay'
                result = owned_fixture(['/usr/bin/python3', str(Path(__file__).with_name('check_linux_managed_terminal_relay.py')),
                                        str(relay)], environment=test_env)
                print(result.stdout[-16000:], end='', flush=True)
                print(result.stderr[-8000:], end='', file=sys.stderr, flush=True)
                require(result.returncode == 0 and result.stdout.count(': pass') == 68,
                        'managed relay did not pass all sixty-eight owned-PTY cases: '
                        + (result.stdout + result.stderr)[-4000:])
                result = owned_fixture(['/usr/bin/python3', str(Path(__file__).with_name('check_linux_managed_terminal_relay.py')),
                                        str(relay), '--long-session'], environment=test_env)
                print(result.stdout[-8000:], end='', flush=True)
                print(result.stderr[-4000:], end='', file=sys.stderr, flush=True)
                require(result.returncode == 0 and result.stdout.count(': pass') == 1,
                        'managed relay did not preserve the active/suspended session across old deadlines: '
                        + (result.stdout + result.stderr)[-4000:])

                store_relay = Path(__file__).resolve().parents[1] / 'target/debug/examples/linux_managed_store_probe'
                result = owned_fixture(['/usr/bin/python3', str(Path(__file__).with_name('check_linux_managed_terminal_relay.py')),
                                        str(store_relay), '--store'], environment=test_env)
                print(result.stdout[-16000:], end='', flush=True)
                print(result.stderr[-8000:], end='', file=sys.stderr, flush=True)
                require(result.returncode == 0 and result.stdout.count(': pass') == 30,
                        'real Store terminal composition did not pass all 30 cases: '
                        + (result.stdout + result.stderr)[-4000:])

                for stopped_relay in (relay, store_relay):
                    for timeout_mode in ('--admission-stop-timeout', '--admission-background-timeout'):
                        result = owned_fixture(['/usr/bin/python3', str(Path(__file__).with_name('check_linux_managed_terminal_relay.py')),
                                                str(stopped_relay), timeout_mode], environment=test_env, seconds=40)
                        print(result.stdout[-8000:], end='', flush=True)
                        print(result.stderr[-4000:], end='', file=sys.stderr, flush=True)
                        require(result.returncode == 0 and result.stdout.count(': pass') == 1,
                                f'{timeout_mode} did not expire safely: '
                                + (result.stdout + result.stderr)[-4000:])

        finally:
            for connection in connections:
                connection.close()
            for descriptor in descriptors:
                os.close(descriptor)
            subprocess.run(admin_args + ['cleanup'] + identity_args, check=True, timeout=50)
    print('::notice title=Linux fixed-user activation cleanup::temporary socket, template units, root-owned Rust guardian image, service instances and fixture files removed', flush=True)


def main():
    args = sys.argv[1:]
    if len(args) == 5 and args[0] == '--admin':
        admin(args[1], Path(args[2]), args[3], args[4])
    elif args == ['--deny-other-user']:
        deny_other_user()
    else:
        require(not args, 'unexpected activation fixture arguments')
        suite()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        context, seen, detail = error, set(), []
        while context is not None and id(context) not in seen and len(detail) < 4:
            seen.add(id(context))
            detail.append(str(context)[-1000:])
            context = context.__cause__ or context.__context__
        diagnostic = json.dumps(' | earlier failure: '.join(detail), ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux fixed-user activation::' + diagnostic, flush=True)
        sys.exit(1)
