#!/usr/bin/env python3
"""Fixed-user activation experiment; disposable hosted CI only, never installation."""
import errno
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

from check_linux_managed_scope import check_controls, membership, private_directory, wait_for

PRESERVE = 'GITHUB_ACTIONS,RUNNER_ENVIRONMENT,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ASWP_CI_SOCKET_ACTIVATION'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


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


def ordinary_ids(uid, gid):
    uid, gid = int(uid), int(gid)
    require(0 < uid < 2**31 and 0 < gid < 2**31, 'ordinary target UID and GID required')
    return uid, gid


def unit_files(prefix, directory, uid, gid):
    uid, gid = ordinary_ids(uid, gid)
    script = Path(__file__).resolve()
    for path in (script, directory):
        require(path.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path))
                and '..' not in path.parts, 'fixture path cannot be represented as a fixed unit argument')
    require(re.fullmatch(r'aswp-activation-[0-9]{1,24}-[0-9]{1,8}', prefix), 'invalid fixture unit prefix')
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
TriggerLimitBurst=16
RemoveOnStop=yes
'''
    service_unit = f'''[Unit]
Description=AgentSwapper disposable fixed-user guardian
CollectMode=inactive-or-failed
[Service]
Type=exec
User={uid}
Group={gid}
ExecStart=/usr/bin/python3 {script} --service {directory} {uid} %n
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


def admin(verb, directory, uid, gid):
    prefix = fixture_prefix()
    require(os.geteuid() == 0 and verb in ('install', 'cleanup'), 'invalid fixture administrator role')
    uid, gid = ordinary_ids(uid, gid)
    private_directory(directory, uid)
    files = unit_files(prefix, directory, uid, gid)
    ownership = json.dumps({'uid': uid, 'gid': gid, 'directory': str(directory), 'units': files}, sort_keys=True)
    marker = Path('/run') / (prefix + '.owner')
    parent = Path('/run/systemd/system')
    metadata = parent.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0,
            'runtime unit directory is not root-owned and protected')
    if verb == 'install':
        require(not endpoint(prefix).exists(), 'fixture activation endpoint already exists')
        for name in files:
            require(not os.path.lexists(parent / name), 'fixture unit name already exists')
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(ownership)
        for name, contents in files.items():
            fd = os.open(parent / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
            with os.fdopen(fd, 'w') as stream:
                stream.write(contents)
        systemctl('daemon-reload')
        systemctl('start', prefix + '.socket')
        return
    if not os.path.lexists(marker):
        # Installation refused before reserving anything. Never stop or remove
        # a pre-existing unit merely because its name matches this fixture.
        return
    marker_meta = marker.lstat()
    require(stat.S_ISREG(marker_meta.st_mode) and marker_meta.st_uid == 0
            and marker_meta.st_mode & 0o077 == 0 and marker.read_text() == ownership,
            'fixture ownership marker is absent, changed or not protected')
    for name, contents in files.items():
        path = parent / name
        if os.path.lexists(path):
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and metadata.st_mode & 0o022 == 0 and path.read_text() == contents,
                    'fixture unit changed; refusing service control')
    # All names are reserved to this run. Stop activation before collecting its
    # service instances; no wildcard includes any unrelated unit prefix.
    systemctl('stop', prefix + '.socket', check=False)
    listing = systemctl('list-units', '--all', '--plain', '--no-legend', '--full', prefix + '@*.service')
    for row in listing.stdout.splitlines():
        name = row.split()[0]
        require(re.fullmatch(re.escape(prefix) + r'@[A-Za-z0-9_.:\\-]+\.service', name),
                'unexpected activation service name')
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
    require(not endpoint(prefix).exists(), 'activation endpoint survived cleanup')
    marker.unlink()


def service(directory, uid, unit):
    started = time.monotonic()
    uid = int(uid)
    require(os.getuid() == os.geteuid() == uid != 0, 'activated guardian is not the fixed ordinary user')
    private_directory(directory)
    require(re.fullmatch(r'aswp-activation-[0-9]{1,24}-[0-9]{1,8}@[A-Za-z0-9_.:\\-]+\.service', unit),
            'invalid activated fixture unit')
    invocation = os.environ.get('INVOCATION_ID', '')
    require(re.fullmatch(r'[0-9a-f]{32}', invocation) and invocation != '0' * 32,
            'activation did not supply an invocation identity')
    group = '/system.slice/' + unit
    require(membership() == group, 'activated guardian is outside its expected scope')
    check_controls(Path('/sys/fs/cgroup' + group))
    with socket.socket(fileno=os.dup(sys.stdin.fileno())) as connection:
        connection.settimeout(8)
        require(connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
                'activation control socket is not sequenced-packet')
        peer_pid, peer_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer_uid == uid and peer_pid > 0, 'activation client identity differs')
        request, ancillary, flags, _ = connection.recvmsg(6, 0)
        require(request in (b'GO\n', b'BIND\n') and not ancillary
                and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'invalid fixture activation request')
        report = {'unit': unit, 'invocation': invocation, 'pid': os.getpid(), 'uid': uid,
                  'group': group, 'peer_uid': peer_uid, 'peer_pid': peer_pid, 'started': started}
        if request == b'BIND\n':
            # The Rust observer authenticates this message's SCM_CREDENTIALS,
            # then binds the claimed invocation through the system manager.
            # This branch accepts no launch request and creates no worker.
            connection.sendall(json.dumps(report).encode() + b'\n')
            connection.settimeout(12)
            require(connection.recv(1) == b'', 'bind-only probe sent launch data')
            return
        run = directory / invocation
        run.mkdir(mode=0o700)
        subprocess.Popen(['/usr/bin/python3', str(Path(__file__).resolve()), '--writer', str(run)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, start_new_session=True)
        wait_for(lambda: (run / 'heartbeat').exists(), seconds=5)
        connection.sendall(json.dumps(report).encode() + b'\n')
        connection.settimeout(40)
        require(connection.recv(1) == b'', 'unexpected fixture activation command')
        (run / 'guardian-clean-eof').write_text(invocation)
    # Exiting the main service process lets KillMode=control-group retire its
    # detached writer. The client never sends a numeric process kill request.


def writer(directory):
    private_directory(directory)
    require(os.geteuid() != 0 and os.getsid(0) == os.getpid(), 'fixture writer is not an ordinary detached process')
    deadline = time.monotonic() + 60
    counter = 0
    while time.monotonic() < deadline:
        temporary = directory / 'heartbeat.tmp'
        temporary.write_text(str(counter))
        temporary.replace(directory / 'heartbeat')
        counter += 1
        time.sleep(0.02)
    (directory / 'voluntary-exit').write_text('deadline')


def deny_other_user():
    prefix = fixture_prefix()
    require(os.geteuid() == 0, 'separate-user probe requires the disposable fixture authority')
    target = endpoint(prefix)
    require(target.stat().st_uid != 65534, 'fixture owner conflicts with the negative-control UID')
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
    print('::notice title=Linux fixed-user activation::different ordinary UID refused at socket permission check', flush=True)


def activate(prefix, directory):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
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
        require(re.fullmatch(re.escape(prefix) + r'@[A-Za-z0-9_.:\\-]+\.service', report['unit'])
                and re.fullmatch(r'[0-9a-f]{32}', report['invocation'])
                and report['uid'] == report['peer_uid'] == os.getuid()
                and report['peer_pid'] == os.getpid() and report['pid'] > 1,
                'activation identities disagree')
        scope = Path('/sys/fs/cgroup/system.slice') / report['unit']
        require(report['group'] == '/system.slice/' + report['unit'], 'activation group disagrees')
        check_controls(scope)
        # Differential fixture metadata only; this is not the authenticated
        # production observer or a receipt that can authorize transfer.
        properties = systemctl('show', report['unit'], '--property=User,MainPID,InvocationID,Delegate,KillMode', '--no-pager')
        fields = dict(line.split('=', 1) for line in properties.stdout.splitlines())
        require(fields == {'User': str(os.getuid()), 'MainPID': str(report['pid']),
                           'InvocationID': report['invocation'], 'Delegate': 'no', 'KillMode': 'control-group'},
                'activated manager properties disagree')
        descriptor = os.open(scope, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        return connection, report, descriptor
    except BaseException:
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
                    and records[1]['retirement']['original_directory_removed'] is True
                    and records[1]['retirement']['main_pidfd_exited'] is True,
                    'Rust activation binding or retirement evidence differs')
            require(not any(directory.iterdir()), 'bind-only observation started a worker')
            print('::notice title=Linux activation binding::kernel message sender matched manager MainPID and invocation; original scope retired after disconnect; no launch data or worker', flush=True)
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
                    print('::notice title=Linux fixed-user activation::' + label + ' refused before worker creation', flush=True)
            faulty, faulty_report, faulty_fd = activate(prefix, directory)
            connections.append(faulty)
            descriptors.append(faulty_fd)
            live_before_disconnect(directory, faulty_report)
            faulty.sendall(b'X')
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
            print('::notice title=Linux activation EOF control::guardian error stopped its worker and removed scope but was refused as clean EOF evidence', flush=True)
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
            before = (directory / second_report['invocation'] / 'heartbeat').read_text()
            live_before_disconnect(directory, first_report)
            first.close()
            retired(directory, first_report, first_fd)
            wait_for(lambda: (directory / second_report['invocation'] / 'heartbeat').read_text() != before, seconds=3)
            require(Path('/sys/fs/cgroup' + second_report['group']).exists(), 'first disconnect retired the other connection')
            live_before_disconnect(directory, second_report)
            second.close()
            retired(directory, second_report, second_fd)
            print('::notice title=Linux fixed-user activation::two ordinary connections received distinct root-managed scopes; both refused migration writes; each guardian recorded clean client EOF before stopped detached writer and original scope removal; sibling continued; no production launch qualification', flush=True)
        finally:
            for connection in connections:
                connection.close()
            for descriptor in descriptors:
                os.close(descriptor)
            subprocess.run(admin_args + ['cleanup'] + identity_args, check=True, timeout=50)
    print('::notice title=Linux fixed-user activation cleanup::temporary socket, template units, service instances and fixture files removed', flush=True)


def main():
    args = sys.argv[1:]
    if len(args) == 4 and args[0] == '--service':
        service(Path(args[1]), args[2], args[3])
    elif len(args) == 2 and args[0] == '--writer':
        writer(Path(args[1]))
    elif len(args) == 5 and args[0] == '--admin':
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
        diagnostic = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux fixed-user activation::' + diagnostic, flush=True)
        sys.exit(1)
