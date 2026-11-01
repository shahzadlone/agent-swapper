#!/usr/bin/env python3
"""Connect the hosted fixed guardian to a relay inside newly created outer PTYs."""
import fcntl
from contextlib import closing
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import sqlite3
import uuid
import struct
import sys
import tempfile
import termios
import time

from check_linux_outer_terminal import OwnedPty


from check_linux_terminal_owner import fresh_observed

def environment():
    keys = ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'ASWP_CI_SOCKET_ACTIVATION',
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ASWP_ACTIVATION_PREFIX',
            'ASWP_CI_ACTIVATED_JOURNAL')
    values = {key: os.environ[key] for key in keys}
    assert values['GITHUB_ACTIONS'] == 'true' and values['RUNNER_ENVIRONMENT'] == 'github-hosted'
    assert values['ASWP_CI_SOCKET_ACTIVATION'] == values['ASWP_CI_ACTIVATED_JOURNAL'] == '1'
    assert values['ASWP_ACTIVATION_PREFIX'] == f"aswp-activation-{values['GITHUB_RUN_ID']}-{values['GITHUB_RUN_ATTEMPT']}"
    return values


def exec_observed(root, data, env):
    if env.get('ASWP_CI_EXEC_GATE') == '1':
        assert (root / 'exec-held').read_text() == str(data['target'])
        assert (root / 'spawn-observed').read_text() == f"fixed target PID: {data['target']}; outcome unresolved\n"
        status = Path(f"/proc/{data['target']}/status").read_text()
        assert re.search(r'^TracerPid:\s*0$', status, re.M)
    else:
        assert not (root / 'exec-held').exists() and not (root / 'spawn-observed').exists()


def state(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()[0]


def check_journal_history(connection, metadata, record, readiness):
    """Cross-check one snapshot; diagnostics here never grant runtime authority."""
    scope = json.loads(record[4])
    assert set(scope) == {'backend', 'id'} and scope['backend'] == 'linux_cgroup'
    assert str(uuid.UUID(scope['id'])) == scope['id'] and uuid.UUID(scope['id']).int != 0
    rows = connection.execute(
        "SELECT payload FROM event_log WHERE json_extract(payload,'$.id')=? ORDER BY sequence",
        (metadata['run'],)).fetchall()
    events = [json.loads(row[0]) for row in rows]
    expected = ['run_planned']
    if record[5] is not None:
        expected.append('linux_scope_bound')
    if record[6] is not None:
        expected.append('run_spawned')
    if record[2] is not None:
        expected.append('linux_scope_retired')
    assert [event['type'] for event in events] == expected, 'journal lifecycle order differs'
    planned = events[0]
    assert planned['profile'] == metadata['profile'] and planned['kind'] == 'run'
    assert planned['requires_spawn_observation'] is True and planned['local_scope'] == scope
    binding = None if record[5] is None else json.loads(record[5])
    if binding is None:
        assert record[2] is None and record[6] is None and not readiness
        return
    assert set(binding) == {'unit', 'invocation', 'user', 'guardian', 'device', 'inode'}
    for field in ('user', 'guardian', 'device', 'inode'):
        assert type(binding[field]) is int and binding[field] > 0
    assert binding['guardian'] > 1 and binding['user'] == os.getuid()
    invocation = binding['invocation']
    assert isinstance(invocation, list) and len(invocation) == 16 and any(invocation)
    assert all(type(byte) is int and 0 <= byte <= 255 for byte in invocation)
    invocation_hex = bytes(invocation).hex()
    prefix = os.environ['ASWP_ACTIVATION_PREFIX']
    assert re.fullmatch(r'aswp-activation-[0-9]{1,24}-[0-9]{1,8}', prefix)
    assert isinstance(binding['unit'], str) and re.fullmatch(
        re.escape(prefix) + r'@[0-9]+-[0-9]+-' + str(os.getuid()) + r'\.service', binding['unit'])
    assert events[1]['binding'] == binding, 'bound event differs from projection'
    for data in readiness.values():
        assert data['guardian'] == binding['guardian'] and data['invocation'] == invocation_hex
        assert type(data['target']) is int and data['target'] > 1
        if record[6] is not None:
            assert record[6] == data['target']
    if readiness:
        client = readiness.get('session-ready', readiness.get('ready'))
        assert type(client['pid']) is int and client['pid'] > 1
        assert binding['unit'].endswith(f"-{client['pid']}-{os.getuid()}.service")
    if record[6] is not None:
        assert events[2]['pid'] == record[6], 'spawn event differs from projection'
    if record[2] is not None:
        assert events[-1]['binding'] == binding and events[-1]['scope'] == scope['id']


def lease_path(root):
    metadata = root / 'journal.json'
    if not metadata.exists():
        return root / 'lease'
    data = json.loads(metadata.read_text())
    assert set(data) == {'profile', 'run'}
    for value in data.values():
        assert str(uuid.UUID(value)) == value
    database = root / 'state' / 'registry.sqlite3'
    audited = (root / 'journal-audited').exists()
    retired_before_read = (root / 'retired').exists()
    readiness = {name: json.loads((root / name).read_text())
                 for name in ('ready', 'session-ready') if (root / name).exists()}
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as connection, connection:
        # Event history and projection must describe the same committed WAL
        # snapshot even when the live consumer completes during this check.
        connection.execute('BEGIN')
        record = connection.execute('SELECT profile, exit_code, outcome, requires_spawn_observation, local_scope, linux_binding, observed_pid FROM runs WHERE id=?', (data['run'],)).fetchone()
        assert record is not None and record[0] == data['profile'] and record[1] is None and record[3] == 1
        assert record[2] in (None, 'local_scope_empty')
        if audited or retired_before_read:
            assert record[2] == 'local_scope_empty'
        check_journal_history(connection, data, record, readiness)
        assert connection.execute('PRAGMA quick_check').fetchone() == ('ok',)
    if (root / 'retired').exists():
        assert (root / 'journal-audited').read_text() == 'scope retired; target outcome unknown'
    return root / 'state' / 'locks' / (data['profile'] + '.lock')



def snapshot_matches(owned, root, name):
    snapshot = root / name
    owned.wait(lambda: snapshot.exists() and snapshot.read_text().endswith('\n'))
    before, actual = (root / 'before').read_text(), snapshot.read_text()
    assert before.endswith('\n'), f'incomplete original terminal snapshot: {before!r}'
    assert actual == before, f'terminal snapshots differ: before={before!r}; {name}={actual!r}'


def retired(owned, root):
    assert (root / 'retired').is_file() and (root / 'restored').is_file()
    assert 'outcome unresolved' in (root / 'intent').read_text()
    # No guardian or client copy may retain the original OFD lease afterwards.
    with lease_path(root).open('rb+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if owned.shell:
        # Bash readline changes terminal modes while displaying its prompt.
        # Compare the complete command-time snapshots on either side of the
        # relay; direct probes compare every original termios field instead.
        snapshot_matches(owned, root, 'after')
    else:
        assert termios.tcgetattr(owned.master) == owned.original


def target_command(owned, command, response):
    offset = len(owned.output)
    owned.send(command + b'\n')
    owned.wait(lambda: response in owned.output[offset:])


def direct(binary, scenario, env, owned_parent=False, fresh=False):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-relay-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, environment=dict(env, ASWP_ENTRY_UNTRUSTED_CANARY='must-not-cross'),
                         arguments=('--fresh-entry',) if fresh else ('--owned-parent',) if owned_parent else ())
        try:
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            if fresh:
                fresh_observed(root, data)
            exec_observed(root, data, env)
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
                if env.get('ASWP_CI_EXEC_GATE') == '1':
                    assert (root / 'observed-exit').read_text() == 'Code { code: 0 }'
                assert all(0 < int(value) <= 16384 for value in (root / 'buffers').read_text().split(':'))
            elif scenario == 'orphan-stop':
                owned.send(b'\x1a')
                owned.wait(lambda: (root / 'resumed-foreground').exists())
                assert (root / 'discarded-stop').exists() and not (root / 'continued').exists()
                owned.wait(lambda: state(data['target']) != 'T')
                target_command(owned, b'size', b'SIZE:24:80\r\n')
                owned.send(b'\x03')
                owned.finish(130 if env.get('ASWP_CI_EXEC_GATE') == '1' else 0)
            elif scenario == 'nested':
                target_command(owned, b'nested', b'NESTED-RUNNING:')
                owned.send(b'\x1a')
                owned.wait(lambda: b'NESTED-STOPPED:' in owned.output)
                assert not (root / 'restored-before-stop').exists()
                assert termios.tcgetattr(owned.master)[3] & (termios.ISIG | termios.ICANON | termios.ECHO) == 0
                target_command(owned, b'resume-nested', b'NESTED-DONE\r\n')
                owned.send(b'\x03')
                owned.finish(130 if env.get('ASWP_CI_EXEC_GATE') == '1' else 0)
            elif scenario == 'exit-code-7':
                assert env.get('ASWP_CI_EXEC_GATE') == '1'
                target_command(owned, b'exit-7', b'exit-7\r\n')
                owned.finish(7)
                assert (root / 'observed-exit').read_text() == 'Code { code: 7 }'
            elif scenario in ('delayed-final-drain', 'blocked-known-exit'):
                owned.send(b'tail-exit-7\n')
                owned.wait(lambda: (root / 'observed-exit').exists(), pump=False)
                assert (root / 'observed-exit').read_text() == 'Code { code: 7 }'
                assert not (root / 'drained').exists() and owned.poll() is None
                if scenario == 'delayed-final-drain':
                    time.sleep(3)
                    assert owned.poll() is None, 'known exit failed before final drain could recover'
                    owned.finish(7)
                    owned.wait(lambda: owned.output.count(b'x') >= 32769)
                    assert owned.output.count(b'x') == 32769  # command echo contains one x
                    assert (root / 'drained').exists() and not (root / 'output-truncated').exists()
                else:
                    owned.wait(lambda: owned.poll() is not None, seconds=10, pump=False)
                    owned.finish(7, pump=False)
                    assert (root / 'output-truncated').exists() and not (root / 'drained').exists()
            elif scenario == 'exit-record-error':
                marker_root = Path(os.environ['ASWP_ACTIVATION_DIRECTORY']) / data['invocation']
                (marker_root / 'target-exit').mkdir()
                owned.send(b'exit-7\n')
                owned.finish(7)
                assert (root / 'observed-exit').read_text() == 'Code { code: 7 }'
                assert (marker_root / 'guardian-exit-record-error').exists()
            elif scenario == 'target-realtime':
                assert env.get('ASWP_CI_EXEC_GATE') == '1'
                descriptor = os.pidfd_open(data['target'])
                try:
                    args = Path(f"/proc/{data['target']}/cmdline").read_bytes().split(b'\0')
                    assert args[1] == b'--activation-job-target'
                    assert Path(f"/proc/{data['target']}/cgroup").read_text() == Path(f"/proc/{data['guardian']}/cgroup").read_text()
                    assert not select.select([descriptor], [], [], 0)[0]
                    signal.pidfd_send_signal(descriptor, signal.SIGRTMIN)
                finally:
                    os.close(descriptor)
                owned.finish(128 + int(signal.SIGRTMIN))
                assert (root / 'observed-exit').read_text() == f'Signal {{ signal: {int(signal.SIGRTMIN)}, core_dumped: false }}'
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
            print(f'{"fresh-" if fresh else ""}{"exec-" if env.get("ASWP_CI_EXEC_GATE") == "1" else ""}managed-{"owned-" if owned_parent else ""}relay-{scenario}: pass', flush=True)
        finally:
            owned.close()


def shell_job(binary, raw_stop, env, owned_parent=False, fresh=False):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-relay-shell-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True, environment=env)
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            role = '--fresh-entry ' if fresh else '--owned-parent ' if owned_parent else ''
            owned.send(f'/usr/bin/stty -g > before.tmp && mv before.tmp before; {shlex.quote(str(binary))} {role}{shlex.quote(str(root))}\n'.encode())
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            if fresh:
                fresh_observed(root, data)
            exec_observed(root, data, env)
            offset = len(owned.output)
            owned.send(b'suspend\n' if raw_stop else b'\x1a')
            owned.wait(lambda: prompt in owned.output[offset:] and os.tcgetpgrp(owned.master) == owned.pid)
            assert (root / 'restored-before-stop').read_text() == str(int(signal.SIGTSTP))
            assert state(data['pid']) == state(data['target']) == 'T'
            if owned_parent:
                assert state(data['child']) == 'T' and (root / 'owner-restored-stop').exists()
            offset = len(owned.output)
            owned.send(b'bg\n')
            owned.wait(lambda: (root / 'continued').exists() and prompt in owned.output[offset:])
            assert not (root / 'resumed-foreground').exists() and state(data['target']) == 'T'
            owned.send(b'/usr/bin/stty -g > background-mode.tmp && mv background-mode.tmp background-mode\n')
            owned.wait(lambda: (root / 'background-mode').exists())
            snapshot_matches(owned, root, 'background-mode')
            fcntl.ioctl(owned.master, termios.TIOCSWINSZ, struct.pack('HHHH', 42, 111, 0, 0))
            owned.send(b'fg\n')
            owned.wait(lambda: (root / 'resumed-foreground').exists())
            assert os.tcgetpgrp(owned.master) == data['group']
            owned.wait(lambda: state(data['target']) != 'T')
            if raw_stop:
                owned.wait(lambda: b'RESUMED\r\n' in owned.output)
            target_command(owned, b'size', b'SIZE:42:111\r\n')
            offset = len(owned.output)
            owned.send(b'\x03')
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'retired').exists())
            owned.send(b'printf "%s" "$?" > exit-code\n')
            owned.wait(lambda: (root / 'exit-code').exists() and (root / 'exit-code').stat().st_size > 0)
            assert (root / 'exit-code').read_text() == ('130' if env.get('ASWP_CI_EXEC_GATE') == '1' else '0')
            owned.send(b'/usr/bin/stty -g > after.tmp && mv after.tmp after\n')
            owned.wait(lambda: (root / 'after').exists())
            snapshot_matches(owned, root, 'after')
            retired(owned, root)
            print(f'{"exec-" if env.get("ASWP_CI_EXEC_GATE") == "1" else ""}managed-{"owned-" if owned_parent else ""}relay-shell-{"raw-self-stop" if raw_stop else "typed-ctrl-z"}: pass', flush=True)
        finally:
            owned.close()


def stopped_exit(binary, scenario, env, owned_parent):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-stopped-exit-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True, environment=env)
        target_fd = None
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            role = '--owned-parent ' if owned_parent else ''
            owned.send(f'/usr/bin/stty -g > before.tmp && mv before.tmp before; {shlex.quote(str(binary))} {role}{shlex.quote(str(root))}\n'.encode())
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            exec_observed(root, data, env)
            target_fd = os.pidfd_open(data['target'])
            assert not select.select([target_fd], [], [], 0)[0]
            offset = len(owned.output)
            owned.send(b'\x1a')
            owned.wait(lambda: prompt in owned.output[offset:] and os.tcgetpgrp(owned.master) == owned.pid)
            assert state(data['target']) == state(data['pid']) == 'T'
            marker_root = Path(os.environ['ASWP_ACTIVATION_DIRECTORY']) / data['invocation']
            if scenario == 'resume-race':
                (marker_root / 'resume-hold').write_text('hold before original child wait')
                owned.send(b'fg\n')
                owned.wait(lambda: (marker_root / 'resume-held').exists())
            signal.pidfd_send_signal(target_fd, signal.SIGKILL)
            owned.wait(lambda: select.select([target_fd], [], [], 0)[0])
            if scenario == 'resume-race':
                (marker_root / 'resume-release').write_text('observe terminal wait')
            owned.wait(lambda: (marker_root / 'target-exit').exists())
            assert (marker_root / 'target-exit').read_text() == 'None:Some(9)'
            if scenario not in ('fg', 'resume-race'):
                offset = len(owned.output)
                owned.send(b'bg\n')
                owned.wait(lambda: (root / 'observed-exit').exists() and prompt in owned.output[offset:])
                owned.send(b'/usr/bin/stty -g > background-mode.tmp && mv background-mode.tmp background-mode\n')
                owned.wait(lambda: (root / 'background-mode').exists())
                snapshot_matches(owned, root, 'background-mode')
                assert not (root / 'resumed-foreground').exists()
                if scenario == 'bg-fg':
                    time.sleep(1)
                    assert not (root / 'retired').exists(), 'background drain did not wait for foreground'
            if scenario == 'bg-expire':
                owned.send(f'wait {data["pid"]}; printf "%s" "$?" > exit-code; /usr/bin/stty -g > after.tmp && mv after.tmp after\n'.encode())
                owned.wait(lambda: (root / 'after').exists(), seconds=12)
                assert (root / 'output-truncated').exists()
                if owned_parent:
                    assert (root / 'owner-background-exit').exists()
            else:
                offset = len(owned.output)
                if scenario != 'resume-race':
                    owned.send(b'fg\n')
                owned.wait(lambda: (scenario == 'resume-race' or prompt in owned.output[offset:]) and (root / 'retired').exists())
                owned.wait(lambda: os.tcgetpgrp(owned.master) == owned.pid)
                owned.send(b'printf "%s" "$?" > exit-code; /usr/bin/stty -g > after.tmp && mv after.tmp after\n')
                owned.wait(lambda: (root / 'after').exists())
                assert (root / 'drained').exists()
            assert (root / 'exit-code').read_text() == '137'
            assert (root / 'observed-exit').read_text() == 'Signal { signal: 9, core_dumped: false }'
            if scenario != 'resume-race':
                assert not (root / 'resumed-foreground').exists(), 'dead target was resumed'
            retired(owned, root)
            owned.send(b'exit\n')
            owned.wait(lambda: owned.poll() is not None)
            assert os.waitstatus_to_exitcode(owned.status) == 0
            print(f'exec-managed-stopped-exit-{scenario}-{"owned" if owned_parent else "direct"}: pass', flush=True)
        finally:
            if target_fd is not None:
                os.close(target_fd)
            owned.close()


def failures(binary, scenario, env, owned_parent=False):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-relay-failure-') as path:
        root = Path(path)
        parent_loss = scenario == 'stopped-parent-loss'
        assert not parent_loss or owned_parent
        owned = OwnedPty(binary, root, environment=env, arguments=('--owned-parent',) if owned_parent else (),
                         shell=parent_loss, subreaper_shell=binary.with_name('terminal_owner_shell') if parent_loss else None)
        descriptors = []
        try:
            if parent_loss:
                prompt = b'__ASWP_OUTER_PROMPT__ '
                owned.wait(lambda: prompt in owned.output)
                assert (root / 'subreaper-shell').read_text() == str(owned.pid)
                owned.send(f'/usr/bin/stty -g > before.tmp && mv before.tmp before; {shlex.quote(str(binary))} --owned-parent {shlex.quote(str(root))}\n'.encode())
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            exec_observed(root, data, env)
            relay_fd = None
            if owned_parent:
                relay_fd = os.pidfd_open(data['child'])
                descriptors.append(relay_fd)
                relay_stat = Path(f"/proc/{data['child']}/stat").read_text().rsplit(') ', 1)[1].split()
                assert int(relay_stat[1]) == int(relay_stat[2]) == data['pid']
                assert os.path.samefile(f"/proc/{data['child']}/exe", binary)
            target_command(owned, b'spawn', b'CHILD:')
            owned.wait(lambda: re.search(rb'CHILD:([0-9]+)\r\n', owned.output) is not None)
            descendant = int(re.search(rb'CHILD:([0-9]+)\r\n', owned.output)[1])
            group = Path(f"/proc/{data['guardian']}/cgroup").read_text().strip()
            assert group.startswith('0::/system.slice/' + env['ASWP_ACTIVATION_PREFIX'] + '@')
            group_path = Path('/sys/fs/cgroup' + group.removeprefix('0::'))
            scope_fd = os.open(group_path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            descriptors.append(scope_fd)
            pidfds = {}
            for pid in (data['guardian'], data['target'], descendant):
                descriptor = os.pidfd_open(pid)
                descriptors.append(descriptor)
                assert not select.select([descriptor], [], [], 0)[0]
                assert Path(f'/proc/{pid}/cgroup').read_text().strip() == group
                pidfds[pid] = descriptor
            desc_stat = Path(f'/proc/{descendant}/stat').read_text().rsplit(') ', 1)[1].split()
            assert int(desc_stat[1]) == int(desc_stat[2]) == data['target']
            status = Path(f'/proc/{descendant}/status').read_text()
            assert int(re.search(r'^SigBlk:\s*([0-9a-f]+)$', status, re.M)[1], 16) & 1
            marker_root = Path(os.environ['ASWP_ACTIVATION_DIRECTORY']) / data['invocation']
            heartbeat = marker_root / 'descendant-heartbeat'
            before = heartbeat.read_text()
            owned.wait(lambda: heartbeat.read_text() != before)
            if parent_loss:
                assert data['session'] == owned.pid and data['group'] != owned.pid
                offset = len(owned.output)
                owned.send(b'\x1a')
                owned.wait(lambda: prompt in owned.output[offset:] and (root / 'owner-restored-stop').exists())
                for pid in (data['pid'], data['child'], data['target'], descendant):
                    assert state(pid) == 'T'
                signal.pidfd_send_signal(owned.probe_fd, signal.SIGKILL)
                # No continuation is sent, and same-session subreaper adoption
                # prevents orphan-group SIGCONT from rescuing a stopped relay.
                owned.wait(lambda: select.select([relay_fd], [], [], 0)[0])
                assert select.select([owned.probe_fd], [], [], 0)[0]
                assert not (root / 'retired').exists() and not (root / 'restored').exists()
                assert not (root / 'owner-restored-exit').exists()
                owned.send(b'/usr/bin/stty -g > after-parent-loss.tmp && mv after-parent-loss.tmp after-parent-loss\n')
                owned.wait(lambda: (root / 'after-parent-loss').exists())
                snapshot_matches(owned, root, 'after-parent-loss')
                assert os.tcgetpgrp(owned.master) == owned.pid
            elif scenario == 'outer-hangup':
                os.close(owned.master)
                owned.master = None
                owned.wait(lambda: owned.poll() is not None, pump=False)
                assert os.waitstatus_to_exitcode(owned.status) == -signal.SIGHUP
                assert (root / 'retired').exists()
                assert (root / 'restoration-unavailable').read_text() == 'owned outer terminal disconnected'
                assert not (root / 'restored').exists()
            elif scenario == 'client-kill':
                if owned_parent:
                    signal.pidfd_send_signal(relay_fd, signal.SIGKILL)
                else:
                    os.kill(owned.pid, signal.SIGKILL)  # Original unreaped owned child.
                owned.wait(lambda: owned.poll() is not None, pump=False)
                assert os.waitstatus_to_exitcode(owned.status) == -signal.SIGKILL
                assert not (root / 'restored').exists() and not (root / 'retired').exists()
                if owned_parent:
                    assert (root / 'owner-restored-exit').read_text() == 'None:Some(9)'
                    assert termios.tcgetattr(owned.master) == owned.original
                else:
                    # No destructor can execute after SIGKILL. With no surviving
                    # owner this direct test terminal remains raw.
                    assert termios.tcgetattr(owned.master)[3] & (termios.ICANON | termios.ECHO | termios.ISIG) == 0
            elif scenario == 'external-stop-refusal':
                outer = os.pidfd_open(owned.pid)
                descriptors.append(outer)
                signal.pidfd_send_signal(outer, signal.SIGTSTP)
                owned.finish(125)
                retired(owned, root)
                assert (root / 'relay-error').read_text() == 'external suspension is unsupported for an active managed target'
            elif scenario == 'unknown-exit':
                assert env.get('ASWP_CI_EXEC_GATE') == '1'
                signal.pidfd_send_signal(pidfds[data['guardian']], signal.SIGKILL)
                owned.finish(125)
                assert (root / 'retired').exists() and (root / 'restored').exists()
                assert (root / 'target-outcome-unresolved').read_text() == 'no authenticated target exit'
                assert not (root / 'observed-exit').exists()
            elif scenario == 'blocked-drain':
                owned.send(b'flood\n')
                owned.wait(lambda: (root / 'backpressure').exists(), pump=False)
                signal.pidfd_send_signal(pidfds[data['guardian']], signal.SIGKILL)
                owned.finish(125, pump=False)
                assert (root / 'retired').exists() and (root / 'restored').exists()
                assert (root / 'relay-error').read_text() == 'terminal output drain remained blocked'
            else:
                raise AssertionError('unknown relay failure')
            owned.wait(lambda: all(select.select([descriptor], [], [], 0)[0] for descriptor in pidfds.values()), pump=False)
            owned.wait(lambda: not group_path.exists(), pump=False)
            assert not group_path.exists(), 'original managed scope survived client/terminal loss'
            try:
                descriptor = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scope_fd)
            except FileNotFoundError:
                pass
            else:
                os.close(descriptor)
                raise AssertionError('retained original scope is still active')
            before = heartbeat.read_text()
            time.sleep(0.1)
            assert heartbeat.read_text() == before and not (marker_root / 'descendant-voluntary-exit').exists()
            with lease_path(root).open('rb+') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(f'{"exec-" if env.get("ASWP_CI_EXEC_GATE") == "1" else ""}managed-{"owned-" if owned_parent else ""}relay-{scenario}: pass (scope cleanup; restoration requires surviving owner)', flush=True)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            owned.close()


def admission(binary, phase, scenario, env, owned_parent):
    """Queue cancellation at a real send boundary, with original scope witnesses."""
    with tempfile.TemporaryDirectory(prefix='aswp-managed-admission-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, environment=dict(env, ASWP_CI_ADMISSION_HOLD=phase),
                         arguments=('--owned-parent',) if owned_parent else ())
        descriptors = []
        try:
            owned.wait(lambda: (root / 'admission-held').exists())
            assert (root / 'admission-held').read_text() == phase
            data = json.loads((root / ('session-ready' if owned_parent else 'ready')).read_text())
            assert data['group'] == data['session'] == owned.pid == os.tcgetpgrp(owned.master)
            assert termios.tcgetattr(owned.master) == owned.original
            if owned_parent:
                stat = Path(f"/proc/{data['pid']}/stat").read_text().rsplit(') ', 1)[1].split()
                assert int(stat[1]) == int(stat[2]) == owned.pid
            else:
                assert data['pid'] == owned.pid
            assert os.path.samefile(f"/proc/{data['pid']}/exe", binary)
            relay_fd = os.pidfd_open(data['pid'])
            descriptors.append(relay_fd)
            group = Path(f"/proc/{data['guardian']}/cgroup").read_text().strip()
            assert group.startswith('0::/system.slice/' + env['ASWP_ACTIVATION_PREFIX'] + '@')
            scope_path = Path('/sys/fs/cgroup' + group.removeprefix('0::'))
            scope_fd = os.open(scope_path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            descriptors.append(scope_fd)
            pidfds = []
            for pid in (data['guardian'], data['target']):
                fd = os.pidfd_open(pid)
                descriptors.append(fd)
                pidfds.append(fd)
                assert not select.select([fd], [], [], 0)[0]
                assert Path(f'/proc/{pid}/cgroup').read_text().strip() == group
            marker_root = Path(os.environ['ASWP_ACTIVATION_DIRECTORY']) / data['invocation']
            assert not (marker_root / 'final-exec').exists()
            expected = 125
            if scenario in ('term', 'ctrl-c'):
                expected_signal = signal.SIGTERM if scenario == 'term' else signal.SIGINT
                expected = -expected_signal
                if scenario == 'ctrl-c':
                    # The outer terminal is still cooked: this is a terminal
                    # generated interrupt to the actual foreground job group.
                    owned.send(b'\x03')
                else:
                    signal.pidfd_send_signal(relay_fd, expected_signal)
                def pending():
                    status = Path(f"/proc/{data['pid']}/status").read_text()
                    bits = [int(x, 16) for x in re.findall(r'^(?:SigPnd|ShdPnd):\s*([0-9a-f]+)$', status, re.M)]
                    return any(value & (1 << (int(expected_signal) - 1)) for value in bits)
                owned.wait(pending)
            elif scenario == 'intent-error':
                assert phase == 'go'
                (root / 'intent').write_text('existing intent canary')
            elif scenario == 'spawn-error':
                assert phase == 'release'
                (root / 'spawn-observed').write_text('existing spawn canary')
            elif scenario == 'ready-error':
                assert phase == 'release'
                # Fail a marker after raw entry; cleanup must still restore
                # modes and observe retirement of the original scope.
                (root / 'relay-ready').mkdir()
            else:
                raise AssertionError('unknown admission scenario')
            (root / 'admission-release').write_text('release fixture barrier')
            owned.finish(expected)
            assert (root / 'retired').exists() and not (root / 'retirement-unresolved').exists()
            if scenario == 'ready-error':
                assert (root / 'relay-error').exists() and (root / 'restored').exists()
            else:
                assert (root / 'admission-error').exists()
                assert not (root / 'relay-ready').exists()
                assert not (marker_root / 'final-exec').exists(), 'cancelled/failed admission ran target instructions'
            if owned_parent:
                assert (root / 'owner-restored-exit').exists()
            owned.wait(lambda: all(select.select([fd], [], [], 0)[0] for fd in pidfds), pump=False)
            owned.wait(lambda: not scope_path.exists(), pump=False)
            try:
                fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scope_fd)
            except FileNotFoundError:
                pass
            else:
                os.close(fd)
                raise AssertionError('original admission scope remains active')
            with lease_path(root).open('rb+') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if scenario == 'intent-error':
                assert (root / 'intent').read_text() == 'existing intent canary'
            elif scenario == 'spawn-error':
                assert (root / 'spawn-observed').read_text() == 'existing spawn canary'
            elif phase == 'go':
                assert not (root / 'intent').exists()
            else:
                assert 'outcome unresolved' in (root / 'intent').read_text()
            if scenario in ('term', 'ctrl-c'):
                assert (root / 'spawn-observed').exists() == (phase == 'release-send')
            print(f'exec-managed-admission-{phase}-{scenario}-{"owned" if owned_parent else "direct"}: pass', flush=True)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            owned.close()


def startup_stop(binary, phase, env, expire=False, background=False, restop=False):
    assert not restop or (background and not expire)
    with tempfile.TemporaryDirectory(prefix='aswp-managed-startup-stop-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True, environment=dict(env, ASWP_CI_ADMISSION_HOLD=phase))
        descriptors = []
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            owned.send(f'/usr/bin/stty -g > before.tmp && mv before.tmp before; {shlex.quote(str(binary))} --owned-parent {shlex.quote(str(root))}\n'.encode())
            owned.wait(lambda: (root / 'admission-held').exists())
            data = json.loads((root / 'session-ready').read_text())
            parent = data['group']
            owned.probe_fd = os.pidfd_open(parent)
            relay_fd = os.pidfd_open(data['pid'])
            descriptors.append(relay_fd)
            def job_states():
                def diagnostic():
                    details = {}
                    for name in ('admission-error', 'relay-error', 'retirement-unresolved',
                                 'owner-background-stop', 'owner-background-exit'):
                        marker = root / name
                        if marker.is_file():
                            with marker.open('rb') as stream:
                                details[name] = stream.read(2048).decode(errors='replace')
                    return f'admission job ended unexpectedly: phase={phase}, background={background}, expire={expire}, restop={restop}, diagnostics={details!r}'
                assert not select.select([owned.probe_fd, relay_fd], [], [], 0)[0], diagnostic()
                try:
                    return state(parent), state(data['pid'])
                except FileNotFoundError as error:
                    raise AssertionError(diagnostic()) from error
            assert os.tcgetpgrp(owned.master) == parent and os.path.samefile(f'/proc/{parent}/exe', binary)
            stat = Path(f'/proc/{parent}/stat').read_text().rsplit(') ', 1)[1].split()
            assert int(stat[1]) == owned.pid
            assert not (root / 'child-ready').exists()
            marker_root = Path(os.environ['ASWP_ACTIVATION_DIRECTORY']) / data['invocation']
            group = Path(f"/proc/{data['guardian']}/cgroup").read_text().strip()
            assert group.startswith('0::/system.slice/' + env['ASWP_ACTIVATION_PREFIX'] + '@')
            scope_path = Path('/sys/fs/cgroup' + group.removeprefix('0::'))
            scope_fd = os.open(scope_path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            descriptors.append(scope_fd)
            pidfds = []
            for pid in (data['guardian'], data['target']):
                fd = os.pidfd_open(pid)
                descriptors.append(fd)
                pidfds.append(fd)
                assert not select.select([fd], [], [], 0)[0]
                assert Path(f'/proc/{pid}/cgroup').read_text().strip() == group
            offset = len(owned.output)
            owned.send(b'\x1a')
            def stop_pending():
                status = Path(f"/proc/{data['pid']}/status").read_text()
                bits = [int(x, 16) for x in re.findall(r'^(?:SigPnd|ShdPnd):\s*([0-9a-f]+)$', status, re.M)]
                return any(value & (1 << (int(signal.SIGTSTP) - 1)) for value in bits)
            owned.wait(stop_pending)
            (root / 'admission-release').write_text('observe cooked stop before control release')
            owned.wait(lambda: prompt in owned.output[offset:] and os.tcgetpgrp(owned.master) == owned.pid)
            assert job_states() == ('T', 'T')
            assert (root / 'owner-restored-stop').exists() and not (marker_root / 'final-exec').exists()
            owned.send(b'/usr/bin/stty -g > paused-mode.tmp && mv paused-mode.tmp paused-mode\n')
            owned.wait(lambda: (root / 'paused-mode').exists() and (root / 'paused-mode').stat().st_size > 0)
            snapshot_matches(owned, root, 'paused-mode')
            if background:
                offset = len(owned.output)
                owned.send(b'bg\n')
                owned.wait(lambda: prompt in owned.output[offset:] and all(value != 'T' for value in job_states()))
                owned.send(b'/usr/bin/stty -g > background-mode.tmp && mv background-mode.tmp background-mode\n')
                snapshot_matches(owned, root, 'background-mode')
                time.sleep(0.4)
                assert not (root / 'retired').exists() and not (marker_root / 'final-exec').exists(), 'background continuation released admission'
                assert os.tcgetpgrp(owned.master) == owned.pid
                if restop:
                    offset = len(owned.output)
                    owned.send(b'kill -TSTP %1\n')
                    def stopped_again():
                        assert not select.select([owned.probe_fd], [], [], 0)[0], 'background re-stop killed the original owner'
                        return prompt in owned.output[offset:] and job_states() == ('T', 'T')
                    owned.wait(stopped_again)
                    assert (root / 'owner-background-stop').exists()
                    assert not (root / 'retired').exists() and not (marker_root / 'final-exec').exists()
                    owned.send(b'/usr/bin/stty -g > restopped-mode.tmp && mv restopped-mode.tmp restopped-mode\n')
                    snapshot_matches(owned, root, 'restopped-mode')
                    assert os.tcgetpgrp(owned.master) == owned.pid
            if expire and not background:
                # The client remains stopped; the guardian's own original
                # admission deadline must retire the scope without client help.
                owned.wait(lambda: all(select.select([fd], [], [], 0)[0] for fd in pidfds), seconds=20)
                owned.wait(lambda: not scope_path.exists())
                assert job_states() == ('T', 'T')
                assert not (root / 'retired').exists() and not (marker_root / 'final-exec').exists()
                try:
                    fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scope_fd)
                except FileNotFoundError:
                    pass
                else:
                    os.close(fd)
                    raise AssertionError('original stopped admission scope still exists')
            offset = len(owned.output)
            if expire and background:
                owned.wait(lambda: select.select([owned.probe_fd], [], [], 0)[0] and (root / 'retired').exists(), seconds=18)
                assert all(select.select([fd], [], [], 0)[0] for fd in pidfds)
                assert (root / 'owner-background-exit').exists()
                assert not (marker_root / 'final-exec').exists() and not scope_path.exists()
                assert os.tcgetpgrp(owned.master) == owned.pid
                owned.send(f'wait {parent}; printf "%s" "$?" > exit-code; /usr/bin/stty -g > after.tmp && mv after.tmp after\n'.encode())
            else:
                owned.send(b'fg\n')
            if not expire:
                os.close(owned.probe_fd)
                owned.probe_fd = None
                ready = owned.ready(greeting=b'\x1b[0m\r\n')
                exec_observed(root, ready, env)
                target_command(owned, b'finish', 'FINAL:\x1b[34m→\x1b[0m\r\n'.encode())
            if not (expire and background):
                owned.wait(lambda: prompt in owned.output[offset:] and (root / 'retired').exists())
                owned.send(b'printf "%s" "$?" > exit-code; /usr/bin/stty -g > after.tmp && mv after.tmp after\n')
            owned.wait(lambda: (root / 'after').exists() and (root / 'after').stat().st_size > 0)
            assert (root / 'exit-code').read_text() == ('125' if expire else '0')
            if expire:
                assert not (marker_root / 'final-exec').exists() and (root / 'admission-error').exists()
                if background:
                    try:
                        fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=scope_fd)
                    except FileNotFoundError:
                        pass
                    else:
                        os.close(fd)
                        raise AssertionError('original background admission scope still exists')
                with lease_path(root).open('rb+') as lease:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                snapshot_matches(owned, root, 'after')
            else:
                retired(owned, root)
            owned.send(b'exit\n')
            owned.wait(lambda: owned.poll() is not None)
            assert os.waitstatus_to_exitcode(owned.status) == 0
            print(f'{"exec" if env.get("ASWP_CI_EXEC_GATE") == "1" else "job"}-managed-startup-stop-{phase}-{"background-" if background else ""}{"restopped-" if restop else ""}{"expired" if expire else "resumed"}: pass', flush=True)
        finally:
            for fd in descriptors:
                os.close(fd)
            owned.close()


def long_session(binary, env):
    with tempfile.TemporaryDirectory(prefix='aswp-managed-long-') as path:
        root = Path(path)
        owned = OwnedPty(binary, root, shell=True, environment=env)
        try:
            prompt = b'__ASWP_OUTER_PROMPT__ '
            owned.wait(lambda: prompt in owned.output)
            owned.send(f'/usr/bin/stty -g > before.tmp && mv before.tmp before; {shlex.quote(str(binary))} --owned-parent {shlex.quote(str(root))}\n'.encode())
            data = owned.ready(greeting=b'\x1b[0m\r\n')
            exec_observed(root, data, env)
            started = time.monotonic()
            # Cross the old absolute admission deadline while still active.
            owned.wait(lambda: time.monotonic() - started >= 15, seconds=18)
            assert owned.poll() is None and not (root / 'retired').exists()
            target_command(owned, b'size', b'SIZE:24:80\r\n')
            offset = len(owned.output)
            owned.send(b'\x1a')
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'owner-restored-stop').exists())
            assert state(data['pid']) == state(data['child']) == state(data['target']) == 'T'
            offset = len(owned.output)
            owned.send(b'bg\n')
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'continued').exists())
            # Cross the old 25/30/35-second fixture lifetimes while paused.
            owned.wait(lambda: time.monotonic() - started >= 38, seconds=27)
            assert state(data['target']) == 'T' and not (root / 'resumed-foreground').exists()
            assert not (root / 'retired').exists() and os.tcgetpgrp(owned.master) == owned.pid
            owned.send(b'/usr/bin/stty -g > during-long-stop.tmp && mv during-long-stop.tmp during-long-stop\n')
            owned.wait(lambda: (root / 'during-long-stop').exists())
            snapshot_matches(owned, root, 'during-long-stop')
            owned.send(b'fg\n')
            owned.wait(lambda: (root / 'resumed-foreground').exists() and state(data['target']) != 'T')
            target_command(owned, b'size', b'SIZE:24:80\r\n')
            offset = len(owned.output)
            target_command(owned, b'finish', 'FINAL:\x1b[34m→\x1b[0m\r\n'.encode())
            owned.wait(lambda: prompt in owned.output[offset:] and (root / 'retired').exists())
            owned.send(b'/usr/bin/stty -g > after.tmp && mv after.tmp after\n')
            owned.wait(lambda: (root / 'after').exists())
            retired(owned, root)
            assert (root / 'observed-exit').read_text() == 'Code { code: 0 }'
            assert time.monotonic() - started >= 38
            print('exec-managed-long-session: pass (active after admission timeout, resumed after 38 seconds, original modes and scope retired)', flush=True)
        finally:
            owned.close()


def main():
    assert sys.platform == 'linux' and (len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[2] in ('--long-session', '--store', '--store-refusal', '--admission-stop-timeout', '--admission-background-timeout')))
    binary = Path(sys.argv[1]).resolve(strict=True)
    if len(sys.argv) == 3 and sys.argv[2] == '--store-refusal':
        with tempfile.TemporaryDirectory(prefix='aswp-store-refusal-') as path:
            root = Path(path)
            owned = OwnedPty(binary, root, environment={'ASWP_ACTIVATION_PREFIX': 'aswp-activation-0-0', 'ASWP_CI_EXEC_GATE': '1'})
            try:
                owned.finish(125)
                assert not (root / 'state').exists() and not (root / 'journal.json').exists()
                assert not (root / 'ready').exists()
                print('Store terminal consumer refuses ordinary host before registry or manager access: pass', flush=True)
            finally:
                owned.close()
        return
    env = environment()
    if len(sys.argv) == 3:
        exec_env = dict(env, ASWP_CI_EXEC_GATE='1')
        if sys.argv[2] == '--long-session':
            long_session(binary, exec_env)
        elif sys.argv[2] in ('--admission-stop-timeout', '--admission-background-timeout'):
            startup_stop(binary, 'release-send', exec_env, expire=True, background=sys.argv[2] == '--admission-background-timeout')
        else:
            for scenario in ('bytes-resize-tail', 'exit-code-7', 'target-realtime',
                             'delayed-final-drain', 'blocked-known-exit', 'flood-term'):
                direct(binary, scenario, exec_env, True)
            direct(binary, 'bytes-resize-tail', exec_env, True, fresh=True)
            shell_job(binary, False, exec_env, True, fresh=True)
            for scenario in ('fg', 'bg-fg', 'bg-expire', 'resume-race'):
                stopped_exit(binary, scenario, exec_env, True)
            for scenario in ('unknown-exit', 'client-kill', 'outer-hangup', 'external-stop-refusal'):
                failures(binary, scenario, exec_env, True)
            for phase in ('go-send', 'release-send'):
                for scenario in ('term', 'ctrl-c'):
                    admission(binary, phase, scenario, exec_env, True)
            for phase, scenario in (('go', 'intent-error'), ('release', 'spawn-error'), ('release', 'ready-error')):
                admission(binary, phase, scenario, exec_env, True)
            for phase in ('go-send', 'release-send', 'raw-entry'):
                startup_stop(binary, phase, exec_env)
                startup_stop(binary, phase, exec_env, background=True)
            startup_stop(binary, 'release-send', exec_env, background=True, restop=True)
            print('::notice::real Store terminal composition: 30 cases passed with actual profile leases and durable run observations; retirement preserves unresolved journal policy', flush=True)
        return
    for owned_parent in (False, True):
        for scenario in ('bytes-resize-tail', 'orphan-stop', 'nested', 'flood-term'):
            direct(binary, scenario, env, owned_parent)
        shell_job(binary, False, env, owned_parent)
        shell_job(binary, True, env, owned_parent)
        for scenario in ('outer-hangup', 'client-kill', 'blocked-drain'):
            failures(binary, scenario, env, owned_parent)
    failures(binary, 'stopped-parent-loss', env, owned_parent=True)
    exec_env = dict(env, ASWP_CI_EXEC_GATE='1')
    for owned_parent in (False, True):
        failures(binary, 'external-stop-refusal', exec_env, owned_parent)
    for scenario in ('bytes-resize-tail', 'orphan-stop', 'nested', 'flood-term', 'exit-code-7', 'target-realtime'):
        direct(binary, scenario, exec_env, True)
    for scenario in ('delayed-final-drain', 'blocked-known-exit', 'exit-record-error'):
        direct(binary, scenario, exec_env, True)
    for owned_parent in (False, True):
        for scenario in ('fg', 'bg-fg', 'bg-expire', 'resume-race'):
            stopped_exit(binary, scenario, exec_env, owned_parent)
    for raw_stop in (False, True):
        shell_job(binary, raw_stop, exec_env, True)
    for scenario in ('outer-hangup', 'client-kill', 'blocked-drain', 'stopped-parent-loss', 'unknown-exit'):
        failures(binary, scenario, exec_env, True)
    for owned_parent in (False, True):
        for phase in ('go', 'go-send', 'release', 'release-send'):
            admission(binary, phase, 'term', exec_env, owned_parent)
    for phase in ('go-send', 'release-send'):
        admission(binary, phase, 'ctrl-c', exec_env, True)
    for phase, scenario, owned_parent in (('go', 'intent-error', False),
                                         ('release', 'spawn-error', True),
                                         ('release', 'ready-error', True)):
        admission(binary, phase, scenario, exec_env, owned_parent)
    direct(binary, 'bytes-resize-tail', exec_env, True, fresh=True)
    shell_job(binary, False, exec_env, True, fresh=True)
    for phase in ('go-send', 'release-send', 'raw-entry'):
        startup_stop(binary, phase, exec_env)
        startup_stop(binary, phase, exec_env, background=True)
    startup_stop(binary, 'release-send', exec_env, background=True, restop=True)
    startup_stop(binary, 'raw-entry', env)
    print('::notice::managed two-terminal relay: sixty-eight owned-PTY cases passed, including admission withdrawal, stopped death and bounded final output; stopped parent loss under a same-session subreaper retires relay and original scope without client cleanup; no production custody, exec/exit receipt, or provider qualification', flush=True)


if __name__ == '__main__':
    main()
