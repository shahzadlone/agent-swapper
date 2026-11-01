"""Guard and fixed-user unit-rendering checks; no privileged operations."""
from pathlib import Path
from contextlib import ExitStack
import hashlib
import json
import os
import select
import stat
import socket
import tempfile
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_linux_socket_activation as probe


class ActivationTests(unittest.TestCase):
    def test_template_control_restores_mode_on_timeout_and_unexpected_success(self):
        refused = SimpleNamespace(returncode=125, stdout='', stderr='installed file is not a root-owned protected regular file')
        for failure in ('timeout', 'success', 'connected', 'none'):
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, ASWP_MANAGED_OBSERVER='/tmp/fixed-observer'))
                stack.enter_context(patch.object(Path, 'is_file', return_value=True))
                stack.enter_context(patch.object(Path, 'read_text', return_value='owned template'))
                stack.enter_context(patch.object(probe.os, 'open', return_value=77))
                stack.enter_context(patch.object(probe.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)))
                chmod = stack.enter_context(patch.object(probe.os, 'fchmod'))
                close = stack.enter_context(patch.object(probe.os, 'close'))
                effective = stack.enter_context(patch.object(probe, 'effective_unit'))
                before = {'NAccepted': '3', 'NConnections': '0'}
                after = {'NAccepted': '4' if failure == 'connected' else '3', 'NConnections': '0'}
                stack.enter_context(patch.object(probe, 'unit_properties', side_effect=[before, after]))
                run = stack.enter_context(patch.object(probe.subprocess, 'run', return_value=refused))
                if failure == 'timeout':
                    run.side_effect = probe.subprocess.TimeoutExpired('observer', 12)
                    expected = self.assertRaises(probe.subprocess.TimeoutExpired)
                elif failure == 'success':
                    run.return_value = SimpleNamespace(returncode=0, stdout='', stderr='')
                    expected = self.assertRaisesRegex(RuntimeError, 'did not refuse')
                elif failure == 'connected':
                    expected = self.assertRaisesRegex(RuntimeError, 'connected before refusing')
                else:
                    expected = ExitStack()
                with expected:
                    probe.template_refusal(Path('/run/systemd/system/aswp@.service'), 'owned template', 'aswp', 1000, 1000)
                self.assertEqual([call.args for call in chmod.call_args_list], [(77, 0o664), (77, 0o644)])
                close.assert_called_once_with(77)
                if failure == 'none':
                    effective.assert_called_once()
                else:
                    effective.assert_not_called()

    def test_owned_fixture_timeout_stops_grandchild_and_keeps_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / 'child.pid'
            source = """import pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])
path = pathlib.Path(sys.argv[1])
pending = path.with_suffix('.tmp')
pending.write_text(str(child.pid))
pending.replace(path)
print('fixture-timeout-diagnostic', flush=True)
time.sleep(20)
"""
            errors = []
            def invoke():
                try:
                    probe.owned_fixture([sys.executable, '-c', source, str(pid_path)], dict(os.environ), seconds=2)
                except RuntimeError as error:
                    errors.append(str(error))
            worker = threading.Thread(target=invoke)
            worker.start()
            deadline = time.monotonic() + 1.5
            while not pid_path.exists():
                self.assertLess(time.monotonic(), deadline, 'grandchild did not start')
                time.sleep(0.01)
            descriptor = os.pidfd_open(int(pid_path.read_text()))
            try:
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(errors), 1)
                self.assertIn('owned activation test group timed out', errors[0])
                self.assertIn('fixture-timeout-diagnostic', errors[0])
                poller = select.poll()
                poller.register(descriptor, select.POLLIN)
                self.assertTrue(poller.poll(1000), 'owned grandchild survived timeout cleanup')
            finally:
                os.close(descriptor)

    def test_partial_file_creation_rolls_back_only_exclusively_created_inodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker, image = directory / 'owner', directory / 'guardian'
            unrelated = directory / 'existing'
            unrelated.write_text('keep')
            created = []
            probe.create_owned_file(marker, b'ownership', 0o600, created)
            with patch.object(probe.os, 'fchmod', side_effect=OSError('injected chmod failure')):
                with self.assertRaises(OSError):
                    probe.create_owned_file(image, b'partial image', 0o755, created)
            probe.rollback_created(created)
            self.assertFalse(marker.exists())
            self.assertFalse(image.exists())
            self.assertEqual(unrelated.read_text(), 'keep')
            created = []
            with self.assertRaises(FileExistsError):
                probe.create_owned_file(unrelated, b'replacement', 0o600, created)
            self.assertEqual(created, [])
            probe.create_owned_file(image, b'owned', 0o600, created)
            image.rename(directory / 'original')
            image.write_text('replacement')
            with self.assertRaisesRegex(RuntimeError, 'changed; refusing rollback'):
                probe.rollback_created(created)
            self.assertEqual(image.read_text(), 'replacement')

    def test_noexec_mount_refuses_before_writing_or_controlling_units(self):
        with patch.object(probe, 'fixture_prefix', return_value='aswp-activation-123-1'), \
             patch.object(probe.os, 'geteuid', return_value=0), \
             patch.object(probe, 'private_directory'), \
             patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)), \
             patch.object(probe.os.path, 'lexists', return_value=False), \
             patch.object(probe.os, 'statvfs', return_value=SimpleNamespace(f_flag=probe.os.ST_NOEXEC)), \
             patch.object(probe.os, 'open') as create, patch.object(probe, 'systemctl') as control:
            with self.assertRaisesRegex(RuntimeError, 'executable /usr/lib mount'):
                probe.admin('install', Path('/tmp/aswp-fixture'), 1000, 1000)
            create.assert_not_called()
            control.assert_not_called()

    def test_noexec_runtime_mount_does_not_block_executable_image_preflight(self):
        with patch.object(probe, 'fixture_prefix', return_value='aswp-activation-123-1'), \
             patch.object(probe.os, 'geteuid', return_value=0), \
             patch.object(probe, 'private_directory'), \
             patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)), \
             patch.object(probe.os.path, 'lexists', return_value=False), \
             patch.object(probe.os, 'statvfs', side_effect=lambda path: SimpleNamespace(
                 f_flag=probe.os.ST_NOEXEC if Path(path) == Path('/run') else 0)) as mounts, \
             patch.object(probe, 'unit_properties', return_value={'LoadState': 'not-found'}), \
             patch.object(probe, 'source_image', side_effect=RuntimeError('source boundary reached')), \
             patch.object(probe.os, 'open') as create, patch.object(probe, 'systemctl') as control:
            with self.assertRaisesRegex(RuntimeError, 'source boundary reached'):
                probe.admin('install', Path('/tmp/aswp-fixture'), 1000, 1000)
            mounts.assert_called_once_with(Path('/usr/lib'))
            create.assert_not_called()
            control.assert_not_called()

    def test_unprotected_image_parent_refuses_before_writes_or_service_control(self):
        safe = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        for bad_path in (Path('/'), Path('/usr'), Path('/usr/lib')):
            for bad in [SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
                        SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0),
                        SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)]:
                with self.subTest(path=bad_path, metadata=bad), \
                     patch.object(probe, 'fixture_prefix', return_value='aswp-activation-123-1'), \
                     patch.object(probe.os, 'geteuid', return_value=0), \
                     patch.object(probe, 'private_directory'), \
                     patch.object(Path, 'lstat', autospec=True, side_effect=lambda path: bad if path == bad_path else safe), \
                     patch.object(probe.os, 'open') as create, patch.object(probe, 'systemctl') as control:
                    with self.assertRaisesRegex(RuntimeError, 'guardian image parent'):
                        probe.admin('install', Path('/tmp/aswp-fixture'), 1000, 1000)
                    create.assert_not_called()
                    control.assert_not_called()

    def test_effective_unit_refuses_overrides_dropins_reload_and_incomplete_properties(self):
        fragment = '/run/systemd/system/aswp-activation-123-1.socket'
        good = f'LoadState=loaded\nFragmentPath={fragment}\nDropInPaths=\nNeedDaemonReload=no\n'
        with patch.object(probe, 'systemctl', return_value=SimpleNamespace(stdout=good)):
            probe.effective_unit('aswp-activation-123-1.socket', Path(fragment))
        for bad in [good.replace('/run/', '/etc/'), good.replace('DropInPaths=', 'DropInPaths=/etc/override.conf'),
                    good.replace('Reload=no', 'Reload=yes'), good.replace('loaded', 'not-found'),
                    good + 'LoadState=loaded\n', good.replace('DropInPaths=\n', '')]:
            with patch.object(probe, 'systemctl', return_value=SimpleNamespace(stdout=bad)), self.assertRaises(RuntimeError):
                probe.effective_unit('aswp-activation-123-1.socket', Path(fragment))

    def test_bind_reset_requires_the_exact_guardian_refusal_marker(self):
        invocation = 'a' * 32
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / (invocation + '.bind-refused')
            for value, accepted in [('bind-only probe sent launch data', True), ('unrelated error', False), (None, False)]:
                if value is not None:
                    marker.write_text(value)
                else:
                    marker.unlink(missing_ok=True)
                client, guardian = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                with client:
                    client.settimeout(1)
                    client.send(b'')
                    client.send(b'X')
                    client.shutdown(socket.SHUT_WR)
                    guardian.recv(1)
                    guardian.send(b'bind-only probe sent launch data')
                    guardian.close()  # unread X causes ECONNRESET, discarding that diagnostic
                    if accepted:
                        probe.read_bind_refusal(client, directory, invocation)
                        self.assertFalse(marker.exists())
                    else:
                        with self.assertRaises(RuntimeError):
                            probe.read_bind_refusal(client, directory, invocation)

    def test_compiled_source_refuses_links_unprotected_files_and_non_elf(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'guardian'
            source.write_bytes(b'\x7fELFfixture only')
            source.chmod(0o755)
            with patch.dict(probe.os.environ, {'ASWP_MANAGED_OBSERVER': str(source)}):
                self.assertEqual(probe.source_image(probe.os.getuid()), source.read_bytes())
                with self.assertRaisesRegex(RuntimeError, 'owned and protected'):
                    probe.source_image(probe.os.getuid() + 1)
                source.chmod(0o777)
                with self.assertRaisesRegex(RuntimeError, 'owned and protected'):
                    probe.source_image(probe.os.getuid())
                source.chmod(0o755)
                source.write_bytes(b'not an executable')
                with self.assertRaisesRegex(RuntimeError, 'bounded ELF'):
                    probe.source_image(probe.os.getuid())
            link = Path(temporary) / 'link'
            link.symlink_to(source)
            with patch.dict(probe.os.environ, {'ASWP_MANAGED_OBSERVER': str(link)}), self.assertRaises(OSError):
                probe.source_image(probe.os.getuid())

    def test_installed_image_requires_root_mode_and_exact_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / 'guardian'
            image.write_bytes(b'fixture image')
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            valid = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            with patch.object(Path, 'lstat', return_value=valid):
                probe.verify_image(image, digest)
                with self.assertRaisesRegex(RuntimeError, 'differs from ownership marker'):
                    probe.verify_image(image, '0' * 64)
            for mode, uid in [(stat.S_IFLNK | 0o755, 0), (stat.S_IFREG | 0o777, 0),
                              (stat.S_IFREG | 0o755, 1000), (stat.S_IFREG | 0o4755, 0)]:
                with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)), \
                     self.assertRaisesRegex(RuntimeError, 'root-owned and protected'):
                    probe.verify_image(image, digest)

    def test_changed_installed_image_never_reaches_cleanup_commands(self):
        prefix, directory = 'aswp-activation-123-1', Path('/tmp/aswp-fixture')
        ownership = {'uid': 1000, 'gid': 1000, 'directory': str(directory),
                     'units': probe.unit_files(prefix, directory, 1000, 1000), 'guardian_sha256': '0' * 64}
        with patch.object(probe, 'fixture_prefix', return_value=prefix), \
             patch.object(probe.os, 'geteuid', return_value=0), \
             patch.object(probe, 'private_directory'), \
             patch.object(probe.os.path, 'lexists', return_value=True), \
             patch.object(Path, 'lstat', autospec=True, side_effect=lambda path: SimpleNamespace(
                 st_mode=(stat.S_IFREG | 0o600) if path.name.endswith('.owner') else (stat.S_IFDIR | 0o755),
                 st_uid=0)), \
             patch.object(Path, 'read_text', return_value=json.dumps(ownership)), \
             patch.object(probe, 'verify_image', side_effect=RuntimeError('image changed')), \
             patch.object(Path, 'unlink') as unlink, patch.object(probe, 'systemctl') as control:
            with self.assertRaisesRegex(RuntimeError, 'image changed'):
                probe.admin('cleanup', directory, 1000, 1000)
            control.assert_not_called()
            unlink.assert_not_called()

    def test_cleanup_without_matching_root_ownership_never_controls_units(self):
        directory_meta = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        marker_meta = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
        for exists in (False, True):
            with self.subTest(marker_exists=exists), \
                 patch.object(probe, 'fixture_prefix', return_value='aswp-activation-123-1'), \
                 patch.object(probe.os, 'geteuid', return_value=0), \
                 patch.object(probe, 'private_directory'), \
                 patch.object(probe.os.path, 'lexists', return_value=exists), \
                 patch.object(Path, 'lstat', side_effect=[directory_meta, marker_meta]), \
                 patch.object(Path, 'read_text', return_value='unrelated fixture owner'), \
                 patch.object(Path, 'unlink') as unlink, \
                 patch.object(probe, 'systemctl') as control:
                if exists:
                    with self.assertRaisesRegex(RuntimeError, 'ownership marker'):
                        probe.admin('cleanup', Path('/tmp/aswp-fixture'), 1000, 1000)
                else:
                    probe.admin('cleanup', Path('/tmp/aswp-fixture'), 1000, 1000)
                control.assert_not_called()
                unlink.assert_not_called()

    def test_local_invocation_never_reaches_administrator_commands(self):
        for role in ('install', 'cleanup', 'template-refusal'):
            with patch.dict(probe.os.environ, {}, clear=True), \
                 patch.object(probe.os, 'geteuid', return_value=0), \
                 patch.object(probe.subprocess, 'run') as command, \
                 patch.object(probe.os, 'open') as create:
                with self.assertRaises(RuntimeError):
                    probe.admin(role, Path('/unused'), 1000, 1000)
                command.assert_not_called()
                create.assert_not_called()

    def test_unit_request_cannot_select_root_or_inject_unit_directives(self):
        prefix, directory = 'aswp-activation-123-1', Path('/tmp/aswp-fixture')
        for uid, gid in [(0, 1000), (1000, 0), (-1, 1000), (2**31, 1000)]:
            with self.subTest(uid=uid, gid=gid), self.assertRaises(RuntimeError):
                probe.unit_files(prefix, directory, uid, gid)
        for bad in [Path('/tmp/fixture\nUser=0'), Path('/tmp/%u'), Path('/tmp/a/../b'), Path('relative')]:
            with self.subTest(path=bad), self.assertRaises(RuntimeError):
                probe.unit_files(prefix, bad, 1000, 1000)
        for bad in ['other', '../other', prefix + '\nUser=0']:
            with self.subTest(prefix=bad), self.assertRaises(RuntimeError):
                probe.unit_files(bad, directory, 1000, 1000)

    def test_fixed_user_template_has_no_client_controlled_root_command(self):
        files = probe.unit_files('aswp-activation-123-1', Path('/tmp/aswp-fixture'), 1000, 1000)
        service = files['aswp-activation-123-1@.service']
        lines = service.splitlines()
        self.assertEqual([x for x in lines if x.startswith('User=')], ['User=1000'])
        self.assertEqual([x for x in lines if x.startswith('Group=')], ['Group=1000'])
        commands = [x for x in lines if x.startswith('Exec')]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0], 'ExecStart=/usr/lib/aswp-activation-123-1.guardian --activation-guardian aswp-activation-123-1 1000 1000 /tmp/aswp-fixture %n')
        self.assertIn('Delegate=no', lines)
        self.assertIn('KillMode=control-group', lines)
        self.assertIn('RuntimeMaxSec=60s', lines)
        self.assertNotIn('PAMName=', service)
        self.assertNotIn('EnvironmentFile=', service)
        self.assertIn('SocketMode=0600', files['aswp-activation-123-1.socket'])
        self.assertIn('ListenSequentialPacket=/run/aswp-activation-123-1.sock', files['aswp-activation-123-1.socket'])


if __name__ == '__main__':
    unittest.main()
