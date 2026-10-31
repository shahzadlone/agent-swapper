"""Guard and fixed-user unit-rendering checks; no privileged operations."""
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_linux_socket_activation as probe


class ActivationTests(unittest.TestCase):
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
        for role in ('install', 'cleanup'):
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
        self.assertTrue(commands[0].startswith('ExecStart=/usr/bin/python3 '))
        self.assertIn('Delegate=no', lines)
        self.assertIn('KillMode=control-group', lines)
        self.assertIn('RuntimeMaxSec=30s', lines)
        self.assertNotIn('PAMName=', service)
        self.assertNotIn('EnvironmentFile=', service)
        self.assertIn('SocketMode=0600', files['aswp-activation-123-1.socket'])


if __name__ == '__main__':
    unittest.main()
