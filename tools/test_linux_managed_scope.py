"""Guard checks for the disposable system-manager qualification fixture."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_linux_managed_scope as probe


class ManagedScopeTests(unittest.TestCase):
    def test_manager_identity_binds_unit_scope_user_and_invocation(self):
        unit, scope = 'aswp-managed-12-1-graceful', '/system.slice/aswp-managed-12-1-graceful.service'
        fields = {'Id': unit + '.service', 'ControlGroup': scope, 'MainPID': '42',
                  'InvocationID': 'a' * 32, 'Transient': 'yes', 'User': '1000', 'ActiveState': 'active'}
        encode = lambda values: ''.join(f'{key}={value}\n' for key, value in values.items())
        self.assertEqual(probe.parse_identity(encode(fields), unit, scope, 1000, 42), 'a' * 32)
        for key, value in [('Id', 'other.service'), ('ControlGroup', '/other'), ('MainPID', '43'),
                           ('User', '0'), ('Transient', 'no'), ('ActiveState', 'inactive'),
                           ('InvocationID', '0' * 32), ('InvocationID', 'secret\nInjected=value')]:
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                probe.parse_identity(encode({**fields, key: value}), unit, scope, 1000, 42)
        for output in (encode(fields) + 'MainPID=42\n', encode(fields) + 'Unexpected=value\n', 'x' * 4097):
            with self.assertRaises(RuntimeError):
                probe.parse_identity(output, unit, scope, 1000, 42)

    def test_local_or_invalid_run_never_starts_a_manager(self):
        for environment in ({}, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                                 'GITHUB_RUN_ID': 'bad/identity', 'GITHUB_RUN_ATTEMPT': '1'}):
            with self.subTest(environment=environment), \
                 patch.object(probe.os, 'environ', environment), \
                 patch.object(probe.os, 'geteuid', return_value=1000), \
                 patch.object(probe.sys, 'platform', 'linux'), \
                 patch.object(probe.sys, 'argv', ['fixture']), \
                 patch.object(probe.subprocess, 'Popen') as spawn, \
                 patch.object(probe.tempfile, 'TemporaryDirectory') as directory:
                with self.assertRaises(RuntimeError):
                    probe.main()
                spawn.assert_not_called()
                directory.assert_not_called()

    def test_private_directory_rejects_links_and_exposed_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            probe.private_directory(root)
            link = root / 'linked'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                probe.private_directory(link)
            root.chmod(0o750)
            with self.assertRaises(RuntimeError):
                probe.private_directory(root)
            root.chmod(0o700)


if __name__ == '__main__':
    unittest.main()
