"""Ordinary-user fixture controls; no namespace or credential mutations."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import check_linux_origin as probe


class OriginFixtureTests(unittest.TestCase):
    def test_privileged_roles_refuse_outside_explicit_hosted_ci(self):
        script = Path(__file__).with_name('check_linux_origin.py')
        for arguments in ([], ['/unused', 'available'],
                          ['--inside', 'private-mount', '/unused', 'auto', '1000', '1000'],
                          ['--child', '/unused', 'auto', '1000', '1000', 'user']):
            result = subprocess.run([sys.executable, '-I', '-B', '-S', str(script), *arguments],
                                    env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertIn('require opted-in disposable hosted CI', result.stdout)
            self.assertEqual(result.stderr, '')

    def test_root_role_cannot_run_in_the_host_mount_namespace(self):
        with patch.object(probe._mounts.os, 'geteuid', return_value=0), \
             patch.object(probe._mounts.os, 'readlink', return_value='mnt:[same]'), \
             patch.object(probe.subprocess, 'run') as run, \
             patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'own root mount namespace'):
                probe.inside('root', '/unused', 'auto', 1000, 1000)
            run.assert_not_called()
            spawn.assert_not_called()

    def test_hosted_gate_rejects_self_hosted_or_ambiguous_identifiers(self):
        hosted = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', ASWP_CI_ORIGIN='1',
                      GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        for field, bad in [('GITHUB_ACTIONS', ''), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                           ('ASWP_CI_ORIGIN', '0'), ('GITHUB_RUN_ID', '../123'),
                           ('GITHUB_RUN_ATTEMPT', '1/2')]:
            with patch.dict(probe.os.environ, {**hosted, field: bad}, clear=True):
                with self.assertRaises(RuntimeError):
                    probe.gate()

    def test_generic_failure_is_not_a_successful_negative_control(self):
        for code, stdout, stderr in [(1, '', 'expected'), (125, '', 'wrong boundary'),
                                     (125, 'unexpected output', 'expected'), (77, '', 'expected')]:
            with self.assertRaises(RuntimeError):
                probe.expected(subprocess.CompletedProcess([], code, stdout, stderr), 'expected')


if __name__ == '__main__':
    unittest.main()
