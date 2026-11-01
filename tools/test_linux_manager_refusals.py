"""Never permit the namespace fixture to start outside opted-in hosted CI."""
import unittest
from unittest.mock import patch

import check_linux_manager_refusals as probe


class RefusalGateTests(unittest.TestCase):
    def test_unqualified_invocations_never_launch_or_mount(self):
        hosted = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                  'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'ASWP_MANAGER_REFUSALS': '1'}
        for environment in ({}, {**hosted, 'RUNNER_ENVIRONMENT': 'self-hosted'},
                            {**hosted, 'ASWP_MANAGER_REFUSALS': '0'},
                            {**hosted, 'GITHUB_RUN_ID': '../unsafe'},
                            {**hosted, 'GITHUB_RUN_ATTEMPT': '0/1'}):
            with self.subTest(environment=environment), \
                 patch.dict(probe.os.environ, environment, clear=True), \
                 patch.object(probe.subprocess, 'Popen') as spawn, \
                 patch.object(probe.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    probe.main()
                spawn.assert_not_called()
                run.assert_not_called()

    def test_inside_role_requires_an_actual_separate_mount_namespace(self):
        with patch.object(probe.os, 'geteuid', return_value=0), \
             patch.object(probe.os, 'readlink', return_value='mnt:[same]'), \
             patch.object(probe.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'separate mount namespace'):
                probe.mounted_case('map-overlay', '/fixture/observer', 1000, 1000)
            spawn.assert_not_called()

    def test_root_and_invalid_target_identities_are_refused(self):
        for uid, gid in [('0', '1000'), ('1000', '0'), ('-1', '1000'), (str(2**31), '1000')]:
            with self.subTest(uid=uid, gid=gid), self.assertRaises(RuntimeError):
                probe.identity(uid, gid)

    def test_fault_listeners_refuse_the_host_mount_namespace(self):
        for role in ('--listen-stall', '--listen-close'):
            with self.subTest(role=role), patch.object(probe, 'gate'), \
                 patch.object(probe.sys, 'argv', ['probe', role, '/unused', '1000', '1000']), \
                 patch.object(probe.os, 'geteuid', return_value=0), \
                 patch.object(probe.os, 'readlink', return_value='mnt:[same]'), \
                 patch.object(probe.socket, 'socket') as listener:
                with self.assertRaisesRegex(RuntimeError, 'separate mount namespace'):
                    probe.main()
                listener.assert_not_called()


if __name__ == '__main__':
    unittest.main()
