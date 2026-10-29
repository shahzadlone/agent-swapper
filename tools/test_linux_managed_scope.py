"""Guard checks for the disposable system-manager qualification fixture."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_linux_managed_scope as probe


class ManagedScopeTests(unittest.TestCase):
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
