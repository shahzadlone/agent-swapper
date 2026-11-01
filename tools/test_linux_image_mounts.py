"""Refusal controls must run before any privilege, mount or fixture creation."""
import os
import unittest
from unittest.mock import patch

import check_linux_image_mounts as probe


class RefusalTests(unittest.TestCase):
    def test_manifest_without_a_version_never_creates_or_mounts(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(probe, 'private_namespace'), \
                patch.object(probe.subprocess, 'run') as run, patch.object(probe.tempfile, 'mkdtemp') as create:
            for case in ('manifest-protected', 'bundle-protected'):
                with self.subTest(case=case), self.assertRaisesRegex(RuntimeError, 'invalid fixture package version'):
                    probe.mounted_case(case, '/usr/bin/true', 1001, 1001)
            run.assert_not_called()
            create.assert_not_called()

    def test_separate_but_shared_namespace_never_creates_or_mounts(self):
        with patch.object(probe.os, 'geteuid', return_value=0), \
                patch.object(probe.os, 'readlink', side_effect=['mnt:[own]', 'mnt:[init]']), \
                patch.object(probe.Path, 'read_text', return_value='1 0 0:1 / /run rw shared:2 - tmpfs tmpfs rw\n'), \
                patch.object(probe.subprocess, 'run') as run, patch.object(probe.tempfile, 'mkdtemp') as create:
            with self.assertRaisesRegex(RuntimeError, 'shared propagation'):
                probe.mounted_case('protected', '/usr/bin/true', 1001, 1001)
            run.assert_not_called()
            create.assert_not_called()

    def test_ordinary_invocation_never_spawns_a_privileged_process(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(probe.sys, 'argv', ['probe', '/usr/bin/true']), \
                patch.object(probe.subprocess, 'run') as run, patch.object(probe.tempfile, 'mkdtemp') as create:
            with self.assertRaisesRegex(RuntimeError, 'opted-in disposable hosted runner'):
                probe.main()
            run.assert_not_called()
            create.assert_not_called()

    def test_root_without_a_separate_namespace_never_creates_or_mounts(self):
        with patch.object(probe.os, 'geteuid', return_value=0), \
                patch.object(probe.os, 'readlink', return_value='mnt:[same]'), \
                patch.object(probe.subprocess, 'run') as run, patch.object(probe.tempfile, 'mkdtemp') as create:
            with self.assertRaisesRegex(RuntimeError, 'own root mount namespace'):
                probe.mounted_case('protected', '/usr/bin/true', 1001, 1001)
            run.assert_not_called()
            create.assert_not_called()


if __name__ == '__main__':
    unittest.main()
