"""Ordinary-user controls for the hosted-only path measurement."""
from pathlib import Path
import subprocess
import sys
import unittest

from check_linux_unit_fragment import expected_fragment


class FragmentMeasurementTests(unittest.TestCase):
    def test_outside_hosted_fixture_refuses_before_manager_or_filesystem_mutation(self):
        script = Path(__file__).with_name('check_linux_unit_fragment.py')
        for arguments in ([], ['--admin']):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, '-I', '-B', '-S', str(script), *arguments],
                                        env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('socket activation fixture requires opted-in disposable hosted CI', result.stderr)
                self.assertEqual(result.stdout, '')

    def test_report_spelling_cannot_name_another_unit_or_search_directory(self):
        name = 'aswp-fragment-123-1.service'
        for directory in ('/usr/lib/systemd/system', '/lib/systemd/system'):
            self.assertTrue(expected_fragment(directory + '/' + name, name))
        for fragment in ('/etc/systemd/system/' + name, '/run/systemd/system/' + name,
                         '/usr/lib/systemd/system/other.service', 'lib/systemd/system/' + name,
                         '/usr/lib/systemd/system/../system/' + name):
            self.assertFalse(expected_fragment(fragment, name))


if __name__ == '__main__':
    unittest.main()
