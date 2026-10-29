"""Tests for safe reporting of the delegated CI environment."""
import unittest

from run_delegated_custody_probe import nsdelegate_observation


class DelegatedCustodyProbeTests(unittest.TestCase):
    def test_mount_option_requires_one_matching_cgroup2_mount(self):
        prefix = "1 2 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup "
        self.assertEqual(nsdelegate_observation(prefix + "rw,nsdelegate\n"), "enabled")
        self.assertEqual(nsdelegate_observation(prefix + "rw\n"), "not reported")
        self.assertEqual(nsdelegate_observation(prefix + "rw,notnsdelegate\n"), "not reported")
        self.assertEqual(nsdelegate_observation(prefix + "rw\n" + prefix + "rw\n"), "unknown")
        self.assertEqual(nsdelegate_observation("untrusted\n::warning::secret"), "unknown")
        self.assertEqual(nsdelegate_observation(prefix.replace("/sys/fs/cgroup", "/other") + "rw,nsdelegate"), "unknown")


if __name__ == "__main__":
    unittest.main()
