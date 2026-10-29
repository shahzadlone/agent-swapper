"""Check that both rebuilt executable names must match the candidate."""
from pathlib import Path
import tempfile
import unittest

from test_verify_candidate_set import TARGETS, make_candidate
from verify_rebuilt_candidate import compare


class RebuiltCandidateTests(unittest.TestCase):
    def test_both_binaries_must_match_on_every_target(self):
        for name, target in TARGETS.items():
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = make_candidate(root, name, target)
                binaries = root / "binaries"
                binaries.mkdir()
                suffix = ".exe" if "windows" in target else ""
                first = binaries / ("aswp" + suffix)
                second = binaries / ("agentswapper" + suffix)
                first.write_bytes(b"binary a")
                second.write_bytes(b"binary b")
                compare(archive, target, binaries)
                second.write_bytes(b"different")
                with self.assertRaisesRegex(ValueError, "does not match"):
                    compare(archive, target, binaries)
                second.unlink()
                with self.assertRaisesRegex(ValueError, "missing or invalid"):
                    compare(archive, target, binaries)


if __name__ == "__main__":
    unittest.main()
