"""Check that both rebuilt executable names must match the candidate."""
import json
from pathlib import Path
import tempfile
import unittest

from test_verify_candidate_set import LOCK, REVISION, SOURCE_FILES, TARGETS, VERSION, digest, make_candidate
from verify_candidate_set import verify_one
from verify_rebuilt_candidate import verify_rebuild


class RebuiltCandidateTests(unittest.TestCase):
    def test_candidate_integrity_and_source_binding_precede_comparison(self):
        cases = ((name, target, mode) for name, target in TARGETS.items()
                 for mode in ("valid", "tamper", "wrong_revision", "dirty_marker", "stale_marker", "missing_marker"))
        for name, target, mode in cases:
            with self.subTest(target=target, mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                make_candidate(root, name, target, tamper=mode == "tamper")
                binaries = root / "binaries"
                binaries.mkdir()
                suffix = ".exe" if "windows" in target else ""
                (binaries / ("aswp" + suffix)).write_bytes(b"binary a")
                (binaries / ("agentswapper" + suffix)).write_bytes(b"binary b")
                marker = {"schema": 1, "revision": REVISION, "dirty": mode == "dirty_marker",
                          "lock_sha256": LOCK, "binaries": {"aswp" + suffix: digest(b"binary a"),
                          "agentswapper" + suffix: digest(b"old" if mode == "stale_marker" else b"binary b")}}
                if mode != "missing_marker":
                    (binaries / "agentswapper-build.json").write_text(json.dumps(marker), encoding="utf-8")
                revision = "c" * 40 if mode == "wrong_revision" else REVISION
                if mode == "valid":
                    verify_rebuild(root / name, target, revision, LOCK, VERSION, SOURCE_FILES, binaries)
                else:
                    with self.assertRaises(ValueError):
                        verify_rebuild(root / name, target, revision, LOCK, VERSION, SOURCE_FILES, binaries)

    def test_both_binaries_must_match_on_every_target(self):
        for name, target in TARGETS.items():
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                make_candidate(root, name, target)
                suffix = ".exe" if "windows" in target else ""
                first, second = "aswp" + suffix, "agentswapper" + suffix
                hashes = {first: digest(b"binary a"), second: digest(b"binary b")}
                verify_one(root / name, target, REVISION, LOCK, VERSION, SOURCE_FILES, hashes)
                for key in (first, second):
                    invalid = {**hashes, key: digest(b"different")}
                    with self.assertRaisesRegex(ValueError, "do not match"):
                        verify_one(root / name, target, REVISION, LOCK, VERSION, SOURCE_FILES, invalid)
                with self.assertRaisesRegex(ValueError, "do not match"):
                    verify_one(root / name, target, REVISION, LOCK, VERSION, SOURCE_FILES, {first: hashes[first]})


if __name__ == "__main__":
    unittest.main()
