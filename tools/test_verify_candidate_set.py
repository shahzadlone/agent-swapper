"""Adversarial checks for the pre-attestation candidate verifier."""
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from verify_candidate_set import TARGETS, digest, verify_set

REVISION = "a" * 40
LOCK = "b" * 64


def make_candidate(root, name, target, *, dirty=False, tamper=False, unsafe=False):
    directory = root / name
    directory.mkdir()
    suffix = ".exe" if "windows" in target else ""
    files = {"aswp" + suffix: b"binary a", "agentswapper" + suffix: b"binary b",
             "LICENSE": b"license", "NOTICE": b"notice", "THIRD_PARTY_LICENSES.txt": b"licenses",
             "PREVIEW.txt": b"preview"}
    if unsafe:
        files["../outside"] = b"bad"
    manifest = {"schema": 1, "version": "0.1.0-dev", "source_revision": REVISION,
                "source_dirty": dirty, "target": target, "cargo_lock_sha256": LOCK,
                "files": {name: digest(data) for name, data in files.items()}}
    if tamper:
        files["NOTICE"] = b"changed"
    archive = directory / f"agentswapper-0.1.0-dev-{target}.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path, data in {**files, "BUILD-INFO.json": json.dumps(manifest).encode()}.items():
            info = zipfile.ZipInfo(path)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(info, data)
    (directory / (archive.name + ".sha256")).write_text(f"{digest(archive.read_bytes())}  {archive.name}\n", encoding="utf-8", newline="\n")
    return archive


class CandidateSetTests(unittest.TestCase):
    def test_valid_platform_set_and_tampering_refusal(self):
        for mode in ("valid", "dirty", "tamper", "unsafe", "missing"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                for index, (name, target) in enumerate(TARGETS.items()):
                    if mode == "missing" and index == 0:
                        continue
                    make_candidate(root, name, target, dirty=mode == "dirty" and index == 0,
                                   tamper=mode == "tamper" and index == 0, unsafe=mode == "unsafe" and index == 0)
                if mode == "valid":
                    self.assertEqual(len(verify_set(root, REVISION, LOCK)), 3)
                    with self.assertRaisesRegex(ValueError, "does not match this run"):
                        verify_set(root, "c" * 40, LOCK)
                    with self.assertRaisesRegex(ValueError, "does not match this run"):
                        verify_set(root, REVISION, "d" * 64)
                else:
                    with self.assertRaises(ValueError):
                        verify_set(root, REVISION, LOCK)


if __name__ == "__main__":
    unittest.main()
