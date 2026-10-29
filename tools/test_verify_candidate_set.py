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
VERSION = "0.1.0-dev"
SOURCE_FILES = {"LICENSE": b"license", "NOTICE": b"notice",
                "assets/brand/THIRD_PARTY_NOTICES.txt": b"brand notices"}


def make_candidate(root, name, target, *, dirty=False, tamper=False, unsafe=False, collision=False, false_notice=False, false_version=False):
    directory = root / name
    directory.mkdir()
    suffix = ".exe" if "windows" in target else ""
    files = {"aswp" + suffix: b"binary a", "agentswapper" + suffix: b"binary b",
             **SOURCE_FILES, "THIRD_PARTY_LICENSES.txt": b"licenses",
             "PREVIEW.txt": b"Internal developer preview; not a signed or published release.\n"}
    if false_notice:
        files["NOTICE"] = b"different notice with a valid manifest hash"
    if unsafe:
        files["../outside"] = b"bad"
    if collision:
        files["Notice"] = b"case collision"
    version = "9.9.9" if false_version else VERSION
    manifest = {"schema": 1, "version": version, "source_revision": REVISION,
                "source_dirty": dirty, "target": target, "cargo_lock_sha256": LOCK,
                "files": {name: digest(data) for name, data in files.items()}}
    if tamper:
        files["NOTICE"] = b"changed"
    archive = directory / f"agentswapper-{version}-{target}.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path, data in {**files, "BUILD-INFO.json": json.dumps(manifest).encode()}.items():
            info = zipfile.ZipInfo(path)
            info.create_system = 3
            executable = path in ("aswp" + suffix, "agentswapper" + suffix)
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            bundle.writestr(info, data)
    (directory / (archive.name + ".sha256")).write_text(f"{digest(archive.read_bytes())}  {archive.name}\n", encoding="utf-8", newline="\n")
    return archive


class CandidateSetTests(unittest.TestCase):
    def test_nonportable_paths_are_refused(self):
        from verify_candidate_set import safe_archive_name
        for name in ("../outside", "/absolute", "a//b", "a\\b", "a/CON.txt", "a/LPT².txt", "a/x:stream", "a/last.", "a/last ", "a/\x1b", "a/\u202efoo", "a/e\u0301"):
            with self.subTest(name=name):
                self.assertFalse(safe_archive_name(name))
        self.assertTrue(safe_archive_name("source/option-ext-0.2.0/LICENSE.txt"))

    def test_valid_platform_set_and_tampering_refusal(self):
        for mode in ("valid", "dirty", "tamper", "unsafe", "collision", "missing", "false_notice", "false_version"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                for index, (name, target) in enumerate(TARGETS.items()):
                    if mode == "missing" and index == 0:
                        continue
                    make_candidate(root, name, target, dirty=mode == "dirty" and index == 0,
                                   tamper=mode == "tamper" and index == 0, unsafe=mode == "unsafe" and index == 0,
                                   collision=mode == "collision" and index == 0,
                                   false_notice=mode == "false_notice" and index == 0,
                                   false_version=mode == "false_version" and index == 0)
                if mode == "valid":
                    self.assertEqual(len(verify_set(root, REVISION, LOCK, VERSION, SOURCE_FILES)), 3)
                    with self.assertRaisesRegex(ValueError, "does not match this run"):
                        verify_set(root, "c" * 40, LOCK, VERSION, SOURCE_FILES)
                    with self.assertRaisesRegex(ValueError, "does not match this run"):
                        verify_set(root, REVISION, "d" * 64, VERSION, SOURCE_FILES)
                else:
                    with self.assertRaises(ValueError):
                        verify_set(root, REVISION, LOCK, VERSION, SOURCE_FILES)


if __name__ == "__main__":
    unittest.main()
