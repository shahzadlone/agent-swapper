"""Adversarial source-archive checks for internal release candidates."""
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import audit_attribution_tool
import build_audited_deny
import build_audited_about
import release_candidate
from release_candidate import add_locked_source, digest, reject_build_paths, safe_path, verify_build_marker, write_candidate
from portable_archive import ensure_portable_names


def crate(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, kind in entries:
            entry = tarfile.TarInfo(name)
            if kind == "link":
                entry.type = tarfile.SYMTYPE
                entry.linkname = "../../outside"
                archive.addfile(entry)
            else:
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


class CandidateSafety(unittest.TestCase):
    def test_attribution_diagnostic_exposes_only_fixed_labels_and_locked_names(self):
        lock = '[[package]]\nname = "example-crate"\nversion = "1.0.0"\n'
        result = release_candidate.attribution_diagnostic(
            b"failed to satisfy license requirements for example-crate: PRIVATE-SECRET\n"
            b"encountered 1 errors resolving licenses", lock)
        self.assertEqual(result, "categories: license resolution, license policy; lockfile names mentioned: example-crate")
        self.assertNotIn("PRIVATE-SECRET", result)
        self.assertIn("unclassified", release_candidate.attribution_diagnostic(b"PRIVATE-SECRET", lock))

    def test_ci_error_annotation_escapes_controls_and_omits_subprocess_output(self):
        failures = [ValueError("bad%\nvalue"),
                    release_candidate.subprocess.CalledProcessError(1, ["cargo", "about"], stderr=b"secret-output")]
        for failure in failures:
            output = io.StringIO()
            with patch.object(release_candidate, "candidate", side_effect=failure), \
                 patch.object(sys, "argv", ["release_candidate.py", "--output", "unused"]), \
                 patch.dict(release_candidate.os.environ, {"GITHUB_ACTIONS": "true"}), \
                 patch("sys.stdout", output):
                with self.assertRaises(type(failure)):
                    release_candidate.main()
            self.assertIn("Candidate packaging", output.getvalue())
            self.assertNotIn("secret-output", output.getvalue())
            if isinstance(failure, ValueError):
                self.assertIn("bad%25%0Avalue", output.getvalue())

    def test_attribution_build_marker_detects_binary_and_lock_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "cargo-about"
            binary.write_bytes(b"reviewed attribution tool")
            marker = binary.parent / "cargo-about-build.json"
            data = {"schema": 1, "source_sha256": audit_attribution_tool.PINS["cargo-about-0.9.3"],
                    "lock_sha256": audit_attribution_tool.AUDITED["cargo-about-0.9.3/Cargo.lock"],
                    "binary_sha256": digest(binary.read_bytes())}
            marker.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(build_audited_about.subprocess, "run") as run:
                run.return_value.stdout = "cargo-about 0.9.3\n"
                build_audited_about.verify_installed(binary)
                binary.write_bytes(b"altered attribution tool")
                with self.assertRaisesRegex(ValueError, "marker does not match"):
                    build_audited_about.verify_installed(binary)
                binary.write_bytes(b"reviewed attribution tool")
                data["source_sha256"] = "0" * 64
                marker.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "marker does not match"):
                    build_audited_about.verify_installed(binary)

    def test_build_marker_refuses_stale_or_changed_binaries(self):
        marker = {"schema": 1, "revision": "revision-a", "dirty": False,
                  "lock_sha256": "lock-a", "binaries": {"aswp": digest(b"built")}}
        verify_build_marker(marker, "revision-a", False, "lock-a", {"aswp": b"built"})
        for revision, dirty, lock, data in (("revision-b", False, "lock-a", b"built"),
                                            ("revision-a", True, "lock-a", b"built"),
                                            ("revision-a", False, "lock-b", b"built"),
                                            ("revision-a", False, "lock-a", b"changed")):
            with self.subTest(revision=revision, dirty=dirty, lock=lock, data=data):
                with self.assertRaisesRegex(ValueError, "do not match"):
                    verify_build_marker(marker, revision, dirty, lock, {"aswp": data})

    def test_checker_build_marker_detects_binary_and_lock_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "cargo-deny"
            binary.write_bytes(b"reviewed binary")
            marker = binary.parent / "cargo-deny-attestation.json"
            data = {"schema": 1, "source_sha256": build_audited_deny.PINS["cargo-deny-0.20.2"],
                    "lock_sha256": build_audited_deny.LOCK_SHA, "binary_sha256": digest(binary.read_bytes())}
            marker.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(build_audited_deny.subprocess, "run") as run:
                run.return_value.stdout = "cargo-deny 0.20.2\n"
                build_audited_deny.verify_installed(binary)
                binary.write_bytes(b"different binary")
                with self.assertRaisesRegex(ValueError, "marker does not match"):
                    build_audited_deny.verify_installed(binary)
                binary.write_bytes(b"reviewed binary")
                data["lock_sha256"] = "0" * 64
                marker.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "marker does not match"):
                    build_audited_deny.verify_installed(binary)

    def test_attribution_audit_refuses_modified_registry_source_and_archive(self):
        data = crate([("tool-1.0/src/lib.rs", b"audited source", "file")])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "registry/src/index/tool-1.0/src/lib.rs"
            archive = root / "registry/cache/index/tool-1.0.crate"
            source.parent.mkdir(parents=True)
            archive.parent.mkdir(parents=True)
            source.write_bytes(b"audited source")
            archive.write_bytes(data)
            with patch.object(audit_attribution_tool, "CARGO_ROOT", root), \
                 patch.object(audit_attribution_tool, "PINS", {"tool-1.0": digest(data)}), \
                 patch.object(audit_attribution_tool, "AUDITED", {"tool-1.0/src/lib.rs": digest(b"audited source")}):
                audit_attribution_tool.verify_crate("tool-1.0")
                source.write_bytes(b"modified")
                with self.assertRaisesRegex(ValueError, "source mismatch"):
                    audit_attribution_tool.verify_crate("tool-1.0")
                source.write_bytes(b"audited source")
                archive.write_bytes(data + b"modified")
                with self.assertRaisesRegex(ValueError, "archive checksum mismatch"):
                    audit_attribution_tool.verify_crate("tool-1.0")

    def test_existing_artifacts_are_not_replaced_and_failed_pair_rolls_back(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "candidate.zip").write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                write_candidate(root, "candidate.zip", b"new")
            self.assertEqual((root / "candidate.zip").read_bytes(), b"original")
            (root / "candidate.zip").unlink()
            (root / "candidate.zip.sha256").write_text("original checksum")
            with self.assertRaises(FileExistsError):
                write_candidate(root, "candidate.zip", b"new")
            self.assertFalse((root / "candidate.zip").exists())
            self.assertEqual((root / "candidate.zip.sha256").read_text(), "original checksum")

    def test_binary_path_leaks_are_rejected_without_printing_the_path(self):
        with self.assertRaisesRegex(ValueError, "local build path found") as error:
            reject_build_paths(b"binary /private/user/source/file", ["/private/user"], False)
        self.assertNotIn("/private/user", str(error.exception))
        with self.assertRaisesRegex(ValueError, "local build path found"):
            reject_build_paths(b"binary C:/Users/Runner/file", [r"c:\users\runner"], True)
        reject_build_paths(b"binary /build-home/source/file", ["/private/user"], False)

    def test_archive_paths_refuse_traversal_and_platform_ambiguity(self):
        for name in ("", "/absolute", "../outside", "source/../outside", "source//x", "source/./x", "source\\x", "x\x00y", "source/CON.txt", "source/COM¹.txt", "source/x:stream", "source/trailing.", "source/\u202ename", "source/e\u0301"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_path(name)
        self.assertEqual(safe_path("source/option-ext-0.2.0/LICENSE.txt"), "source/option-ext-0.2.0/LICENSE.txt")

    def test_archive_names_refuse_case_collisions_and_file_directory_conflicts(self):
        for entries in (("a/Foo", "A/foo"), ("a/one", "A/two"),
                        ("parent", "parent/child"), ("Parent", "parent/child")):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                ensure_portable_names(entries)
        ensure_portable_names(("source/a", "source/b", "NOTICE"))

    def test_locked_source_rejects_tamper_links_traversal_and_duplicates(self):
        good = crate([("option-ext-0.2.0/LICENSE.txt", b"license", "file")])
        files = {}
        add_locked_source(files, good, digest(good))
        self.assertEqual(files["source/option-ext-0.2.0/LICENSE.txt"][0], b"license")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            add_locked_source({}, good, "0" * 64)
        for entries in (
            [("option-ext-0.2.0/../outside", b"x", "file")],
            [("option-ext-0.2.0/link", b"", "link")],
            [("other/LICENSE", b"x", "file")],
            [("option-ext-0.2.0/x", b"a", "file"), ("option-ext-0.2.0/x", b"b", "file")],
        ):
            bad = crate(entries)
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                add_locked_source({}, bad, digest(bad))


if __name__ == "__main__":
    unittest.main()
