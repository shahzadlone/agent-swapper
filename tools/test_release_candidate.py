"""Adversarial source-archive checks for internal release candidates."""
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import audit_attribution_tool
import build_audited_deny
from release_candidate import add_locked_source, digest, reject_build_paths, safe_path, write_candidate


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
        for name in ("", "/absolute", "../outside", "source/../outside", "source//x", "source/./x", "source\\x", "x\x00y", "source/CON.txt", "source/x:stream", "source/trailing."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_path(name)
        self.assertEqual(safe_path("source/option-ext-0.2.0/LICENSE.txt"), "source/option-ext-0.2.0/LICENSE.txt")

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
