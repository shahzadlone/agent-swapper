"""Regression checks for failure diagnostics, including Windows code pages."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).with_name("report_test_failures.py")


class FailureDiagnosticsTests(unittest.TestCase):
    def report(self, content):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "junit.xml"
            path.write_bytes(content)
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "cp1252:strict"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path)], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return result.stdout.decode("utf-8", "strict")

    def document(self, message, stdout="", stderr=""):
        root = ET.Element("testsuites")
        case = ET.SubElement(ET.SubElement(root, "testsuite"), "testcase", name="fixture")
        ET.SubElement(case, "failure", type="assertion").text = message
        ET.SubElement(case, "system-out").text = stdout
        ET.SubElement(case, "system-err").text = stderr
        return ET.tostring(root, encoding="utf-8", xml_declaration=True)

    def test_unicode_failure_survives_legacy_stdout_encoding(self):
        output = self.report(self.document("assertion failed", stderr="└── predicate 未匹配 🦀"))
        self.assertIn("::error::fixture (assertion)", output)
        self.assertIn("└── predicate 未匹配 🦀", output)

    def test_untrusted_newlines_and_percent_sequences_stay_inside_annotation(self):
        output = self.report(self.document("failed %0A\r\n::warning::injected"))
        self.assertEqual(len(output.splitlines()), 1)
        # XML normalizes the text node's CRLF to LF before reporting.
        self.assertIn("%250A%0A::warning::injected", output)

    def test_large_failure_keeps_context_and_replay_seed(self):
        output = self.report(self.document("begin-assertion", stdout="x" * 10000,
                                           stderr="replay-seed-at-end"))
        self.assertIn("begin-assertion", output)
        self.assertIn("[output truncated]", output)
        self.assertIn("replay-seed-at-end", output)
        self.assertLess(len(output), 6200)

    def test_malformed_or_oversized_reports_produce_bounded_diagnostics(self):
        self.assertIn("::error::JUnit diagnostics could not be read", self.report(b"<truncated>"))
        output = self.report(b"x" * (10 * 1024 * 1024 + 1))
        self.assertIn("::error::JUnit report exceeds", output)
        self.assertLess(len(output), 200)


if __name__ == "__main__":
    unittest.main()
