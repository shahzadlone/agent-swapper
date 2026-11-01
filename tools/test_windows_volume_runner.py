"""Exercise CI evidence validation with an in-process fake cargo, never a disk."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
HARNESS = r"""
Write-Output 'fixture phase: PowerShell started'
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
Write-Output 'fixture phase: payload decoded'
$fixtureCase = $payload.fixtureCase
function cargo {
    Write-Output 'fixture phase: synthetic cargo entered'
    $global:LASTEXITCODE = [int]$fixtureCase.code
    $fixtureCase.lines | Write-Output
}
& ([scriptblock]::Create($payload.source)) -Kind root
"""
BASIC = "::notice title=Owned volume root reparse measurement::basic: OS result 5"
EXTENDED = "::notice title=Owned volume root reparse measurement::extended: OS result 5"
CUSTODY = "::notice title=Owned volume root custody::controls and cleanup passed"
PASSED = "test result: ok. 1 passed; 0 failed; 0 ignored; 9 filtered out"


@unittest.skipUnless(os.name == "nt", "Windows PowerShell runner contract")
class VolumeRunnerTests(unittest.TestCase):
    def invoke(self, lines, code=0):
        executable = str(
            Path(os.environ["SystemRoot"])
            / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        payload = {
            "source": (ROOT / "run_windows_volume_probe.ps1").read_text(),
            "fixtureCase": {"code": code, "lines": lines},
        }
        try:
            return subprocess.run(
                [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", HARNESS],
                input=json.dumps(payload), text=True, capture_output=True, timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            # subprocess.run kills and reaps the owned PowerShell process.
            # Preserve partial phase output; never retry or treat a timeout as
            # a passing negative test. This payload contains synthetic data only.
            self.fail(f"PowerShell fixture exceeded 30s; stdout={error.stdout!r}; stderr={error.stderr!r}")

    def test_prefixed_notice_is_republished_at_column_zero(self):
        result = self.invoke(["test fixture ... " + BASIC, EXTENDED, CUSTODY, PASSED])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(BASIC, result.stdout.splitlines())

    def test_zero_matches_cannot_supply_evidence(self):
        result = self.invoke([BASIC, EXTENDED, CUSTODY, "test result: ok. 0 passed; 0 failed;"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one passing test required", result.stdout)

    def test_missing_or_duplicate_measurement_fails(self):
        for lines in ([BASIC, PASSED], [BASIC, BASIC, EXTENDED, CUSTODY, PASSED], [BASIC, EXTENDED, PASSED]):
            with self.subTest(lines=lines):
                result = self.invoke(lines)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unique result/cleanup notice required", result.stdout)

    def test_failed_cargo_cannot_hide_behind_success_text(self):
        result = self.invoke([BASIC, EXTENDED, CUSTODY, PASSED, "failure 50%\nnew line"], 101)
        self.assertNotEqual(result.returncode, 0)
        annotation = [line for line in result.stdout.splitlines() if line.startswith("::error")]
        self.assertEqual(len(annotation), 1)
        self.assertIn("cargo exit 101", annotation[0])
        self.assertIn("50%25%0Anew line", annotation[0])


class TimeoutDiagnosticsTests(unittest.TestCase):
    def test_timeout_preserves_phase_output_and_does_not_retry(self):
        timeout = subprocess.TimeoutExpired('owned PowerShell', 30,
                                            output=b'fixture phase: payload decoded\n', stderr=b'partial')
        fixture = VolumeRunnerTests('test_failed_cargo_cannot_hide_behind_success_text')
        with patch.dict(os.environ, {'SystemRoot': '/synthetic/windows'}), \
             patch.object(subprocess, 'run', side_effect=timeout) as run:
            with self.assertRaisesRegex(AssertionError, 'exceeded 30s.*payload decoded.*partial'):
                fixture.invoke([PASSED], 101)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.kwargs['timeout'], 30)


if __name__ == "__main__":
    # Keep the actual traceback available in public CI annotations as well as
    # logs. Captured payloads contain synthetic fixture text only.
    report = io.StringIO()
    result = unittest.TextTestRunner(stream=report, verbosity=2).run(
        unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                           for case in (VolumeRunnerTests, TimeoutDiagnosticsTests))
    )
    text = report.getvalue()
    print(text, end="")
    if not result.wasSuccessful():
        diagnostic = text[-10000:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::error title=Windows volume runner contract::" + diagnostic)
    sys.exit(0 if result.wasSuccessful() else 1)
