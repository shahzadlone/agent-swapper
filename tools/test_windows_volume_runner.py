"""Exercise CI evidence validation with an in-process fake cargo, never a disk."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent
HARNESS = r"""
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$fixtureCase = $payload.fixtureCase
function cargo {
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
        return subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", HARNESS],
            input=json.dumps(payload), text=True, capture_output=True, timeout=30,
            check=False,
        )

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


if __name__ == "__main__":
    # Keep the actual traceback available in public CI annotations as well as
    # logs. Captured payloads contain synthetic fixture text only.
    report = io.StringIO()
    result = unittest.TextTestRunner(stream=report, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(VolumeRunnerTests)
    )
    text = report.getvalue()
    print(text, end="")
    if not result.wasSuccessful():
        diagnostic = text[-10000:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::error title=Windows volume runner contract::" + diagnostic)
    sys.exit(0 if result.wasSuccessful() else 1)
