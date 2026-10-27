"""Expose bounded nextest JUnit failures as GitHub check annotations."""

from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def escape(message):
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main():
    path = Path(sys.argv[1])
    if not path.is_file():
        print("No JUnit report exists; failure occurred before test reporting.")
        return
    if path.stat().st_size > 10 * 1024 * 1024:
        print("::error::JUnit report exceeds the diagnostic size limit.")
        return
    root = ET.parse(path).getroot()
    for case in root.iter("testcase"):
        for tag in ("failure", "error"):
            for failure in case.findall(tag):
                name = case.get("name", "unknown test")
                output = failure.text or failure.get("message", "Test failed")
                stdout = case.findtext("system-out", "")
                stderr = case.findtext("system-err", "")
                kind = failure.get("type", tag)
                diagnostic = f"{name} ({kind}): {output}\n{stdout}\n{stderr}"
                if len(diagnostic) > 6000:
                    # Proptest puts the minimized input and replay seed at the end.
                    diagnostic = diagnostic[:2500] + "\n[output truncated]\n" + diagnostic[-3400:]
                print("::error::" + escape(diagnostic))


if __name__ == "__main__":
    main()
