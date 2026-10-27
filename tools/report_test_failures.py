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
                stderr = case.findtext("system-err", "")
                print("::error::" + escape(f"{name}: {output}\n{stderr}"[:6000]))


if __name__ == "__main__":
    main()
