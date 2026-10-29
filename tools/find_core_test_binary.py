#!/usr/bin/env python3
"""Select Cargo's core library test executable from JSON compiler messages."""
import json
import sys

found = set()
for line in sys.stdin:
    message = json.loads(line)
    if (message.get("reason") == "compiler-artifact"
            and message.get("target", {}).get("name") == "agentswapper_core"
            and message.get("profile", {}).get("test") is True
            and message.get("executable")):
        found.add(message["executable"])
if len(found) != 1:
    raise SystemExit("expected exactly one core library test executable")
print(found.pop())
