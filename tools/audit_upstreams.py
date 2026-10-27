"""Reproduce narrow security observations using synthetic data and mocked I/O.

This is an audit aid, not a certification or a test of live provider accounts.
It loads only the reviewed stdlib-only leaf modules. Credential encoding is
evaluated from an extracted method with a stub host; no account store is loaded.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
UPSTREAMS = {
    "claude-swap": "80f07866558c6b6d82112071f6973115132a0288",
    "ccswap": "e8c8b608c9fe60a42402dc13960255e8a874b64d",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def load_leaf(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inspect_repo(name: str, revision: str) -> dict:
    repo = ROOT / ".research" / "upstream" / name
    assert git(repo, "rev-parse", "HEAD") == revision, "Audit snapshot changed"
    source = repo / "src" / "claude_swap"
    files = sorted(source.rglob("*.py"))
    records = {}
    for path in files:
        data = path.read_bytes()
        records[str(path.relative_to(repo))] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "lines": len(data.splitlines()),
        }
    test_count = sum(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
        for path in (repo / "tests").rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text()))
    )
    observations = []
    keychain = load_leaf(source / "macos_keychain.py", name + "_keychain")
    with patch.object(keychain.subprocess, "run") as run:
        run.return_value = SimpleNamespace(returncode=0, stderr="")
        keychain.set_password("audit-service", "audit-account", "synthetic-short")
        assert run.call_args.args[0] == ["/usr/bin/security", "-i"]
        assert "synthetic-short".encode().hex() in run.call_args.kwargs["input"]
    observations.append({"id": "keychain-short-stdin", "observed": True})
    synthetic = "SYNTHETIC_AUDIT_VALUE_" * 220
    with patch.object(keychain.subprocess, "run") as run:
        run.return_value = SimpleNamespace(returncode=0, stderr="")
        keychain.set_password("audit-service", "audit-account", synthetic)
        argv = run.call_args.args[0]
        assert argv[-2] == "-X" and bytes.fromhex(argv[-1]).decode() == synthetic
        assert "input" not in run.call_args.kwargs
    observations.append({"id": "keychain-long-secret-in-argv", "observed": True})

    tree = ast.parse((source / "credentials.py").read_text())
    method = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_atomic_b64_write"
    )
    captured = {}
    namespace = {
        "Path": Path,
        "base64": base64,
        "atomic_write_text": lambda target, text: captured.update(payload=text),
    }
    method_module = ast.Module(body=[method], type_ignores=[])
    exec(compile(ast.fix_missing_locations(method_module), str(source / "credentials.py"), "exec"), namespace)
    with tempfile.TemporaryDirectory(prefix="agentswapper-audit-") as temp:
        scratch = Path(temp)
        host = SimpleNamespace(_host=SimpleNamespace(credentials_dir=scratch))
        namespace["_atomic_b64_write"](host, scratch / "synthetic.enc", synthetic)
        assert base64.b64decode(captured["payload"]).decode() == synthetic
    observations.append({"id": "backup-base64-is-reversible", "observed": True})

    fsutil = load_leaf(source / "fsutil.py", name + "_fsutil")
    with tempfile.TemporaryDirectory(prefix="agentswapper-audit-") as temp:
        scratch = Path(temp)
        target = scratch / "target"
        old_mask = os.umask(0)
        try:
            fsutil.atomic_write_text(target, "synthetic-content")
        finally:
            os.umask(old_mask)
        assert target.stat().st_mode & 0o777 == 0o600
        observations.append({"id": "atomic-file-private-despite-open-umask", "observed": True})
        victim = scratch / "victim"
        victim.write_text("untouched")
        link = scratch / "export-link"
        link.symlink_to(victim)
        fsutil.atomic_write_text(link, "synthetic-export", follow_symlinks=False)
        assert victim.read_text() == "untouched" and not link.is_symlink()
        observations.append({"id": "export-no-follow-preserves-symlink-target", "observed": True})
        before = target.read_bytes()
        with patch.object(fsutil, "replace_with_retry", side_effect=OSError("synthetic failure")):
            try:
                fsutil.atomic_write_text(target, "replacement")
            except OSError:
                pass
            else:
                raise AssertionError("Expected publication failure")
        assert target.read_bytes() == before
        assert not list(scratch.glob("*.tmp"))
        observations.append({"id": "failed-publication-preserves-original-and-cleans-temp", "observed": True})

    transfer = ast.parse((source / "transfer.py").read_text())
    plaintext_marker = any(
        isinstance(node, ast.Dict)
        and any(
            isinstance(key, ast.Constant) and key.value == "encrypted"
            and isinstance(value, ast.Constant) and value.value is False
            for key, value in zip(node.keys, node.values)
        )
        for node in ast.walk(transfer)
    )
    assert plaintext_marker
    observations.append({"id": "export-declares-unencrypted-payload", "observed": True})
    return {
        "revision": revision,
        "commitCount": int(git(repo, "rev-list", "--count", "HEAD")),
        "rootCommits": git(repo, "rev-list", "--max-parents=0", "HEAD").splitlines(),
        "sourceFiles": len(files),
        "sourceLines": sum(record["lines"] for record in records.values()),
        "testFunctionsFoundNotExecuted": test_count,
        "observations": observations,
        "files": records,
    }


if __name__ == "__main__":
    report = {name: inspect_repo(name, revision) for name, revision in UPSTREAMS.items()}
    request = urllib.request.Request("https://provider.example/usage", headers={"Authorization": "Bearer SYNTHETIC"})
    redirected = urllib.request.HTTPRedirectHandler().redirect_request(
        request, None, 302, "Found", {}, "https://different-origin.example/usage"
    )
    assert redirected.get_header("Authorization") == "Bearer SYNTHETIC"
    report["transportObservation"] = {
        "id": "stdlib-redirect-retains-authorization-across-origins",
        "observed": True,
        "networkRequestsMade": 0,
        "scope": "stdlib behavior; no claim that a real provider returns such redirects",
    }
    destination = ROOT / ".research" / "audit-results.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    for name in UPSTREAMS:
        row = report[name]
        print(f"{name}: {len(row['observations'])} observations reproduced; {row['sourceFiles']} Python source files inventoried")
    print("Transport: one synthetic redirect observation; zero network requests")
    print(f"Saved {destination}")
