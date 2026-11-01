"""Create provider-free registry fixtures using clean historical CLI revisions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

REVISIONS = {5: 'da6b2d931a38968277a8bdb24272ebdaa15f7c3b',
             6: '533c3551377d4761fe6bf0b1192c353f2c8b6938',
             7: '63ac7462c617d5d9d0f3a241e142e66c9b9d0e72'}
STUB = '''fn main() {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--fixture-pending" {
            let marker = args.next().expect("owned marker path");
            std::fs::write(marker, b"ready").expect("write owned marker");
            std::thread::sleep(std::time::Duration::from_secs(20));
            std::process::exit(99);
        }
    }
    std::process::exit(7);
}
'''

def generate(schema, source, target, output, current):
    assert os.geteuid() != 0 and sys.platform == 'linux'
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    assert revision == REVISIONS[schema]
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=source).strip()
    # Distinct historical worktrees must never reuse a local package artifact.
    target = target / f'schema-{schema}-{revision[:7]}'
    destination = output / f'schema-{schema}.sqlite3'
    assert not destination.exists()
    with (output / f'schema-{schema}-build.log').open('wb') as log:
        subprocess.run(['cargo', '+1.98.0', 'build', '--locked', '-p', 'agentswapper-cli', '--bin', 'aswp'],
                       cwd=source, env=dict(os.environ, CARGO_TARGET_DIR=str(target)),
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
    binary = target / 'debug/aswp'
    with tempfile.TemporaryDirectory(prefix=f'aswp-historical-{schema}-') as directory:
        root = Path(directory)
        (root / 'home').mkdir()
        (root / 'fixture.rs').write_text(STUB)
        stub = root / 'native-fixture'
        subprocess.run(['rustc', '--edition=2024', str(root / 'fixture.rs'), '-o', str(stub)], check=True)
        env = {'HOME': str(root / 'home'), 'USERPROFILE': str(root / 'home'), 'PATH': '/usr/bin:/bin'}
        state = root / 'state'
        base = [str(binary), '--state-dir', str(state)]
        for alias in ('fixture-completed', 'fixture-pending'):
            subprocess.run(base + ['profile', 'add', 'codex', '--alias', alias], env=env, cwd=root,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True, timeout=10)
        result = subprocess.run(base + ['run', 'fixture-completed', '--experimental-native', '--executable', str(stub)],
                                env=env, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        assert result.returncode == 7, (result.returncode, result.stderr)
        marker = root / 'pending-ready'
        child = subprocess.Popen(base + ['run', 'fixture-pending', '--experimental-native', '--executable', str(stub),
                                        '--', '--fixture-pending', str(marker)], env=env, cwd=root,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        try:
            until = time.monotonic() + 10
            while True:
                # Observe without reaping: reserve the original process-group
                # leader even if an unexpected early exit needs cleanup.
                assert os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None, 'historical CLI exited before interruption'
                if marker.exists():
                    with sqlite3.connect(state / 'registry.sqlite3') as db:
                        row = db.execute("SELECT observed_pid,outcome FROM runs JOIN profiles ON runs.profile=profiles.id WHERE profiles.alias='fixture-pending'").fetchone()
                    if row and row[0] is not None and row[1] is None:
                        break
                assert time.monotonic() < until, 'historical fixture deadline'
                time.sleep(0.01)
            # The original leader is unreaped and the only target is our bounded
            # stub in this new session. No stored or discovered PID is signalled.
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=5)
        finally:
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.communicate(timeout=5)
        with sqlite3.connect(state / 'registry.sqlite3') as db:
            assert db.execute('PRAGMA user_version').fetchone() == (schema,)
            assert db.execute('PRAGMA quick_check').fetchone() == ('ok',)
            rows = db.execute('SELECT alias,exit_code,outcome FROM runs JOIN profiles ON runs.profile=profiles.id ORDER BY alias').fetchall()
            assert rows == [('fixture-completed', 7, 'exited'), ('fixture-pending', None, None)], rows
            assert db.execute('SELECT count(*) FROM event_log').fetchone() == (7,)
            with sqlite3.connect(destination) as copy:
                db.backup(copy)
        # Validate downgrade refusal against a real current upgrade of the full
        # private state. Do not modify the historical fixture to produce it.
        upgraded = root / 'upgraded'
        shutil.copytree(state, upgraded)
        result = subprocess.run([str(current), '--state-dir', str(upgraded), 'registry', 'verify', '--json'],
                                env=env, cwd=root, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['data']['schemaVersion'] == 9
        result = subprocess.run([str(binary), '--state-dir', str(upgraded), 'registry', 'verify'],
                                env=env, cwd=root, capture_output=True, text=True, timeout=10)
        assert result.returncode == 125 and 'newer' in result.stderr, (result.returncode, result.stderr)
    destination.chmod(0o600)
    metadata = {'schema': schema, 'revision': revision,
                'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                'producer_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'stub_sha256': hashlib.sha256(STUB.encode()).hexdigest(),
                'events': 7, 'completed_exit': 7, 'pending_runs': 1,
                'current_schema': 9, 'historical_downgrade_exit': 125}
    (output / f'schema-{schema}.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(f'schema {schema}: generated by {revision[:7]}; upgrade and downgrade checks passed', flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('schema', type=int, choices=sorted(REVISIONS))
    parser.add_argument('source', type=Path, help='clean worktree at the pinned historical revision')
    parser.add_argument('target', type=Path, help='build directory; revisions receive separate subdirectories')
    parser.add_argument('output', type=Path, help='destination; existing fixtures are never overwritten')
    parser.add_argument('current', type=Path, help='current schema-9 aswp executable for upgrade checks')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    generate(args.schema, args.source.resolve(), args.target.resolve(), output, args.current.resolve())
