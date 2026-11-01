#!/usr/bin/env python3
"""Build two ordinary-observer fault controls in disposable source copies.

Never changes the checkout, installed guardian or production feature graph.
The hosted activation harness must demonstrate the expected failure from each.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


TRANSITION = '        value.policy = value.policy.admitted()?;\n'
BARRIER = '        checkpoint()?;\n        value.recheck(manager).await?;\n'
KINDS = ('missing-transition', 'premature-transition')


def mutate(source, kind):
    if kind not in KINDS or source.count(TRANSITION) != 1 or source.count(BARRIER) != 1:
        raise RuntimeError('admission mutation no longer matches exactly one reviewed boundary')
    source = source.replace(TRANSITION, '', 1)
    if kind == 'premature-transition':
        source = source.replace(BARRIER, TRANSITION + BARRIER, 1)
    return source


def build(destination):
    if os.geteuid() == 0 or not destination.is_absolute():
        raise RuntimeError('mutation builds require an ordinary user and an absolute new output directory')
    destination.mkdir(mode=0o700)  # Never reuse or remove a caller's output.
    root = Path(__file__).resolve().parents[1]
    listing = subprocess.run(['git', 'ls-files', '-z', '--', 'Cargo.toml', 'Cargo.lock',
                              'crates', 'tools/linux-manager-evaluation'], cwd=root,
                             capture_output=True, check=True).stdout
    paths = [Path(os.fsdecode(name)) for name in listing.split(b'\0') if name]
    for kind in KINDS:
        with tempfile.TemporaryDirectory(prefix=kind + '-', dir=destination) as temporary:
            copy = Path(temporary) / 'source'
            for path in paths:
                source = root / path
                if path.is_absolute() or '..' in path.parts or source.is_symlink() or not source.is_file():
                    raise RuntimeError('mutation build requires ordinary tracked source files')
                target = copy / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            service = copy / 'crates/agentswapper-linux-manager/src/service.rs'
            service.write_text(mutate(service.read_text(), kind))
            # Each source copy has its own target. Reusing a target across
            # unrelated worktrees can incorrectly reuse Cargo fingerprints.
            target = Path(temporary) / 'target'
            environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
            subprocess.run(['cargo', '+1.98.0', 'build', '--locked', '--manifest-path',
                            str(copy / 'tools/linux-manager-evaluation/Cargo.toml'),
                            '--bin', 'aswp-linux-manager-evaluation'], env=environment, check=True)
            shutil.copyfile(target / 'debug/aswp-linux-manager-evaluation', destination / kind)
            (destination / kind).chmod(0o700)
        print('Built ordinary admission observer: ' + kind, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    build(parser.parse_args().destination)
