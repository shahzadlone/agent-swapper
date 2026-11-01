#!/usr/bin/env python3
"""Keep the qualification client out of production dependency graphs."""
import subprocess
import json
from pathlib import Path


def check():
    root = Path(__file__).resolve().parents[1]
    locks = []
    for manifest in ('Cargo.toml', 'tools/linux-manager-evaluation/Cargo.toml'):
        result = subprocess.run(['cargo', '+1.98.0', 'metadata', '--locked', '--format-version', '1',
                                 '--manifest-path', manifest, '--filter-platform', 'x86_64-unknown-linux-gnu'],
                                cwd=root, capture_output=True, text=True, check=True, timeout=120)
        locks.append(json.loads(result.stdout)['packages'])
    # The audited Linux transport/runtime must resolve identically in both locks.
    names = {'zbus', 'zbus_macros', 'zruntime', 'tokio', 'rustix', 'nix', 'unix-ancillary', 'fuxix', 'zeroize'}
    versions = [{p['name']: p['version'] for p in packages if p['name'] in names} for packages in locks]
    if versions[0] != versions[1] or versions[0].keys() != names:
        raise RuntimeError('root and isolated manager dependency pins differ')
    forbidden = {'agentswapper-linux-manager', 'aswp-linux-manager-evaluation', 'zbus', 'tokio', 'unix-ancillary'}
    for package in ('agentswapper-core', 'agentswapper-cli'):
        result = subprocess.run(['cargo', '+1.98.0', 'tree', '--locked', '-p', package,
                                 '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}'],
                                cwd=root, capture_output=True, text=True, check=True, timeout=60)
        present = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
        if forbidden & present:
            raise RuntimeError(f'{package} acquired qualification-only production dependencies')
    result = subprocess.run(['cargo', '+1.98.0', 'tree', '--locked', '-p', 'agentswapper-linux-runtime',
                             '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}'],
                            cwd=root, capture_output=True, text=True, check=True, timeout=60)
    present = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    if (forbidden | {'agentswapper-core', 'agentswapper-cli', 'rusqlite', 'age'}) & present:
        raise RuntimeError('Linux helper transport acquired application or manager dependencies')
    result = subprocess.run(['cargo', '+1.98.0', 'tree', '--locked', '-p', 'agentswapper-linux-manager',
                             '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}'],
                            cwd=root, capture_output=True, text=True, check=True, timeout=60)
    present = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    if {'aswp-linux-manager-evaluation', 'agentswapper-core', 'agentswapper-cli', 'rusqlite', 'age', 'unix-ancillary', 'fuxix'} & present:
        raise RuntimeError('Read-only manager transport acquired application or fixture dependencies')
    for package in ('agentswapper-core', 'agentswapper-cli', 'agentswapper-linux-runtime', 'agentswapper-linux-manager'):
        result = subprocess.run(['cargo', '+1.98.0', 'tree', '--locked', '-p', package,
                                 '--edges', 'normal,build', '--prefix', 'none', '--format', '{p} features=[{f}]'],
                                cwd=root, capture_output=True, text=True, check=True, timeout=60)
        for line in result.stdout.splitlines():
            if line.startswith(('agentswapper-linux-runtime ', 'agentswapper-linux-manager ')):
                features = line.split('features=[', 1)[1].split(']', 1)[0].split(',')
                if 'qualification' in features:
                    raise RuntimeError(f'{package} enables qualification-only kernel capabilities')
    print('Manager qualification dependency pins match; production graphs remain isolated.')


if __name__ == '__main__':
    check()
