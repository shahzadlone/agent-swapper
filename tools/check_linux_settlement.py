#!/usr/bin/env python3
"""Settlement control: a launch that fails after its durable intent must
still settle its run.

The intent is committed before the launch gate, so from that point on the
client owes a settlement. This control makes a launch fail after the intent
while the helper stays alive - the target cannot be executed - and then reads
the Store back:

  * the helper reports the launch's own failure,
  * the run resolved with no authenticated exit (nothing nonce-bound was
    observed, so nothing may be recorded),
  * the profile is reusable: no unfinished run remains and a second launch
    succeeds.

It deliberately does not claim anything about a crash: a helper killed
between its intent and its settlement leaves the run unresolved by design,
and `docs/linux-restart-recovery.md` records why that cannot be recovered
from the user's own store.
"""
import argparse
import json
import subprocess
import sys

# A path that cannot exist: the shim's exec fails after the intent.
MISSING_TARGET = '/nonexistent-aswp-settlement-control-target'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def invoke(client, arguments):
    completed = subprocess.run(
        [client, '--json', *arguments],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    require(completed.returncode == 0,
            f'{" ".join(arguments)} failed: {completed.stderr.strip()}')
    return json.loads(completed.stdout)['data']


def runs_for(client, alias):
    return [run for run in invoke(client, ['runs']) if run['alias'] == alias]


def unfinished(client):
    return invoke(client, ['status'])['unfinishedRuns']


def check_settled(record, alias):
    """The settled shape of a run whose launch failed after its intent.

    A target that could never be executed was never observed either, so this
    shape says nothing about `observedPid`: the binding is what the settle
    path must keep, and the absent exit is what it must not invent.
    """
    require(record['alias'] == alias, f'the run belongs to {record["alias"]}')
    require(record['outcome'] == 'local_scope_empty',
            f'the failed launch left outcome {record["outcome"]!r}')
    require(record['custody'] == 'local_scope_empty',
            f'the failed launch left custody {record["custody"]!r}')
    require(record['exitCode'] is None,
            'a launch that observed no authenticated exit recorded one')
    scope = record['localScope'] or {}
    require(scope.get('backend') == 'linux_cgroup',
            'the settled run has no linux cgroup scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True)
    parser.add_argument('--profile', required=True)
    options = parser.parse_args()

    before = {run['id'] for run in runs_for(options.client, options.profile)}
    failed = subprocess.run(
        [options.client, 'managed-launch', options.profile, '--',
         MISSING_TARGET],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    print(f'failed launch status {failed.returncode}', file=sys.stderr)
    sys.stderr.write(failed.stdout)
    sys.stderr.write(failed.stderr)
    require(failed.returncode != 0,
            'a launch whose target cannot be executed reported success')
    require('session helper refused' in (failed.stdout + failed.stderr),
            'the helper did not report the launch failure')

    new = [run for run in runs_for(options.client, options.profile)
           if run['id'] not in before]
    require(len(new) == 1,
            f'expected exactly one new run, found {len(new)}')
    check_settled(new[0], options.profile)

    pending = unfinished(options.client)
    require(pending == [], f'the failed launch left {len(pending)} unfinished run(s)')
    replayed = [run for run in runs_for(options.client, options.profile)
                if run['id'] == new[0]['id']]
    require(len(replayed) == 1, 'the settled run was recorded twice')
    check_settled(replayed[0], options.profile)

    reused = subprocess.run(
        [options.client, 'managed-launch', options.profile, '--',
         '/bin/sh', '-c', 'echo settlement-reuse-ok'],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    require(reused.returncode == 0,
            f'the profile was not reusable: {reused.stderr.strip()}')
    require('settlement-reuse-ok' in (reused.stdout + reused.stderr),
            'the second launch did not reach its target')
    print('settlement control: the failed launch settled with no exit and the profile was reusable')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        print(f'::error title=settlement control::{error}')
        raise SystemExit(1)
