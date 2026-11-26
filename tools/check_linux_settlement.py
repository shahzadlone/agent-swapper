#!/usr/bin/env python3
"""Settlement control: a launch that fails after its durable intent must
still settle its run.

The intent is committed before the launch gate, so from that point on the
client owes a settlement. This control makes the launch fail after the intent
while the helper stays alive - the target cannot be executed at all - and
then reads the Store back:

  * the helper exits through its refusal path, naming the missing exec event,
  * exactly one new run exists, it resolved with the local scope empty and no
    authenticated exit (nothing nonce-bound was observed, so nothing may be
    recorded), and it was never observed at all,
  * the journal grew by exactly the intent, the binding and the retirement,
  * nothing is left unfinished, and the profile is reusable: a second launch
    on the same alias reaches its target.

It deliberately claims nothing about a crash: a helper killed between its
intent and its settlement leaves the run unresolved by design, and
`docs/linux-restart-recovery.md` records why that cannot be recovered from
the user's own store.
"""
import argparse
import json
import os
import subprocess
import sys

# A path that cannot exist: the shim's exec fails after the intent.
MISSING_TARGET = '/nonexistent-aswp-settlement-control-target'
# The helper's own refusal path exits 125 and never any other status.
REFUSED = 125
# The failure the client must report: the gate opened and no exec followed.
EXEC_MISSING = 'session helper refused: exec event missing:'
# The three events a settled failed launch adds: intent, binding, retirement.
SETTLEMENT_EVENTS = 3
READ_DEADLINE = 60
LAUNCH_DEADLINE = 180


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def quiet(text):
    """The helper prints a workflow annotation for its own failure; echoing
    it would surface an expected failure as a step error."""
    return '\n'.join(line for line in text.splitlines()
                     if not line.startswith('::error'))


def invoke(client, arguments):
    completed = subprocess.run(
        [client, '--json', *arguments],
        capture_output=True,
        text=True,
        timeout=READ_DEADLINE,
        check=False,
    )
    require(completed.returncode == 0,
            f'{" ".join(arguments)} failed: {quiet(completed.stderr).strip()}')
    try:
        return json.loads(completed.stdout)['data']
    except (KeyError, json.JSONDecodeError) as error:
        raise RuntimeError(f'{" ".join(arguments)} did not answer with a '
                           f'JSON envelope: {error}') from error


def runs_for(client, alias):
    return [run for run in invoke(client, ['runs', '--limit', '50'])
            if run['alias'] == alias]


def unfinished(client):
    return invoke(client, ['status'])['unfinishedRuns']


def journal_events(client):
    return invoke(client, ['registry', 'verify'])['events']


def check_settled(record, alias):
    """The settled shape of a run whose launch failed after its intent.

    A target that could never be executed was never observed either, so this
    shape requires the absent observation as well as the absent exit: the
    binding is what the settle path must keep, and what it must not invent is
    an exit or a spawn.
    """
    require(record['alias'] == alias, f'the run belongs to {record["alias"]}')
    require(record['outcome'] == 'local_scope_empty',
            f'the failed launch left outcome {record["outcome"]!r}')
    require(record['custody'] == 'local_scope_empty',
            f'the failed launch left custody {record["custody"]!r}')
    require(record['exitCode'] is None,
            'a launch that observed no authenticated exit recorded one')
    require(record['observedPid'] is None,
            'a launch whose target never executed recorded an observation')
    scope = record['localScope'] or {}
    require(scope.get('backend') == 'linux_cgroup',
            'the settled run has no linux cgroup scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True)
    parser.add_argument('--profile', required=True)
    options = parser.parse_args()

    require(not os.path.exists(MISSING_TARGET),
            f'{MISSING_TARGET} exists; the control needs an unexecutable target')
    before = {run['id'] for run in runs_for(options.client, options.profile)}
    events = journal_events(options.client)

    failed = subprocess.run(
        [options.client, 'managed-launch', options.profile, '--',
         MISSING_TARGET],
        capture_output=True,
        text=True,
        timeout=LAUNCH_DEADLINE,
        check=False,
    )
    output = failed.stdout + failed.stderr
    print(f'failed launch exited {failed.returncode}', file=sys.stderr)
    sys.stderr.write(quiet(output))
    require(failed.returncode == REFUSED,
            f'a post-intent failure exited {failed.returncode}, not {REFUSED}')
    require(EXEC_MISSING in output,
            'the failure was not the missing exec event after the gate')

    new = [run for run in runs_for(options.client, options.profile)
           if run['id'] not in before]
    require(len(new) == 1, f'expected exactly one new run, found {len(new)}')
    check_settled(new[0], options.profile)
    require(journal_events(options.client) == events + SETTLEMENT_EVENTS,
            'the settlement did not record exactly intent, binding and retirement')

    pending = unfinished(options.client)
    require(pending == [], f'the failed launch left {len(pending)} unfinished run(s)')

    reused = subprocess.run(
        [options.client, 'managed-launch', options.profile, '--',
         '/bin/sh', '-c', 'echo settlement-reuse-ok'],
        capture_output=True,
        text=True,
        timeout=LAUNCH_DEADLINE,
        check=False,
    )
    require(reused.returncode == 0,
            f'the second launch exited {reused.returncode}: '
            f'{quiet(reused.stderr).strip()}')
    require('settlement-reuse-ok' in (reused.stdout + reused.stderr),
            'the second launch did not reach its target')
    print('settlement control: the failed launch settled with no observation '
          'and no exit, and the profile was reusable')


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        print(f'::error title=settlement control::{error}')
        raise SystemExit(1)
    except subprocess.TimeoutExpired as error:
        print(f'::error title=settlement control::deadline exceeded: {error}')
        raise SystemExit(1)
