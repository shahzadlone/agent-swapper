"""Journal observation checks; no terminal, provider or privileged operations."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from check_linux_managed_terminal_relay import lease_path


class JournalObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'state').mkdir()
        self.profile = '00000000-0000-4000-8000-000000000001'
        self.run = '00000000-0000-4000-8000-000000000002'
        self.scope = {'backend': 'linux_cgroup', 'id': '00000000-0000-4000-8000-000000000003'}
        self.binding = {'unit': f'aswp-activation-123-1@1-41-{os.getuid()}.service',
                        'invocation': [7] * 16, 'user': os.getuid(), 'guardian': 42,
                        'device': 25, 'inode': 128}
        self.ready = {'pid': 41, 'guardian': 42, 'invocation': '07' * 16, 'target': 43}
        self.events = [{'type': 'run_planned', 'id': self.run, 'profile': self.profile,
                        'kind': 'run', 'requires_spawn_observation': True, 'local_scope': self.scope}]
        self.db = sqlite3.connect(self.root / 'state/registry.sqlite3')
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE runs(id, profile, exit_code, outcome, requires_spawn_observation, local_scope, linux_binding, observed_pid)')
        self.db.execute('CREATE TABLE event_log(sequence INTEGER PRIMARY KEY, payload)')
        self.db.execute('INSERT INTO runs VALUES (?, ?, NULL, NULL, 1, ?, NULL, NULL)',
                        (self.run, self.profile, json.dumps(self.scope)))
        (self.root / 'journal.json').write_text(json.dumps({'profile': self.profile, 'run': self.run}))
        self.environment = mock.patch.dict(os.environ, {'ASWP_ACTIVATION_PREFIX': 'aswp-activation-123-1'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.save_events()

    def save_events(self):
        self.db.execute('DELETE FROM event_log')
        self.db.executemany('INSERT INTO event_log(payload) VALUES (?)',
                            [(json.dumps(event),) for event in self.events])
        self.db.commit()

    def bound(self, spawned=False, retired=False):
        self.events.append({'type': 'linux_scope_bound', 'id': self.run, 'binding': deepcopy(self.binding)})
        self.db.execute('UPDATE runs SET linux_binding=?', (json.dumps(self.binding),))
        (self.root / 'ready').write_text(json.dumps(self.ready))
        if spawned:
            self.events.append({'type': 'run_spawned', 'id': self.run, 'pid': self.ready['target']})
            self.db.execute('UPDATE runs SET observed_pid=?', (self.ready['target'],))
        if retired:
            self.events.append({'type': 'linux_scope_retired', 'id': self.run,
                                'scope': self.scope['id'], 'binding': deepcopy(self.binding)})
            self.db.execute("UPDATE runs SET outcome='local_scope_empty'")
            (self.root / 'journal-audited').write_text('scope retired; target outcome unknown')
            (self.root / 'retired').write_text('test marker')
        self.save_events()

    def accepted(self):
        self.assertEqual(lease_path(self.root), self.root / 'state/locks' / (self.profile + '.lock'))

    def refused(self):
        with self.assertRaises(AssertionError):
            lease_path(self.root)

    def test_pending_intent_and_unobserved_retirement_preserve_unknown_exit(self):
        self.accepted()
        self.bound(retired=True)
        self.accepted()
        for statement in ["UPDATE runs SET exit_code=0", "UPDATE runs SET exit_code=NULL,outcome='exited'",
                          "UPDATE runs SET outcome='local_scope_empty',linux_binding=NULL"]:
            self.db.execute(statement)
            self.db.commit()
            self.refused()

    def test_spawned_retirement_and_owned_session_have_matching_history(self):
        self.bound(spawned=True, retired=True)
        self.accepted()
        (self.root / 'session-ready').write_text(json.dumps(self.ready))
        (self.root / 'ready').write_text(json.dumps({**self.ready, 'pid': 40, 'child': 41}))
        self.accepted()

    def test_pending_spawn_does_not_claim_retirement_after_client_loss(self):
        self.bound(spawned=True)
        self.accepted()
        (self.root / 'retired').write_text('unsupported claim')
        self.refused()

    def test_missing_reordered_duplicate_and_foreign_events_refuse(self):
        self.bound(spawned=True, retired=True)
        original = deepcopy(self.events)
        mutations = [original[:index] + original[index + 1:] for index in range(4)]
        mutations += [[original[1], original[0], *original[2:]],
                      [original[0], original[2], original[1], original[3]],
                      original + [original[-1]]]
        foreign = deepcopy(original)
        foreign[1]['id'] = self.scope['id']
        mutations.append(foreign)
        for events in mutations:
            with self.subTest(events=[event['type'] for event in events]):
                self.events = events
                self.save_events()
                self.refused()
        self.events = original
        self.save_events()
        self.accepted()

    def test_empty_binding_and_projection_only_retirement_refuse(self):
        self.db.execute("UPDATE runs SET outcome='local_scope_empty',linux_binding='{}'")
        self.db.commit()
        self.refused()
        self.db.execute("UPDATE runs SET outcome=NULL,linux_binding=NULL")
        self.bound(retired=True)
        for event in self.events[1:]:
            event['binding'] = {}
        self.db.execute("UPDATE runs SET linux_binding='{}'")
        self.save_events()
        self.refused()

    def test_event_projection_and_prepared_identity_must_agree(self):
        self.bound(spawned=True, retired=True)
        original = deepcopy(self.events)
        for field, value in [('invocation', [8] * 16), ('guardian', 99), ('inode', 256),
                             ('device', 26), ('unit', self.binding['unit'].replace('@1-', '@2-'))]:
            with self.subTest(field=field):
                self.events = deepcopy(original)
                self.events[-1]['binding'][field] = value
                self.save_events()
                self.refused()
        self.events = original
        self.save_events()
        for field, value in [('invocation', '08' * 16), ('guardian', 99), ('target', 44), ('pid', 99)]:
            with self.subTest(ready=field):
                (self.root / 'ready').write_text(json.dumps({**self.ready, field: value}))
                self.refused()
        (self.root / 'ready').write_text(json.dumps(self.ready))
        self.accepted()

    def test_coherent_wrong_invocation_and_foreign_unit_refuse(self):
        self.bound(retired=True)
        for field, value in [('invocation', [8] * 16), ('guardian', 99),
                             ('unit', f'aswp-activation-456-1@1-41-{os.getuid()}.service')]:
            with self.subTest(field=field):
                altered = {**self.binding, field: value}
                self.db.execute('UPDATE runs SET linux_binding=?', (json.dumps(altered),))
                for event in self.events[1:]:
                    event['binding'] = altered
                self.save_events()
                self.refused()


if __name__ == '__main__':
    unittest.main()
