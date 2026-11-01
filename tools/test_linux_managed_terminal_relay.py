"""Journal observation checks; no terminal, provider or privileged operations."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from check_linux_managed_terminal_relay import lease_path


class JournalObservationTests(unittest.TestCase):
    def test_scope_retirement_preserves_unknown_target_status(self):
        profile = '00000000-0000-4000-8000-000000000001'
        run = '00000000-0000-4000-8000-000000000002'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'state').mkdir()
            (root / 'journal.json').write_text(json.dumps({'profile': profile, 'run': run}))
            with sqlite3.connect(root / 'state/registry.sqlite3') as db:
                db.execute('CREATE TABLE runs(id, profile, exit_code, outcome, requires_spawn_observation, local_scope, linux_binding)')
                db.execute('INSERT INTO runs VALUES (?, ?, NULL, NULL, 1, ?, NULL)', (run, profile, '{"backend":"linux_cgroup"}'))
            expected = root / 'state/locks' / (profile + '.lock')
            self.assertEqual(lease_path(root), expected)
            (root / 'retired').write_text('test marker')
            with self.assertRaises(AssertionError):
                lease_path(root)
            with sqlite3.connect(root / 'state/registry.sqlite3') as db:
                db.execute("UPDATE runs SET outcome='local_scope_empty',linux_binding='{}'")
            (root / 'journal-audited').write_text('scope retired; target outcome unknown')
            self.assertEqual(lease_path(root), expected)
            for statement in ["UPDATE runs SET exit_code=0", "UPDATE runs SET exit_code=NULL,outcome='exited'", "UPDATE runs SET outcome='local_scope_empty',linux_binding=NULL"]:
                with sqlite3.connect(root / 'state/registry.sqlite3') as db:
                    db.execute(statement)
                with self.assertRaises(AssertionError):
                    lease_path(root)


if __name__ == '__main__':
    unittest.main()
