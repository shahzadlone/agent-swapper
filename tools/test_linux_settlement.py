"""Unit cover for the settlement control's assertions.

The hosted control needs a live manager and a real store; these tests pin the
part that decides whether a recorded run is settled and what the helper's
failure output contains, so a wrong expectation fails here instead of looking
like a hosted flake.
"""
import copy
import unittest

import check_linux_settlement as control

SETTLED = {
    'id': '11111111-1111-4111-8111-111111111111',
    'alias': 'aswp-launch',
    'outcome': 'local_scope_empty',
    'custody': 'local_scope_empty',
    'exitCode': None,
    'observedPid': None,
    'localScope': {'backend': 'linux_cgroup',
                   'id': '22222222-2222-4222-8222-222222222222'},
}


class SettledShapeTest(unittest.TestCase):
    def test_the_settled_shape_is_what_a_failed_launch_leaves(self):
        control.check_settled(copy.deepcopy(SETTLED), 'aswp-launch')

    def test_an_unresolved_run_is_rejected(self):
        for field in ('outcome', 'custody'):
            record = copy.deepcopy(SETTLED)
            record[field] = 'unknown'
            with self.assertRaises(RuntimeError):
                control.check_settled(record, 'aswp-launch')

    def test_a_recorded_exit_is_rejected(self):
        record = copy.deepcopy(SETTLED)
        record['exitCode'] = 0
        with self.assertRaises(RuntimeError):
            control.check_settled(record, 'aswp-launch')

    def test_a_recorded_observation_is_rejected(self):
        record = copy.deepcopy(SETTLED)
        record['observedPid'] = 4242
        with self.assertRaises(RuntimeError):
            control.check_settled(record, 'aswp-launch')

    def test_a_run_without_its_scope_is_rejected(self):
        record = copy.deepcopy(SETTLED)
        record['localScope'] = None
        with self.assertRaises(RuntimeError):
            control.check_settled(record, 'aswp-launch')

    def test_another_profiles_run_is_rejected(self):
        with self.assertRaises(RuntimeError):
            control.check_settled(copy.deepcopy(SETTLED), 'other')


class OutputTest(unittest.TestCase):
    def test_the_expected_annotation_is_not_replayed(self):
        text = ('::error title=session helper::refused\n'
                'session helper refused: exec event missing: gone\n')
        self.assertEqual(control.quiet(text),
                         'session helper refused: exec event missing: gone')

    def test_the_control_expects_the_refusal_status(self):
        self.assertEqual(control.REFUSED, 125)

    def test_the_settlement_adds_its_three_events(self):
        # Intent, binding and retirement: no spawn, no exit to record.
        self.assertEqual(control.SETTLEMENT_EVENTS, 3)


if __name__ == '__main__':
    unittest.main()
